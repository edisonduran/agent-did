const { expect } = require('chai');
const { ethers } = require('hardhat');
const { time } = require('@nomicfoundation/hardhat-network-helpers');

describe('AgentRegistry', function () {
  let registry;
  let owner; // deployer, admin and initial registrar
  let other;
  let stranger;

  const DID = 'did:agent:polygon:0xabc123';
  const CONTROLLER = 'did:ethr:0xcontroller';
  const DOC_REF = 'hash://sha256/abcdef1234567890';

  const TYPES = {
    Registration: [
      { name: 'did', type: 'string' },
      { name: 'controller', type: 'string' },
      { name: 'documentRef', type: 'string' },
      { name: 'owner', type: 'address' },
      { name: 'deadline', type: 'uint256' }
    ]
  };

  async function domain() {
    const { chainId } = await ethers.provider.getNetwork();
    return { name: 'AgentRegistry', version: '1', chainId, verifyingContract: await registry.getAddress() };
  }

  async function attest({
    did = DID,
    controller = CONTROLLER,
    documentRef = '',
    attestedOwner = owner.address,
    deadline,
    signer = owner
  } = {}) {
    const exp = deadline ?? (await time.latest()) + 3600;
    const signature = await signer.signTypedData(await domain(), TYPES, {
      did, controller, documentRef, owner: attestedOwner, deadline: exp
    });
    return { owner: attestedOwner, deadline: exp, signature };
  }

  async function register({ did = DID, controller = CONTROLLER, documentRef = '', sender = owner, ...attestOpts } = {}) {
    const attestation = await attest({ did, controller, documentRef, ...attestOpts });
    return registry.connect(sender).registerAgentAttested(did, controller, documentRef, attestation);
  }

  beforeEach(async function () {
    [owner, other, stranger] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory('AgentRegistry');
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

  describe('registerAgentAttested', function () {
    it('should register an agent without documentRef', async function () {
      await register();
      const record = await registry.getAgentRecord(DID);
      expect(record.recordDid).to.equal(DID);
      expect(record.controller).to.equal(CONTROLLER);
      expect(record.documentRef).to.equal('');
    });

    it('should register agent and documentRef atomically and emit both events', async function () {
      await expect(register({ documentRef: DOC_REF }))
        .to.emit(registry, 'AgentRegistered')
        .and.to.emit(registry, 'DocumentReferenceUpdated');
      expect((await registry.getAgentRecord(DID)).documentRef).to.equal(DOC_REF);
    });

    it('should set the attested owner, not the transaction sender', async function () {
      await register({ attestedOwner: other.address, sender: stranger });
      await expect(registry.connect(stranger).revokeAgent(DID)).to.be.revertedWith('not authorized');
      await registry.connect(other).revokeAgent(DID);
      expect(await registry.isRevoked(DID)).to.equal(true);
    });

    it('should reject duplicate registration', async function () {
      await register();
      await expect(register()).to.be.revertedWith('already registered');
    });

    it('should reject invalid DID formats', async function () {
      await expect(register({ did: '' })).to.be.revertedWith('did required');
      await expect(register({ did: 'short' })).to.be.revertedWith('did too short');
      await expect(register({ did: 'notadid:x' })).to.be.revertedWith('did must start with did:');
    });

    it('should reject documentRef exceeding max length', async function () {
      await expect(register({ documentRef: 'x'.repeat(1025) })).to.be.revertedWith('documentRef too long');
    });

    it('should be queryable via isRevoked (not revoked)', async function () {
      await register({ documentRef: DOC_REF });
      expect(await registry.isRevoked(DID)).to.equal(false);
    });
  });

  describe('attestation', function () {
    it('should reject a signature from an account that is not the registrar', async function () {
      await expect(register({ signer: stranger })).to.be.revertedWith('invalid attestation');
    });

    it('should reject a squatter who reuses an attestation for another DID or owner', async function () {
      const victimAttestation = await attest({ did: 'did:agent:polygon:0xvictim', attestedOwner: other.address });
      await expect(
        registry.connect(stranger).registerAgentAttested(DID, CONTROLLER, '', victimAttestation)
      ).to.be.revertedWith('invalid attestation');
      await expect(
        registry.connect(stranger).registerAgentAttested(
          'did:agent:polygon:0xvictim', CONTROLLER, '', { ...victimAttestation, owner: stranger.address }
        )
      ).to.be.revertedWith('invalid attestation');
    });

    it('should bind the controller and documentRef to the signature', async function () {
      const attestation = await attest({ documentRef: DOC_REF });
      await expect(
        registry.registerAgentAttested(DID, 'did:ethr:0xother', DOC_REF, attestation)
      ).to.be.revertedWith('invalid attestation');
      await expect(
        registry.registerAgentAttested(DID, CONTROLLER, 'hash://sha256/other', attestation)
      ).to.be.revertedWith('invalid attestation');
    });

    it('should reject an expired attestation', async function () {
      const attestation = await attest({ deadline: (await time.latest()) + 10 });
      await time.increase(60);
      await expect(
        registry.registerAgentAttested(DID, CONTROLLER, '', attestation)
      ).to.be.revertedWith('attestation expired');
    });

    it('should reject a zero owner and malformed signatures', async function () {
      await expect(register({ attestedOwner: ethers.ZeroAddress })).to.be.revertedWith('owner required');
      const attestation = await attest();
      await expect(
        registry.registerAgentAttested(DID, CONTROLLER, '', { ...attestation, signature: '0x1234' })
      ).to.be.revertedWith('invalid attestation');
    });

    it('should reject a malleable (high-s) signature', async function () {
      const { owner: o, deadline, signature } = await attest();
      const sig = ethers.Signature.from(signature);
      const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
      const highS = ethers.toBeHex(n - BigInt(sig.s), 32);
      const flipped = ethers.concat([sig.r, highS, ethers.toBeHex(sig.v === 27 ? 28 : 27, 1)]);
      await expect(
        registry.registerAgentAttested(DID, CONTROLLER, '', { owner: o, deadline, signature: flipped })
      ).to.be.revertedWith('invalid attestation');
    });

    it('should expose the digest that the registrar signs', async function () {
      const exp = (await time.latest()) + 3600;
      const digest = await registry.registrationDigest(DID, CONTROLLER, '', owner.address, exp);
      const expected = ethers.TypedDataEncoder.hash(await domain(), TYPES, {
        did: DID, controller: CONTROLLER, documentRef: '', owner: owner.address, deadline: exp
      });
      expect(digest).to.equal(expected);
    });
  });

  describe('registrar management', function () {
    it('should default the registrar to the admin', async function () {
      expect(await registry.registrar()).to.equal(owner.address);
    });

    it('should let only the admin rotate the registrar', async function () {
      await expect(registry.connect(stranger).setRegistrar(stranger.address)).to.be.revertedWith('only admin');
      await expect(registry.setRegistrar(ethers.ZeroAddress)).to.be.revertedWith('registrar required');
      await expect(registry.setRegistrar(other.address)).to.emit(registry, 'RegistrarUpdated');
    });

    it('should honor attestations only from the current registrar', async function () {
      const oldAttestation = await attest();
      await registry.setRegistrar(other.address);
      await expect(
        registry.registerAgentAttested(DID, CONTROLLER, '', oldAttestation)
      ).to.be.revertedWith('invalid attestation');
      await register({ signer: other });
      expect((await registry.getAgentRecord(DID)).recordDid).to.equal(DID);
    });
  });

  describe('revokeAgent', function () {
    it('should revoke a registered agent', async function () {
      await register({ documentRef: DOC_REF });
      await registry.revokeAgent(DID);
      expect(await registry.isRevoked(DID)).to.equal(true);
    });

    it('should reject revoking non-existent DID', async function () {
      await expect(registry.revokeAgent(DID)).to.be.revertedWith('not found');
    });
  });

  describe('setDocumentRef', function () {
    it('should update documentRef for existing agent', async function () {
      await register();
      await registry.setDocumentRef(DID, DOC_REF);
      expect((await registry.getAgentRecord(DID)).documentRef).to.equal(DOC_REF);
    });

    it('should reject update from non-owner', async function () {
      await register();
      await expect(registry.connect(other).setDocumentRef(DID, DOC_REF)).to.be.revertedWith('only owner');
    });
  });

  describe('revocationDelegate', function () {
    it('should allow delegate to revoke', async function () {
      await register({ documentRef: DOC_REF });
      await registry.setRevocationDelegate(DID, other.address, true);
      expect(await registry.isRevocationDelegate(DID, other.address)).to.equal(true);
      await registry.connect(other).revokeAgent(DID);
      expect(await registry.isRevoked(DID)).to.equal(true);
    });
  });

  describe('transferAgentOwnership', function () {
    it('should transfer ownership', async function () {
      await register({ documentRef: DOC_REF });
      await registry.transferAgentOwnership(DID, other.address);
      const newRef = 'hash://sha256/newref';
      await registry.connect(other).setDocumentRef(DID, newRef);
      expect((await registry.getAgentRecord(DID)).documentRef).to.equal(newRef);
    });
  });

  describe('pause / unpause', function () {
    it('should block registration when paused', async function () {
      await registry.pause();
      await expect(register({ documentRef: DOC_REF })).to.be.revertedWith('contract paused');
    });

    it('should still allow revocation while paused', async function () {
      await register({ documentRef: DOC_REF });
      await registry.pause();
      await registry.revokeAgent(DID);
      expect((await registry.getAgentRecord(DID)).revokedAt).to.not.equal('');
    });

    it('should resume after unpause', async function () {
      await registry.pause();
      await registry.unpause();
      await register({ documentRef: DOC_REF });
      expect((await registry.getAgentRecord(DID)).recordDid).to.equal(DID);
    });
  });
});
