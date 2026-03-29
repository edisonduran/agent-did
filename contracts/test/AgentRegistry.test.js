const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('AgentRegistry', function () {
  let registry;
  let owner;
  let other;

  const DID = 'did:agent:polygon:0xabc123';
  const CONTROLLER = 'did:ethr:0xcontroller';
  const DOC_REF = 'hash://sha256/abcdef1234567890';

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory('AgentRegistry');
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

  describe('registerAgent (legacy two-step)', function () {
    it('should register an agent without documentRef', async function () {
      await registry.registerAgent(DID, CONTROLLER);
      const record = await registry.getAgentRecord(DID);
      expect(record.recordDid).to.equal(DID);
      expect(record.controller).to.equal(CONTROLLER);
      expect(record.documentRef).to.equal('');
    });

    it('should reject duplicate registration', async function () {
      await registry.registerAgent(DID, CONTROLLER);
      await expect(registry.registerAgent(DID, CONTROLLER)).to.be.revertedWith('already registered');
    });

    it('should reject invalid DID formats', async function () {
      await expect(registry.registerAgent('', CONTROLLER)).to.be.revertedWith('did required');
      await expect(registry.registerAgent('short', CONTROLLER)).to.be.revertedWith('did too short');
      await expect(registry.registerAgent('notadid:x', CONTROLLER)).to.be.revertedWith('did must start with did:');
    });
  });

  describe('registerAgentWithDocument (atomic)', function () {
    it('should register agent and documentRef atomically', async function () {
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      const record = await registry.getAgentRecord(DID);
      expect(record.recordDid).to.equal(DID);
      expect(record.controller).to.equal(CONTROLLER);
      expect(record.documentRef).to.equal(DOC_REF);
    });

    it('should emit both AgentRegistered and DocumentReferenceUpdated events', async function () {
      await expect(registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF))
        .to.emit(registry, 'AgentRegistered')
        .and.to.emit(registry, 'DocumentReferenceUpdated');
    });

    it('should reject duplicate registration', async function () {
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      await expect(
        registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF)
      ).to.be.revertedWith('already registered');
    });

    it('should reject empty documentRef', async function () {
      await expect(
        registry.registerAgentWithDocument(DID, CONTROLLER, '')
      ).to.be.revertedWith('documentRef required');
    });

    it('should reject documentRef exceeding max length', async function () {
      const longRef = 'x'.repeat(1025);
      await expect(
        registry.registerAgentWithDocument(DID, CONTROLLER, longRef)
      ).to.be.revertedWith('documentRef too long');
    });

    it('should be queryable via isRevoked (not revoked)', async function () {
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      expect(await registry.isRevoked(DID)).to.equal(false);
    });
  });

  describe('revokeAgent', function () {
    it('should revoke a registered agent', async function () {
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      await registry.revokeAgent(DID);
      expect(await registry.isRevoked(DID)).to.equal(true);
    });

    it('should reject revoking non-existent DID', async function () {
      await expect(registry.revokeAgent(DID)).to.be.revertedWith('not found');
    });
  });

  describe('setDocumentRef', function () {
    it('should update documentRef for existing agent', async function () {
      await registry.registerAgent(DID, CONTROLLER);
      await registry.setDocumentRef(DID, DOC_REF);
      const record = await registry.getAgentRecord(DID);
      expect(record.documentRef).to.equal(DOC_REF);
    });

    it('should reject update from non-owner', async function () {
      await registry.registerAgent(DID, CONTROLLER);
      await expect(
        registry.connect(other).setDocumentRef(DID, DOC_REF)
      ).to.be.revertedWith('only owner');
    });
  });

  describe('revocationDelegate', function () {
    it('should allow delegate to revoke', async function () {
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      await registry.setRevocationDelegate(DID, other.address, true);
      expect(await registry.isRevocationDelegate(DID, other.address)).to.equal(true);
      await registry.connect(other).revokeAgent(DID);
      expect(await registry.isRevoked(DID)).to.equal(true);
    });
  });

  describe('transferAgentOwnership', function () {
    it('should transfer ownership', async function () {
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      await registry.transferAgentOwnership(DID, other.address);
      // New owner can update documentRef
      const newRef = 'hash://sha256/newref';
      await registry.connect(other).setDocumentRef(DID, newRef);
      const record = await registry.getAgentRecord(DID);
      expect(record.documentRef).to.equal(newRef);
    });
  });

  describe('pause / unpause', function () {
    it('should block operations when paused', async function () {
      await registry.pause();
      await expect(
        registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF)
      ).to.be.revertedWith('contract paused');
    });

    it('should resume after unpause', async function () {
      await registry.pause();
      await registry.unpause();
      await registry.registerAgentWithDocument(DID, CONTROLLER, DOC_REF);
      const record = await registry.getAgentRecord(DID);
      expect(record.recordDid).to.equal(DID);
    });
  });
});
