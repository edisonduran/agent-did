/**
 * AgentMetadataCredential (RFC-001 §4.4, ADR-006 D-8d): the controller issues the agent's metadata as a VC 2.0
 * credential with an `eddsa-jcs-2022` proof; the verifier checks the proof, the issuer, the subject and the binding.
 * Python parity: sdk-python/tests/test_agent_metadata_credential.py.
 */
import {
  AGENT_METADATA_CREDENTIAL_CONTEXT,
  AgentDidClient,
  AgentIdentity,
  AgentMetadataCredential,
  LocalKeySigner
} from '../src';
import { CreateAgentParams } from '../src/core/types';

const base: CreateAgentParams = {
  name: 'CredentialBot',
  description: 'Answers billing questions',
  version: '2.1.0',
  capabilities: ['billing:read', 'tickets:write']
};

let now = new Date('2026-11-15T12:00:00.000Z');
const clock = () => now;

async function party() {
  const client = new AgentDidClient({ clock });
  const [wallet] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner: wallet, client });
  const created = await identity.create(base);
  const controllerDid = created.document.controller;
  const controllerDocument = await client.resolve(controllerDid);
  return {
    client,
    identity,
    created,
    agentDid: created.document.id,
    controllerDid,
    controllerKeyId: (controllerDocument.assertionMethod as string[])[0],
    controllerSigner: new LocalKeySigner(created.controllerPrivateKey as string)
  };
}

async function verifierWith(logs: string[]): Promise<AgentDidClient> {
  const verifier = new AgentDidClient({ clock });
  for (const log of logs) {
    await verifier.importDidWebvhHistory(log);
  }
  return verifier;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

beforeEach(() => {
  now = new Date('2026-11-15T12:00:00.000Z');
});

describe('AgentMetadataCredential', () => {
  it('is issued by the controller and verifies in another client', async () => {
    const p = await party();
    const credential = await p.client.issueAgentMetadataCredential({
      agentDid: p.agentDid,
      signer: p.controllerSigner,
      verificationMethodId: p.controllerKeyId,
      validUntil: '2027-11-15T12:00:00Z'
    });

    expect(credential['@context']).toEqual(AGENT_METADATA_CREDENTIAL_CONTEXT);
    expect(credential.type).toEqual(['VerifiableCredential', 'AgentMetadataCredential']);
    expect(credential.issuer).toBe(p.controllerDid);
    expect(credential.validFrom).toBe('2026-11-15T12:00:00.000Z');
    expect(credential.credentialSubject).toEqual({
      id: p.agentDid,
      agentMetadata: {
        name: 'CredentialBot',
        description: 'Answers billing questions',
        version: '2.1.0',
        capabilities: ['billing:read', 'tickets:write']
      }
    });
    expect(credential.proof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-11-15T12:00:00.000Z',
      verificationMethod: p.controllerKeyId,
      proofPurpose: 'assertionMethod',
      '@context': credential['@context']
    });

    const verifier = await verifierWith([
      p.client.exportDidWebvhHistory(p.controllerDid),
      p.client.exportDidWebvhHistory(p.agentDid)
    ]);
    const result = await verifier.verifyAgentMetadataCredential(clone(credential), { expectedAgentDid: p.agentDid });
    expect(result).toEqual({
      ok: true,
      agentDid: p.agentDid,
      issuer: p.controllerDid,
      verificationMethod: p.controllerKeyId,
      agentMetadata: credential.credentialSubject.agentMetadata,
      controllers: [p.controllerDid]
    });
  });

  it('shares a subset of the metadata', async () => {
    const p = await party();
    const credential = await p.client.issueAgentMetadataCredential({
      agentDid: p.agentDid,
      signer: p.controllerSigner,
      verificationMethodId: p.controllerKeyId,
      agentMetadata: { name: 'CredentialBot', capabilities: ['billing:read'] },
      id: 'urn:uuid:7f1d3c1e-2f43-4a51-9a0e-6c1f0c2b9d11'
    });
    expect(credential.id).toBe('urn:uuid:7f1d3c1e-2f43-4a51-9a0e-6c1f0c2b9d11');
    expect(credential.credentialSubject.agentMetadata).toEqual({ name: 'CredentialBot', capabilities: ['billing:read'] });
    const result = await p.client.verifyAgentMetadataCredential(credential);
    expect(result.ok).toBe(true);
  });

  it('a self-controlled agent issues its own credential', async () => {
    const client = new AgentDidClient({ clock });
    const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
    const created = await identity.create({
      ...base,
      webvh: { domain: 'agents.example', controllerDid: '{DID}', controllerSigner: LocalKeySigner.generate()[0] }
    });
    const credential = await client.issueAgentMetadataCredential({
      agentDid: created.document.id,
      signer: new LocalKeySigner(created.agentPrivateKey),
      verificationMethodId: (created.document.assertionMethod as string[])[0]
    });
    expect(credential.issuer).toBe(created.document.id);
    const result = await client.verifyAgentMetadataCredential(credential);
    expect(result).toMatchObject({ ok: true, issuer: created.document.id, controllers: [] });
  });

  describe('issue refuses', () => {
    it('a key that is not an assertionMethod key of the controller', async () => {
      const p = await party();
      await expect(
        p.client.issueAgentMetadataCredential({
          agentDid: p.agentDid,
          signer: new LocalKeySigner(p.created.agentPrivateKey),
          verificationMethodId: p.created.document.assertionMethod![0]
        })
      ).rejects.toThrow(/must be a key of the agent's controller/);
      await expect(
        p.client.issueAgentMetadataCredential({
          agentDid: p.agentDid,
          signer: p.controllerSigner,
          verificationMethodId: `${p.controllerDid}#nope`
        })
      ).rejects.toThrow(/not an active Ed25519 assertionMethod key/);
    });

    it('a signer that does not hold the key', async () => {
      const p = await party();
      await expect(
        p.client.issueAgentMetadataCredential({
          agentDid: p.agentDid,
          signer: LocalKeySigner.generate()[0],
          verificationMethodId: p.controllerKeyId
        })
      ).rejects.toThrow(/does not hold/);
    });

    it('bad metadata and dates', async () => {
      const p = await party();
      const params = { agentDid: p.agentDid, signer: p.controllerSigner, verificationMethodId: p.controllerKeyId };
      await expect(p.client.issueAgentMetadataCredential({ ...params, agentMetadata: {} })).rejects.toThrow(TypeError);
      await expect(
        p.client.issueAgentMetadataCredential({ ...params, agentMetadata: { name: 'x', extra: 1 } as never })
      ).rejects.toThrow(/not an agentMetadata member/);
      await expect(p.client.issueAgentMetadataCredential({ ...params, validFrom: '2026-11-15' })).rejects.toThrow(TypeError);
      await expect(
        p.client.issueAgentMetadataCredential({ ...params, validFrom: '2026-11-15T00:00:00Z', validUntil: '2026-11-14T00:00:00Z' })
      ).rejects.toThrow(TypeError);
    });

    it('a deactivated agent', async () => {
      const p = await party();
      await p.client.revokeDid(p.agentDid);
      await expect(
        p.client.issueAgentMetadataCredential({ agentDid: p.agentDid, signer: p.controllerSigner, verificationMethodId: p.controllerKeyId })
      ).rejects.toThrow(/revoked/);
    });
  });

  describe('verify rejects', () => {
    let p: Awaited<ReturnType<typeof party>>;
    let credential: AgentMetadataCredential;

    beforeEach(async () => {
      p = await party();
      credential = await p.client.issueAgentMetadataCredential({
        agentDid: p.agentDid,
        signer: p.controllerSigner,
        verificationMethodId: p.controllerKeyId,
        validUntil: '2026-12-15T12:00:00Z'
      });
    });

    const reason = async (value: unknown, options = {}) => {
      const result = await p.client.verifyAgentMetadataCredential(value, options);
      return result.ok ? 'ok' : result.reason;
    };

    it('a malformed credential', async () => {
      expect(await reason(null)).toBe('malformed_credential');
      expect(await reason({ ...clone(credential), '@context': ['https://www.w3.org/ns/credentials/v2'] })).toBe('malformed_credential');
      expect(await reason({ ...clone(credential), type: ['VerifiableCredential'] })).toBe('malformed_credential');
      expect(await reason({ ...clone(credential), issuer: { id: p.controllerDid } })).toBe('malformed_credential');
      expect(await reason({ ...clone(credential), credentialStatus: { id: 'x' } })).toBe('malformed_credential');
      expect(await reason({ ...clone(credential), validFrom: 'yesterday' })).toBe('malformed_credential');
      const noSubject = clone(credential) as unknown as Record<string, Record<string, unknown>>;
      delete noSubject.credentialSubject.agentMetadata;
      expect(await reason(noSubject)).toBe('malformed_credential');
    });

    it('an unsupported proof', async () => {
      expect(await reason({ ...clone(credential), proof: [clone(credential.proof)] })).toBe('unsupported_proof');
      expect(await reason({ ...clone(credential), proof: undefined })).toBe('unsupported_proof');
      for (const patch of [
        { cryptosuite: 'eddsa-rdfc-2022' },
        { proofPurpose: 'authentication' },
        { verificationMethod: `${p.agentDid}#key-1` },
        { proofValue: 'zabc' },
        { created: 'now' }
      ]) {
        expect(await reason({ ...clone(credential), proof: { ...clone(credential.proof), ...patch } })).toBe('unsupported_proof');
      }
    });

    it('outside the validity period', async () => {
      now = new Date('2026-11-15T11:59:59.000Z');
      expect(await reason(credential)).toBe('not_yet_valid');
      now = new Date('2026-12-15T12:00:01.000Z');
      expect(await reason(credential)).toBe('expired');
    });

    it('another subject than expected', async () => {
      expect(await reason(credential, { expectedAgentDid: p.controllerDid })).toBe('subject_mismatch');
    });

    it('a changed claim or proof member', async () => {
      const tampered = clone(credential);
      tampered.credentialSubject.agentMetadata.capabilities = ['admin'];
      expect(await reason(tampered)).toBe('signature_invalid');
      const otherCreated = clone(credential);
      otherCreated.proof.created = '2026-11-15T12:00:01.000Z';
      expect(await reason(otherCreated)).toBe('signature_invalid');
      const otherContext = clone(credential);
      otherContext.proof['@context'] = ['https://www.w3.org/ns/credentials/v2'];
      expect(await reason(otherContext)).toBe('signature_invalid');
    });

    it('an issuer that is not the controller', async () => {
      const other = await party();
      const forged = await other.client.issueAgentMetadataCredential({
        agentDid: other.agentDid,
        signer: other.controllerSigner,
        verificationMethodId: other.controllerKeyId
      });
      // Re-target the credential at p's agent: the issuer (other's controller) is not p's controller
      const retargeted = clone(forged);
      retargeted.credentialSubject.id = p.agentDid;
      const verifier = await verifierWith([
        p.client.exportDidWebvhHistory(p.controllerDid),
        p.client.exportDidWebvhHistory(p.agentDid),
        other.client.exportDidWebvhHistory(other.controllerDid)
      ]);
      const result = await verifier.verifyAgentMetadataCredential(retargeted);
      expect(result).toEqual({ ok: false, reason: 'issuer_not_controller' });
    });

    it('a key the issuer does not list under assertionMethod', async () => {
      const wrongKey = clone(credential);
      wrongKey.proof.verificationMethod = `${p.controllerDid}#key-9`;
      expect(await reason(wrongKey)).toBe('key_not_authorized');
    });

    it('a deactivated agent', async () => {
      await p.client.revokeDid(p.agentDid);
      expect(await reason(credential)).toBe('did_deactivated');
    });

    it('an unknown agent', async () => {
      const verifier = new AgentDidClient({ clock });
      expect(await verifier.verifyAgentMetadataCredential(credential)).toEqual({ ok: false, reason: 'did_resolution_failed' });
    });

    it('an agent that is not bound to its controller', async () => {
      const mallory = new AgentDidClient({ clock });
      const malloryIdentity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client: mallory });
      const forged = await malloryIdentity.create({
        ...base,
        name: 'ForgedBot',
        webvh: { domain: 'mallory.example', controllerDid: p.controllerDid, controllerSigner: LocalKeySigner.generate()[0] }
      });
      const claim = clone(credential);
      claim.credentialSubject.id = forged.document.id;
      const verifier = await verifierWith([
        p.client.exportDidWebvhHistory(p.controllerDid),
        mallory.exportDidWebvhHistory(forged.document.id)
      ]);
      expect(await verifier.verifyAgentMetadataCredential(claim)).toEqual({ ok: false, reason: 'controller_not_bound' });
    });
  });
});
