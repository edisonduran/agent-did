import { ethers } from 'ethers';
import { AgentDidClient, AgentIdentity } from '../src';
import { CreateAgentParams } from '../src/core/types';

const params: CreateAgentParams = {
  name: 'ClientBot',
  description: 'Agent used to test AgentDidClient isolation',
  coreModel: 'gpt-4o-mini',
  systemPrompt: 'You are a test assistant.'
};

describe('AgentDidClient', () => {
  const wallet = ethers.Wallet.createRandom();

  it('keeps state isolated between clients', async () => {
    const a = new AgentDidClient();
    const b = new AgentDidClient();
    const { document } = await new AgentIdentity({ signer: wallet, client: a }).create(params);

    expect((await a.resolve(document.id)).id).toBe(document.id);
    expect(a.getDocumentHistory(document.id)).toHaveLength(1);
    await expect(b.resolve(document.id)).rejects.toThrow();
    expect(b.getDocumentHistory(document.id)).toHaveLength(0);
  });

  it('does not touch the default client when an explicit client is used', async () => {
    const client = new AgentDidClient();
    const { document } = await new AgentIdentity({ signer: wallet, client }).create(params);
    expect(AgentIdentity.getDefaultClient().getDocumentHistory(document.id)).toHaveLength(0);
  });

  it('verifies signatures through the client that created the agent', async () => {
    const client = new AgentDidClient();
    const identity = new AgentIdentity({ signer: wallet, client });
    const { document, agentPrivateKey } = await identity.create(params);
    const signature = await identity.signMessage('hello', agentPrivateKey);
    expect(await client.verifySignature(document.id, 'hello', signature)).toBe(true);
  });

  it('uses the injected clock for document timestamps', async () => {
    const fixed = new Date('2030-01-02T03:04:05.000Z');
    const client = new AgentDidClient({ clock: () => fixed });
    const { document } = await new AgentIdentity({ signer: wallet, client }).create(params);
    expect(document.created).toBe('2030-01-02T03:04:05.000Z');
  });

  it('the static API delegates to the replaceable default client', async () => {
    const previous = AgentIdentity.getDefaultClient();
    const fresh = new AgentDidClient();
    AgentIdentity.setDefaultClient(fresh);
    try {
      const { document } = await new AgentIdentity({ signer: wallet }).create(params);
      expect((await AgentIdentity.resolve(document.id)).id).toBe(document.id);
      expect(fresh.getDocumentHistory(document.id)).toHaveLength(1);
    } finally {
      AgentIdentity.setDefaultClient(previous);
    }
  });
});
