import { LocalKeySigner } from '../src/core/signer';
import { AgentDidClient, AgentIdentity } from '../src';

// Parity: sdk-python/tests/test_history_labels.py
describe('history derived from an imported did:webvh log', () => {
  it('labels an added key as an update and a retired key as a rotation', async () => {
    const owner = new AgentDidClient();
    const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client: owner });
    const { document } = await identity.create({ name: 'HistoryBot', coreModel: 'test', systemPrompt: 'test' });
    await owner.addVerificationMethod(document.id);
    await owner.rotateVerificationMethod(document.id);

    const reader = new AgentDidClient();
    await reader.importDidWebvhHistory(owner.exportDidWebvhHistory(document.controller as string));
    await reader.importDidWebvhHistory(owner.exportDidWebvhHistory(document.id));

    expect(reader.getDocumentHistory(document.id).map((entry) => entry.action)).toEqual(['created', 'updated', 'rotated-key']);
  });
});
