// Run: node sdk/examples/quickstart.js

const { AgentIdentity, InMemoryAgentRegistry, LocalKeySigner } = require('../dist');

const main = async () => {
  AgentIdentity.setRegistry(new InMemoryAgentRegistry());

  const [controllerSigner] = LocalKeySigner.generate();
  const identity = new AgentIdentity({ controllerSigner });

  const created = await identity.create({
    name: 'quickstart-bot',
    coreModel: 'gpt-4.1-mini',
    systemPrompt: 'Sign outbound API requests.'
  });

  const headers = await identity.signHttpRequest({
    method: 'POST',
    url: 'https://api.example.com/tasks',
    body: '{"taskId":7}',
    agentPrivateKey: created.agentPrivateKey,
    agentDid: created.document.id, verificationMethodId: `${created.document.id}#key-1`
  });

  const ok = await AgentIdentity.verifyHttpRequestSignature({
    method: 'POST',
    url: 'https://api.example.com/tasks',
    body: '{"taskId":7}',
    headers
  });

  console.log({
    did: created.document.id,
    controller: created.document.controller,
    ok,
    headerNames: Object.keys(headers).sort()
  });
};

void main();