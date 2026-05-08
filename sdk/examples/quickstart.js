// Run: node sdk/examples/quickstart.js

const { AgentIdentity, InMemoryAgentRegistry } = require('../dist');
const { ethers } = require('ethers');

const main = async () => {
  AgentIdentity.setRegistry(new InMemoryAgentRegistry());

  const wallet = ethers.Wallet.createRandom();
  const identity = new AgentIdentity({ signer: wallet });

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
    agentDid: created.document.id
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