const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { AgentIdentity, LocalKeySigner } = require('../../sdk/dist/index.js');
const {
  EvmAgentRegistry,
  EthersAgentRegistryContractClient,
  REGISTRATION_ATTESTATION_TYPES,
  registrationAttestationDomain,
  registrationAttestationMessage
} = require('../dist/index.js');

const ABI_PATH = path.resolve(__dirname, './abi/AgentRegistry.abi.json');

function loadAbi() {
  if (!fs.existsSync(ABI_PATH)) {
    throw new Error(`ABI file not found at ${ABI_PATH}`);
  }

  return JSON.parse(fs.readFileSync(ABI_PATH, 'utf8'));
}

async function main() {
  const rpcUrl = process.env.RPC_URL || 'http://127.0.0.1:8545';
  const registryAddress = process.env.AGENT_REGISTRY_ADDRESS;
  const privateKey = process.env.CREATOR_PRIVATE_KEY;
  const creatorAccountIndex = process.env.CREATOR_ACCOUNT_INDEX;

  if (!registryAddress) {
    throw new Error('Missing AGENT_REGISTRY_ADDRESS environment variable');
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  let signer;

  if (privateKey) {
    signer = new ethers.Wallet(privateKey, provider);
  } else if (creatorAccountIndex !== undefined) {
    signer = await provider.getSigner(Number(creatorAccountIndex));
  } else {
    throw new Error('Missing signer configuration. Set CREATOR_PRIVATE_KEY or CREATOR_ACCOUNT_INDEX');
  }

  const abi = loadAbi();

  const contract = new ethers.Contract(registryAddress, abi, signer);
  const contractClient = new EthersAgentRegistryContractClient(contract);
  // The deployer (account 0) is the contract's initial registrar. In production the registrar is a
  // separate service that verifies DID control before signing.
  const registrar = await provider.getSigner(Number(process.env.REGISTRAR_ACCOUNT_INDEX || 0));
  const ownerAddress = await signer.getAddress();
  const { chainId } = await provider.getNetwork();

  const registry = new EvmAgentRegistry({
    contractClient,
    awaitTransactionConfirmation: true,
    attestationProvider: async (request) => {
      const deadline = Math.floor(Date.now() / 1000) + 3600;
      const signature = await registrar.signTypedData(
        registrationAttestationDomain(chainId, registryAddress),
        REGISTRATION_ATTESTATION_TYPES,
        registrationAttestationMessage(request, ownerAddress, deadline)
      );
      return { owner: ownerAddress, deadline, signature };
    }
  });

  AgentIdentity.setRegistry(registry);

  const identity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], network: 'localhost' });
  const { document, agentPrivateKey } = await identity.create({
    name: 'SmokeBot',
    coreModel: 'gpt-4o-mini',
    systemPrompt: 'You are a smoke test bot',
    didMethod: 'agent'
  });

  const payload = 'approve:smoke:1';
  const signature = await identity.signMessage(payload, agentPrivateKey);

  const validBeforeRevocation = await AgentIdentity.verifySignature(document.id, payload, signature);
  if (!validBeforeRevocation) {
    throw new Error('Expected signature to be valid before revocation');
  }

  await AgentIdentity.revokeDid(document.id);

  const validAfterRevocation = await AgentIdentity.verifySignature(document.id, payload, signature);
  if (validAfterRevocation) {
    throw new Error('Expected signature to be invalid after revocation');
  }

  console.log('SMOKE TEST PASSED');
  console.log(`DID: ${document.id}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
