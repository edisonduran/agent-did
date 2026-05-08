import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import {
  AgentIdentity,
  EvmAgentRegistry,
  EthersAgentRegistryContractClient
} from '../src';

const ABI_PATH = path.resolve(__dirname, './abi/AgentRegistry.abi.json');

function loadAgentRegistryAbi(): unknown[] {
  if (!fs.existsSync(ABI_PATH)) {
    throw new Error(`ABI file not found at ${ABI_PATH}. Run contracts export first: npm run export:abi`);
  }

  const content = fs.readFileSync(ABI_PATH, 'utf8');
  return JSON.parse(content) as unknown[];
}

const AGENT_REGISTRY_ABI_FALLBACK = [
  'function registerAgent(string did, string controller) external',
  'function setDocumentRef(string did, string documentRef) external',
  'function revokeAgent(string did) external',
  'function getAgentRecord(string did) external view returns (string did, string controller, string createdAt, string revokedAt, string documentRef)',
  'function isRevoked(string did) external view returns (bool)'
];

async function main() {
  const rpcUrl = process.env.RPC_URL;
  const privateKey = process.env.CREATOR_PRIVATE_KEY;
  const registryAddress = process.env.AGENT_REGISTRY_ADDRESS;

  if (!rpcUrl || !privateKey || !registryAddress) {
    throw new Error('Missing required env vars: RPC_URL, CREATOR_PRIVATE_KEY, AGENT_REGISTRY_ADDRESS');
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);
  const abi = loadAgentRegistryAbi() || AGENT_REGISTRY_ABI_FALLBACK;

  const contract = new ethers.Contract(registryAddress, abi, signer);
  const contractClient = new EthersAgentRegistryContractClient(contract as never);
  const registry = new EvmAgentRegistry({
    contractClient,
    awaitTransactionConfirmation: true
  });

  AgentIdentity.setRegistry(registry);

  const identity = new AgentIdentity({
    signer,
    network: 'polygon'
  });

  const { document, agentPrivateKey } = await identity.create({
    name: 'EvmLinkedBot',
    coreModel: 'gpt-4o-mini',
    systemPrompt: 'You are a compliant enterprise assistant',
    didMethod: 'agent'
  });

  const payload = 'approve:order:456';
  const signature = await identity.signMessage(payload, agentPrivateKey);
  const isValid = await AgentIdentity.verifySignature(document.id, payload, signature);

  console.log('DID:', document.id);
  console.log('Signature valid:', isValid);

  await AgentIdentity.revokeDid(document.id);
  const isValidAfterRevocation = await AgentIdentity.verifySignature(document.id, payload, signature);
  console.log('Signature valid after revocation:', isValidAfterRevocation);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
