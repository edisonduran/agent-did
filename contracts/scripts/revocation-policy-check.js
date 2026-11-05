const hre = require('hardhat');

async function expectRevert(promise, expectedMessage) {
  try {
    await promise;
    throw new Error(`Expected revert with message containing: ${expectedMessage}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes(expectedMessage)) {
      throw new Error(`Unexpected revert message. Expected to include "${expectedMessage}", got: ${message}`);
    }
  }
}

async function registerAttested(contract, registrar, ownerAddress, did) {
  const { chainId } = await hre.ethers.provider.getNetwork();
  const deadline = Math.floor(Date.now() / 1000) + 3600;
  const controller = `did:ethr:${ownerAddress}`;
  const signature = await registrar.signTypedData(
    { name: 'AgentRegistry', version: '1', chainId, verifyingContract: await contract.getAddress() },
    {
      Registration: [
        { name: 'did', type: 'string' },
        { name: 'controller', type: 'string' },
        { name: 'documentRef', type: 'string' },
        { name: 'owner', type: 'address' },
        { name: 'deadline', type: 'uint256' }
      ]
    },
    { did, controller, documentRef: '', owner: ownerAddress, deadline }
  );
  await (await contract.registerAgentAttested(did, controller, '', { owner: ownerAddress, deadline, signature })).wait();
}

async function main() {
  const contractAddress = process.env.AGENT_REGISTRY_ADDRESS;
  if (!contractAddress) {
    throw new Error('AGENT_REGISTRY_ADDRESS is required');
  }

  const [deployer, owner, delegate, newOwner] = await hre.ethers.getSigners();
  const contract = await hre.ethers.getContractAt('AgentRegistry', contractAddress);

  const didOne = 'did:agent:polygon:0xpolicy1';
  await registerAttested(contract, deployer, owner.address, didOne);

  await expectRevert(contract.connect(delegate).revokeAgent(didOne), 'not authorized');

  await (await contract.connect(owner).setRevocationDelegate(didOne, delegate.address, true)).wait();

  const isDelegateAuthorized = await contract.isRevocationDelegate(didOne, delegate.address);
  if (!isDelegateAuthorized) {
    throw new Error('Delegate should be authorized after setRevocationDelegate');
  }

  await (await contract.connect(delegate).revokeAgent(didOne)).wait();

  const didOneRevoked = await contract.isRevoked(didOne);
  if (!didOneRevoked) {
    throw new Error('DID should be revoked by authorized delegate');
  }

  const didTwo = 'did:agent:polygon:0xpolicy2';
  await registerAttested(contract, deployer, owner.address, didTwo);

  await (await contract.connect(owner).transferAgentOwnership(didTwo, newOwner.address)).wait();

  await expectRevert(
    contract.connect(owner).setRevocationDelegate(didTwo, delegate.address, true),
    'only owner'
  );

  await (await contract.connect(newOwner).setRevocationDelegate(didTwo, delegate.address, true)).wait();
  await (await contract.connect(delegate).revokeAgent(didTwo)).wait();

  const didTwoRevoked = await contract.isRevoked(didTwo);
  if (!didTwoRevoked) {
    throw new Error('DID should be revoked after ownership transfer + delegation');
  }

  console.log('✅ Revocation policy check completed successfully');
}

main().catch((error) => {
  console.error('❌ Revocation policy check failed');
  console.error(error);
  process.exit(1);
});
