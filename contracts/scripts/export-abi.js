const fs = require('fs');
const path = require('path');

function main() {
  const artifactPath = path.join(
    __dirname,
    '..',
    'artifacts',
    'src',
    'AgentRegistry.sol',
    'AgentRegistry.json'
  );

  if (!fs.existsSync(artifactPath)) {
    throw new Error('Artifact not found. Run `npm run build` in contracts/ first.');
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const outputDir = path.join(__dirname, '..', '..', 'evm', 'examples', 'abi');
  const outputPath = path.join(outputDir, 'AgentRegistry.abi.json');

  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(artifact.abi, null, 2));

  console.log(`ABI exported to: ${outputPath}`);
}

main();
