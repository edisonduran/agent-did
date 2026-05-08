const fs = require('node:fs');
const path = require('node:path');

const { SDK_DIST } = require('./smoke-utils');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_MANIFEST_PATH = path.join(ROOT, 'fixtures', 'external-smoke', 'webvh-public-targets.json');

function parseBooleanEnv(name) {
  const value = process.env[name];
  if (!value) {
    return false;
  }

  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function resolveManifestPath() {
  const explicitManifestPath = process.env.AGENTDID_WEBVH_EXTERNAL_MANIFEST;
  if (!explicitManifestPath) {
    return DEFAULT_MANIFEST_PATH;
  }

  return path.isAbsolute(explicitManifestPath)
    ? explicitManifestPath
    : path.join(ROOT, explicitManifestPath);
}

function loadManifestTarget() {
  const manifestPath = resolveManifestPath();
  let manifest;

  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`No se pudo leer el manifest de smoke externo (${manifestPath}): ${message}`);
  }

  const targetName = process.env.AGENTDID_WEBVH_EXTERNAL_TARGET || manifest.defaultTarget;
  const target = manifest.targets?.[targetName];

  if (!target) {
    throw new Error(`Target externo no encontrado en el manifest: ${targetName}`);
  }

  if (!Array.isArray(target.candidateUrls) || target.candidateUrls.length === 0) {
    throw new Error(`El target externo ${targetName} no define candidateUrls.`);
  }

  if (typeof target.did !== 'string' || target.did.trim().length === 0) {
    throw new Error(`El target externo ${targetName} no define un did esperado.`);
  }

  return {
    candidateUrls: target.candidateUrls,
    expectedDid: target.did,
    manifestPath,
    targetName
  };
}

function parseCandidateUrls() {
  const explicitUrls = process.env.AGENTDID_WEBVH_EXTERNAL_URLS;
  if (explicitUrls) {
    return explicitUrls
      .split(',')
      .map((url) => url.trim())
      .filter((url) => url.length > 0);
  }

  const singleUrl = process.env.AGENTDID_WEBVH_EXTERNAL_URL;
  if (singleUrl && singleUrl.trim().length > 0) {
    return [singleUrl.trim()];
  }

  return [];
}

function resolveExternalTarget() {
  const candidateUrls = parseCandidateUrls();
  if (candidateUrls.length > 0) {
    return {
      candidateUrls,
      expectedDid: process.env.AGENTDID_WEBVH_EXTERNAL_DID,
      sourceLabel: 'env override'
    };
  }

  const manifestTarget = loadManifestTarget();
  return {
    candidateUrls: manifestTarget.candidateUrls,
    expectedDid: process.env.AGENTDID_WEBVH_EXTERNAL_DID || manifestTarget.expectedDid,
    sourceLabel: `manifest:${manifestTarget.targetName}`,
    manifestPath: manifestTarget.manifestPath
  };
}

async function main() {
  let WebvhDIDDocumentSource;
  try {
    ({ WebvhDIDDocumentSource } = require(path.join(SDK_DIST, 'resolver', 'WebvhDIDDocumentSource.js')));
  } catch {
    throw new Error('SDK dist no encontrado. Ejecuta `npm --prefix sdk run build`.');
  }

  const externalTarget = resolveExternalTarget();
  const timeoutMs = Number(process.env.AGENTDID_WEBVH_EXTERNAL_TIMEOUT_MS || '15000');
  const allowPrivateTargets = parseBooleanEnv('AGENTDID_WEBVH_EXTERNAL_ALLOW_PRIVATE_TARGETS');

  const fetchFn = async (url) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await fetch(url, { signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  };

  const source = new WebvhDIDDocumentSource({
    referenceToUrls: () => externalTarget.candidateUrls,
    fetchFn,
    httpSecurity: {
      allowPrivateTargets
    }
  });

  const resolved = await source.getByReference(externalTarget.candidateUrls[0]);
  if (!resolved) {
    throw new Error(
      `No se pudo resolver did:webvh desde los endpoints externos: ${externalTarget.candidateUrls.join(', ')}`
    );
  }

  if (!resolved.id.startsWith('did:webvh:')) {
    throw new Error(`El documento externo no resolvió un DID did:webvh: ${resolved.id}`);
  }

  if (externalTarget.expectedDid && resolved.id !== externalTarget.expectedDid) {
    throw new Error(`DID resuelto inesperado. Esperado=${externalTarget.expectedDid} actual=${resolved.id}`);
  }

  if (!Array.isArray(resolved.verificationMethod) || resolved.verificationMethod.length === 0) {
    throw new Error('El documento externo no expone verificationMethod.');
  }

  if (!Array.isArray(resolved.assertionMethod) || resolved.assertionMethod.length === 0) {
    throw new Error('El documento externo no expone assertionMethod.');
  }

  console.log('✅ External did:webvh smoke completed successfully');
  console.log(`Resolved DID: ${resolved.id}`);
  console.log(`Updated: ${resolved.updated}`);
  console.log(`Source: ${externalTarget.sourceLabel}`);
  if (externalTarget.manifestPath) {
    console.log(`Manifest: ${externalTarget.manifestPath}`);
  }
  console.log(`Candidate URLs: ${externalTarget.candidateUrls.join(', ')}`);
}

main().catch((error) => {
  console.error('❌ External did:webvh smoke failed');
  console.error(error);
  process.exit(1);
});