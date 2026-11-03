import { LocalKeySigner } from '../../src/core/signer';
import { createDidWebvhLog, DID_WEBVH_PLACEHOLDER, DidWebvhLogResult } from '../../src/webvh/adapter';

export const TEST_CONTROLLER_KEY = '5a'.repeat(32);

/** Agent-DID document template; `{DID}` is replaced with the generated did:webvh DID. */
export function agentDocumentTemplate(name = 'WebvhResolverBot'): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://agent-did.org/v1'],
    id: DID_WEBVH_PLACEHOLDER,
    controller: 'did:webvh:QmControllerScid:example.com:organizations:acme-support',
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
    agentMetadata: {
      name,
      version: '1.0.0',
      coreModelHash: 'hash://hmac-sha256/model',
      systemPromptHash: 'hash://hmac-sha256/prompt'
    },
    verificationMethod: [
      {
        id: `${DID_WEBVH_PLACEHOLDER}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: DID_WEBVH_PLACEHOLDER,
        publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      }
    ],
    authentication: [`${DID_WEBVH_PLACEHOLDER}#key-1`],
    assertionMethod: [`${DID_WEBVH_PLACEHOLDER}#key-1`]
  };
}

/** A controller-signed did:webvh v1.0 log holding an Agent-DID document. */
export function createAgentWebvhLog(domain: string, pathSegments: string[] = []): Promise<DidWebvhLogResult> {
  return createDidWebvhLog({
    domain,
    pathSegments,
    document: agentDocumentTemplate(),
    signer: new LocalKeySigner(TEST_CONTROLLER_KEY),
    created: '2026-01-01T00:00:00Z'
  });
}

/** Rewrites the `state` of the last entry without re-signing it. */
export function tamperLastState(log: string, mutate: (state: Record<string, any>) => void): string {
  const lines = log.trimEnd().split('\n');
  const entry = JSON.parse(lines[lines.length - 1]);
  mutate(entry.state);
  lines[lines.length - 1] = JSON.stringify(entry);
  return lines.join('\n') + '\n';
}

export function textResponse(body: string, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => ({}), text: async () => body };
}
