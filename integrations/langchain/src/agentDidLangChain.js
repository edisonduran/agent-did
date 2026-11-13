const net = require("node:net");
const { SystemMessage } = require("@langchain/core/messages");
const { tool } = require("@langchain/core/tools");
const { z } = require("zod");
const { createAgentDidObserver } = require("./observability");

const MIDDLEWARE_BRAND = Symbol.for("AgentMiddleware");
const MAX_PAYLOAD_BYTES = 1048576; // 1 MB

const DEFAULT_EXPOSURE = {
  currentIdentity: true,
  resolveDid: true,
  verifySignatures: true,
  signPayload: false,
  signHttp: false,
  documentHistory: false,
  rotateKeys: false,
};

function withPrefix(prefix, name) {
  return `${prefix}_${name}`;
}

/**
 * The key the agent signs payloads and HTTP requests with: the key of the last rotation, else the first active key
 * under `assertionMethod`, the relationship verifiers require for both (RFC-001 §6.2.1.3).
 */
function getActiveSigningKeyId(runtimeIdentity) {
  if (runtimeIdentity.verificationMethodId) {
    return runtimeIdentity.verificationMethodId;
  }
  const document = runtimeIdentity.document;
  const retired = new Set(document.verificationMethod.filter((method) => method.deactivated).map((method) => method.id));
  return (document.assertionMethod ?? []).find((keyId) => !retired.has(keyId));
}

function getActiveVerificationMethodId(runtimeIdentity) {
  return runtimeIdentity.verificationMethodId ?? runtimeIdentity.document.authentication[0];
}

function createBrandedMiddleware(config) {
  return {
    [MIDDLEWARE_BRAND]: true,
    name: config.name,
    wrapModelCall: config.wrapModelCall,
  };
}

function buildAgentDidIdentitySnapshot(runtimeIdentity) {
  const { document } = runtimeIdentity;

  return {
    did: document.id,
    controller: document.controller,
    name: document.agentMetadata.name,
    description: document.agentMetadata.description,
    version: document.agentMetadata.version,
    capabilities: document.agentMetadata.capabilities ?? [],
    memberOf: document.agentMetadata.memberOf,
    authenticationKeyId: getActiveVerificationMethodId(runtimeIdentity),
    created: document.created,
    updated: document.updated,
  };
}

function buildAgentDidSystemPrompt(snapshot, additionalSystemContext) {
  const capabilities = snapshot.capabilities.length > 0 ? snapshot.capabilities.join(", ") : "none";
  const lines = [
    "Agent-DID identity context:",
    `- did: ${snapshot.did}`,
    `- controller: ${snapshot.controller}`,
    `- name: ${snapshot.name}`,
    `- version: ${snapshot.version}`,
    `- capabilities: ${capabilities}`,
    `- member_of: ${snapshot.memberOf ?? "none"}`,
    `- authentication_key_id: ${snapshot.authenticationKeyId ?? "unknown"}`,
    "Rules:",
    "- Treat this DID as the authoritative identity of this agent.",
    "- Never invent or substitute another DID for this agent.",
    "- If an outbound HTTP request must be authenticated with Agent-DID, use the dedicated signing tool instead of fabricating headers.",
  ];

  if (additionalSystemContext && additionalSystemContext.trim()) {
    lines.push(`Additional identity policy: ${additionalSystemContext.trim()}`);
  }

  return lines.join("\n");
}

function validateHttpTarget(url, allowPrivateNetworkTargets) {
  const parsedUrl = new URL(url);
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error("Only http and https URLs are allowed");
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new Error("URLs with embedded credentials are not allowed");
  }

  const hostname = parsedUrl.hostname;
  if (!hostname) {
    throw new Error("An absolute URL with hostname is required");
  }

  // URL.hostname keeps the brackets of an IPv6 literal ("[::1]"), which net.isIP does not accept
  const normalizedHostname = hostname.toLowerCase().replace(/^\[|\]$/gu, "");
  if (allowPrivateNetworkTargets) {
    return;
  }

  if (normalizedHostname === "localhost" || normalizedHostname.endsWith(".localhost")) {
    throw new Error("Private or loopback HTTP targets are not allowed by default");
  }

  const ipVersion = net.isIP(normalizedHostname);
  if (ipVersion === 4 && isRestrictedIpv4(normalizedHostname)) {
    throw new Error("Private or loopback HTTP targets are not allowed by default");
  }

  if (ipVersion === 6 && isRestrictedIpv6(normalizedHostname)) {
    throw new Error("Private or loopback HTTP targets are not allowed by default");
  }
}

function isRestrictedIpv4(hostname) {
  const octets = hostname.split(".").map((segment) => Number.parseInt(segment, 10));
  if (octets.length !== 4 || octets.some((segment) => Number.isNaN(segment))) {
    return false;
  }

  const [first, second] = octets;
  if (first === 10 || first === 127 || first === 0) {
    return true;
  }
  if (first === 169 && second === 254) {
    return true;
  }
  if (first === 172 && second >= 16 && second <= 31) {
    return true;
  }
  if (first === 192 && second === 168) {
    return true;
  }
  if (first >= 224) {
    return true;
  }

  return false;
}

function isRestrictedIpv6(hostname) {
  const normalizedHostname = hostname.toLowerCase();
  return (
    normalizedHostname === "::1"
    || normalizedHostname === "::"
    || normalizedHostname.startsWith("fc")
    || normalizedHostname.startsWith("fd")
    || normalizedHostname.startsWith("fe8")
    || normalizedHostname.startsWith("fe9")
    || normalizedHostname.startsWith("fea")
    || normalizedHostname.startsWith("feb")
    || normalizedHostname.startsWith("ff")
  );
}

function emitToolStarted(observer, { toolName, did, inputs = {} }) {
  observer.emit("agent_did.tool.started", {
    attributes: {
      tool_name: toolName,
      did,
      inputs,
    },
  });
}

function emitToolSucceeded(observer, { toolName, did, outputs = {} }) {
  observer.emit("agent_did.tool.succeeded", {
    attributes: {
      tool_name: toolName,
      did,
      outputs,
    },
  });
}

function emitToolFailed(observer, { toolName, did, error, inputs = {} }) {
  observer.emit("agent_did.tool.failed", {
    level: "error",
    attributes: {
      tool_name: toolName,
      did,
      inputs,
      error: error instanceof Error ? error.message : String(error),
    },
  });
}

function captureIdentitySnapshot(runtimeIdentity, observer, reason) {
  const snapshot = buildAgentDidIdentitySnapshot(runtimeIdentity);
  observer.emit("agent_did.identity_snapshot.refreshed", {
    attributes: {
      did: snapshot.did,
      authentication_key_id: snapshot.authenticationKeyId,
      reason,
    },
  });
  return snapshot;
}

function createAgentDidMiddleware(options) {
  const middlewareName = options.middlewareName ?? "AgentDidIdentityMiddleware";
  const observer = options.observer ?? createAgentDidObserver();

  return createBrandedMiddleware({
    name: middlewareName,
    wrapModelCall: async (request, handler) => {
      const snapshot = captureIdentitySnapshot(options.runtimeIdentity, observer, "middleware");
      const identitySection = buildAgentDidSystemPrompt(snapshot, options.additionalSystemContext);

      return handler({
        ...request,
        systemMessage: request.systemMessage.concat(
          new SystemMessage({
            content: identitySection,
          })
        ),
      });
    },
  });
}

function createAgentDidTools(options) {
  const exposure = { ...DEFAULT_EXPOSURE, ...options.expose };
  const toolPrefix = options.toolPrefix ?? "agent_did";
  const observer = options.observer ?? createAgentDidObserver();
  const tools = [];

  if (exposure.currentIdentity) {
    tools.push(
      tool(async () => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "get_current_identity");
        emitToolStarted(observer, { toolName, did: currentDid });
        try {
          const snapshot = captureIdentitySnapshot(options.runtimeIdentity, observer, "tool:get_current_identity");
          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: {
              authentication_key_id: snapshot.authenticationKeyId,
            },
          });
          return snapshot;
        } catch (err) {
          emitToolFailed(observer, { toolName, did: currentDid, error: err });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "get_current_identity"),
        description: "Return the current Agent-DID identity attached to this LangChain agent.",
        schema: z.object({}),
      })
    );
  }

  if (exposure.resolveDid) {
    tools.push(
      tool(async ({ did }) => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "resolve_did");
        emitToolStarted(observer, { toolName, did: currentDid, inputs: { did } });
        try {
          const targetDid = did && did.trim() ? did.trim() : options.runtimeIdentity.document.id;
          const resolved = await options.agentIdentity.client.resolve(targetDid);
          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: { resolved_did: resolved.id },
          });
          return resolved;
        } catch (err) {
          emitToolFailed(observer, { toolName, did: currentDid, error: err, inputs: { did } });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "resolve_did"),
        description: "Resolve an Agent-DID document. If no DID is provided, resolves the current agent DID.",
        schema: z.object({
          did: z.string().max(512).optional().describe("Optional DID to resolve"),
        }),
      })
    );
  }

  if (exposure.verifySignatures) {
    tools.push(
      tool(async ({ did, payload, signature, keyId }) => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "verify_signature");
        emitToolStarted(observer, {
          toolName,
          did: currentDid,
          inputs: { did, key_id: keyId, payload, signature },
        });
        try {
          const targetDid = did && did.trim() ? did.trim() : options.runtimeIdentity.document.id;
          const isValid = await options.agentIdentity.client.verifySignature(targetDid, payload, signature, keyId);
          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: { target_did: targetDid, is_valid: isValid, key_id: keyId },
          });
          return { did: targetDid, keyId, isValid };
        } catch (err) {
          emitToolFailed(observer, {
            toolName,
            did: currentDid,
            error: err,
            inputs: { did, key_id: keyId, payload, signature },
          });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "verify_signature"),
        description: "Verify an Agent-DID signature against a DID document and active verification methods.",
        schema: z.object({
          did: z.string().max(512).optional().describe("Optional DID. Defaults to the current agent DID."),
          payload: z.string().max(MAX_PAYLOAD_BYTES).describe("The exact payload that was signed."),
          signature: z.string().max(256).describe("Hex-encoded Ed25519 signature."),
          keyId: z.string().max(512).optional().describe("Optional verification method id to pin verification."),
        }),
      })
    );
  }

  if (exposure.signPayload) {
    tools.push(
      tool(async ({ payload }) => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "sign_payload");
        emitToolStarted(observer, { toolName, did: currentDid, inputs: { payload } });
        try {
          const signature = await options.agentIdentity.signMessage(payload, options.runtimeIdentity.agentPrivateKey);
          const keyId = getActiveSigningKeyId(options.runtimeIdentity);
          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: { key_id: keyId, signature_generated: true },
          });
          return {
            did: currentDid,
            keyId,
            payload,
            signature,
          };
        } catch (err) {
          emitToolFailed(observer, { toolName, did: currentDid, error: err, inputs: { payload } });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "sign_payload"),
        description: "Sign a payload with the current agent verification key without exposing the private key.",
        schema: z.object({
          payload: z.string().max(MAX_PAYLOAD_BYTES).describe("Payload to sign exactly as-is."),
        }),
      })
    );
  }

  if (exposure.signHttp) {
    tools.push(
      tool(async ({ method, url, body }) => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "sign_http_request");
        emitToolStarted(observer, {
          toolName,
          did: currentDid,
          inputs: { method, url, body },
        });
        try {
          validateHttpTarget(url, options.allowPrivateNetworkTargets === true);
          const keyId = getActiveSigningKeyId(options.runtimeIdentity);
          const headers = await options.agentIdentity.signHttpRequest({
            method,
            url,
            body,
            agentPrivateKey: options.runtimeIdentity.agentPrivateKey,
            agentDid: options.runtimeIdentity.document.id,
            verificationMethodId: keyId,
            // The SDK applies its own target policy too: without this, allowPrivateNetworkTargets would not reach it
            httpSecurity: { allowPrivateTargets: options.allowPrivateNetworkTargets === true },
          });

          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: {
              key_id: keyId,
              method,
              url,
              header_names: Object.keys(headers).sort(),
            },
          });

          return {
            did: currentDid,
            keyId,
            method,
            url,
            headers,
          };
        } catch (err) {
          emitToolFailed(observer, { toolName, did: currentDid, error: err, inputs: { method, url, body } });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "sign_http_request"),
        description: "Create Agent-DID HTTP signature headers for an outbound request.",
        schema: z.object({
          method: z.string().max(16).describe("HTTP method, for example GET or POST."),
          url: z.string().url().max(2048).describe("Target absolute URL."),
          body: z.string().max(MAX_PAYLOAD_BYTES).optional().describe("Optional raw request body."),
        }),
      })
    );
  }

  if (exposure.documentHistory) {
    tools.push(
      tool(async ({ did }) => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "get_document_history");
        emitToolStarted(observer, { toolName, did: currentDid, inputs: { did } });
        try {
          const targetDid = did && did.trim() ? did.trim() : options.runtimeIdentity.document.id;
          const history = await options.agentIdentity.client.getDocumentHistory(targetDid);
          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: { target_did: targetDid, entry_count: history.length },
          });
          return history;
        } catch (err) {
          emitToolFailed(observer, { toolName, did: currentDid, error: err, inputs: { did } });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "get_document_history"),
        description: "Return the revision history registered for an Agent-DID document.",
        schema: z.object({
          did: z.string().max(512).optional().describe("Optional DID. Defaults to the current agent DID."),
        }),
      })
    );
  }

  if (exposure.rotateKeys) {
    tools.push(
      tool(async () => {
        const currentDid = options.runtimeIdentity.document.id;
        const toolName = withPrefix(toolPrefix, "rotate_key");
        emitToolStarted(observer, { toolName, did: currentDid });
        try {
          const rotated = await options.agentIdentity.client.rotateVerificationMethod(options.runtimeIdentity.document.id);
          const updatedIdentity = {
            ...options.runtimeIdentity,
            document: rotated.document,
            agentPrivateKey: rotated.agentPrivateKey,
            verificationMethodId: rotated.verificationMethodId,
          };
          Object.assign(options.runtimeIdentity, updatedIdentity);
          const snapshot = captureIdentitySnapshot(options.runtimeIdentity, observer, "tool:rotate_key");
          emitToolSucceeded(observer, {
            toolName,
            did: currentDid,
            outputs: {
              verification_method_id: rotated.verificationMethodId,
            },
          });

          return {
            did: rotated.document.id,
            verificationMethodId: rotated.verificationMethodId,
            snapshot,
          };
        } catch (err) {
          emitToolFailed(observer, { toolName, did: currentDid, error: err });
          return { error: err instanceof Error ? err.message : String(err) };
        }
      }, {
        name: withPrefix(toolPrefix, "rotate_key"),
        description: "Rotate the active Agent-DID verification method and update the attached runtime identity.",
        schema: z.object({}),
      })
    );
  }

  return tools;
}

function createAgentDidIntegration(options) {
  const observer = options.observer ?? createAgentDidObserver({
    eventHandler: options.observabilityHandler,
    logger: options.logger,
  });
  const integrationOptions = {
    ...options,
    observer,
  };
  const middleware = createAgentDidMiddleware(integrationOptions);
  const tools = createAgentDidTools(integrationOptions);

  return {
    middleware,
    observer,
    tools,
    getCurrentIdentity: () => captureIdentitySnapshot(options.runtimeIdentity, observer, "get_current_identity"),
    getCurrentDocument: () => options.runtimeIdentity.document,
  };
}

function createAgentDidPlugin(options) {
  return createAgentDidIntegration(options);
}

module.exports = {
  buildAgentDidIdentitySnapshot,
  buildAgentDidSystemPrompt,
  createAgentDidIntegration,
  createAgentDidMiddleware,
  createAgentDidPlugin,
  createAgentDidTools,
};