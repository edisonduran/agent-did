const { ethers } = require("ethers");
const { createAgent } = require("langchain");
const { fakeModel } = require("@langchain/core/testing");
const { AgentIdentity, InMemoryAgentRegistry } = require("@agentdid/sdk");
const { createAgentDidIntegration } = require("../src");

const ACTIVE_DID = "did:wba:agents.example:profiles:weather-bot";
const PARTNER_DID = "did:wba:agents.example:partners:dispatch-router";
const ACTIVE_DOCUMENT_URL = "https://agents.example/profiles/weather-bot/did.json";
const PARTNER_DOCUMENT_URL = "https://agents.example/partners/dispatch-router/did.json";
const SIGNED_REQUEST_URL = "https://api.example.com/tasks";
const SIGNED_REQUEST_BODY = JSON.stringify({ taskId: 42, route: "storm-front" });

function buildRuntimeDidWbaDocument(runtimeIdentity) {
  const verificationMethod = runtimeIdentity.document.verificationMethod[0];

  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
    id: ACTIVE_DID,
    controller: "did:web:agents.example",
    created: "2026-03-22T00:00:00Z",
    updated: "2026-03-22T00:00:00Z",
    agentMetadata: {
      name: "WeatherBot",
      description: "Integrated did:wba runtime identity for LangChain JS tests",
      version: "1.0.0",
      coreModelHash: "hash://sha256/weatherbot-model",
      systemPromptHash: "hash://sha256/weatherbot-prompt",
      capabilities: ["weather:forecast", "http:sign", "partner:resolve"],
    },
    verificationMethod: [
      {
        ...verificationMethod,
        id: `${ACTIVE_DID}#key-1`,
        controller: "did:web:agents.example",
      },
    ],
    authentication: [`${ACTIVE_DID}#key-1`],
    assertionMethod: [`${ACTIVE_DID}#key-1`],
  };
}

function buildPartnerDocument() {
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
    id: PARTNER_DID,
    controller: "did:web:agents.example",
    created: "2026-03-22T00:00:00Z",
    updated: "2026-03-22T00:00:00Z",
    agentMetadata: {
      name: "DispatchRouter",
      description: "Remote did:wba partner resolved over HTTPS",
      version: "1.0.0",
      coreModelHash: "hash://sha256/dispatchrouter-model",
      systemPromptHash: "hash://sha256/dispatchrouter-prompt",
      capabilities: ["dispatch:receive", "dispatch:ack"],
    },
    verificationMethod: [
      {
        id: `${PARTNER_DID}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: "did:web:agents.example",
        publicKeyMultibase: "z6Mkdispatchrouterkey",
      },
    ],
    authentication: [`${PARTNER_DID}#key-1`],
    assertionMethod: [`${PARTNER_DID}#key-1`],
  };
}

describe("@agentdid/langchain did:wba integrated demo", () => {
  it("supports an active did:wba runtime, partner resolution, and verifiable HTTP signing", async () => {
    const signer = ethers.Wallet.createRandom();
    const registry = new InMemoryAgentRegistry();
    const identity = new AgentIdentity({ signer, network: "polygon" });
    const createdIdentity = await identity.create({
      name: "weather_demo_bot",
      description: "Base identity used to derive a did:wba runtime",
      coreModel: "gpt-4.1-mini",
      systemPrompt: "Resolve trusted did:wba partners before signing outbound HTTP requests.",
      capabilities: ["weather:forecast", "http:sign"],
    });

    const runtimeIdentity = {
      ...createdIdentity,
      document: buildRuntimeDidWbaDocument(createdIdentity),
    };
    const partnerDocument = buildPartnerDocument();
    const documentsByUrl = new Map([
      [ACTIVE_DOCUMENT_URL, runtimeIdentity.document],
      [PARTNER_DOCUMENT_URL, partnerDocument],
    ]);
    const resolutionEvents = [];

    AgentIdentity.setRegistry(registry);
    AgentIdentity.useProductionResolverFromHttp({
      registry,
      fetchFn: async (url) => {
        const document = documentsByUrl.get(url);
        if (!document) {
          return {
            ok: false,
            status: 404,
            json: async () => ({}),
          };
        }

        return {
          ok: true,
          status: 200,
          json: async () => document,
        };
      },
      onResolutionEvent: (event) => {
        resolutionEvents.push([event.did, event.stage]);
      },
    });

    const integration = createAgentDidIntegration({
      agentIdentity: identity,
      runtimeIdentity,
      expose: {
        signHttp: true,
      },
    });
    const toolsByName = new Map(integration.tools.map((currentTool) => [currentTool.name, currentTool]));

    const model = fakeModel()
      .respondWithTools([
        { name: "agent_did_get_current_identity", args: {} },
        { name: "agent_did_resolve_did", args: { did: PARTNER_DID } },
        {
          name: "agent_did_sign_http_request",
          args: {
            method: "POST",
            url: SIGNED_REQUEST_URL,
            body: SIGNED_REQUEST_BODY,
          },
        },
      ]);

    const agent = createAgent({
      model,
      tools: integration.tools,
      middleware: [integration.middleware],
      systemPrompt: "Use Agent-DID tools before asserting identity or trust.",
    });

    const agentResult = await agent.invoke({
      messages: [
        {
          role: "user",
          content:
            "Identify your current DID, resolve your did:wba partner and prepare an HTTP signature for POST https://api.example.com/tasks.",
        },
      ],
    });

    const currentIdentity = await toolsByName.get("agent_did_get_current_identity").invoke({});
    const resolvedPartner = await toolsByName.get("agent_did_resolve_did").invoke({ did: PARTNER_DID });
    const signedRequest = await toolsByName.get("agent_did_sign_http_request").invoke({
      method: "POST",
      url: SIGNED_REQUEST_URL,
      body: SIGNED_REQUEST_BODY,
    });
    const verified = await AgentIdentity.verifyHttpRequestSignature({
      method: "POST",
      url: SIGNED_REQUEST_URL,
      body: SIGNED_REQUEST_BODY,
      headers: signedRequest.headers,
    });

    expect(agentResult.messages.at(-1)?.content).toContain(ACTIVE_DID);
    expect(agentResult.messages.at(-1)?.content).toContain(SIGNED_REQUEST_URL);
    expect(currentIdentity.did).toBe(ACTIVE_DID);
    expect(resolvedPartner.id).toBe(PARTNER_DID);
    expect(resolvedPartner.agentMetadata.name).toBe("DispatchRouter");
    expect(signedRequest.did).toBe(ACTIVE_DID);
    expect(verified).toBe(true);
    expect(resolutionEvents).toContainEqual([PARTNER_DID, "resolved"]);
    expect(resolutionEvents).toContainEqual([ACTIVE_DID, "resolved"]);
  });
});
