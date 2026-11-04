const { AgentIdentity, LocalKeySigner } = require("@agentdid/sdk");
const {
  composeEventHandlers,
  createAgentDidIntegration,
  createJsonLoggerEventHandler,
} = require("../src");

async function main() {
  const privateKey = process.env.CREATOR_PRIVATE_KEY;

  if (!privateKey) {
    throw new Error("Missing CREATOR_PRIVATE_KEY environment variable");
  }

  const signer = new LocalKeySigner(privateKey);
  const identity = new AgentIdentity({ controllerSigner: signer, network: "polygon" });
  const runtimeIdentity = await identity.create({
    name: "observable_assistant",
    description: "Agent with structured Agent-DID tool telemetry",
    coreModel: "gpt-4.1-mini",
    systemPrompt: "Eres un agente seguro y trazable.",
    capabilities: ["http:sign", "audit:trace"],
  });

  const localEvents = [];
  const integration = createAgentDidIntegration({
    agentIdentity: identity,
    runtimeIdentity,
    expose: {
      signPayload: true,
      signHttp: true,
      verifySignatures: true,
    },
    observabilityHandler: composeEventHandlers(
      (event) => localEvents.push(event),
      createJsonLoggerEventHandler(console, {
        extraFields: { example: "observability" },
      })
    ),
  });

  const signPayloadTool = integration.tools.find((tool) => tool.name === "agent_did_sign_payload");
  const signHttpTool = integration.tools.find((tool) => tool.name === "agent_did_sign_http_request");

  const payloadResult = await signPayloadTool.invoke({ payload: "approve:ticket:123" });
  const httpResult = await signHttpTool.invoke({
    method: "POST",
    url: "https://api.example.com/orders",
    body: JSON.stringify({ orderId: 42 }),
  });

  console.log({
    payloadDid: payloadResult.did,
    httpHeaderNames: Object.keys(httpResult.headers || {}),
    eventTypes: localEvents.map((event) => event.eventType),
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});