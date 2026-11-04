const { createAgent } = require("langchain");
const { AgentIdentity, LocalKeySigner } = require("@agentdid/sdk");
const {
  composeEventHandlers,
  createAgentDidIntegration,
  createJsonLoggerEventHandler,
} = require("../src");

async function main() {
  if (process.env.RUN_LANGCHAIN_PRODUCTION_EXAMPLE !== "1") {
    console.log("Set RUN_LANGCHAIN_PRODUCTION_EXAMPLE=1 to execute this example.");
    return;
  }

  const privateKey = process.env.CREATOR_PRIVATE_KEY;
  if (!privateKey) {
    console.log("Set CREATOR_PRIVATE_KEY before running this example.");
    return;
  }

  const model = process.env.LANGCHAIN_MODEL ?? "openai:gpt-4.1-mini";
  const signer = new LocalKeySigner(privateKey);
  const identity = new AgentIdentity({ controllerSigner: signer, network: "polygon" });
  const runtimeIdentity = await identity.create({
    name: "production_assistant",
    description: "Production-style Agent-DID LangChain JS recipe",
    coreModel: "gpt-4.1-mini",
    systemPrompt: "Eres un agente empresarial seguro.",
    capabilities: ["research:web", "http:sign", "audit:trace"],
  });

  const localEvents = [];
  const integration = createAgentDidIntegration({
    agentIdentity: identity,
    runtimeIdentity,
    expose: {
      signHttp: true,
      verifySignatures: true,
      documentHistory: true,
    },
    observabilityHandler: composeEventHandlers(
      (event) => localEvents.push(event),
      createJsonLoggerEventHandler(console, {
        extraFields: { service: "agent-gateway", environment: process.env.NODE_ENV ?? "dev" },
      })
    ),
  });

  const agent = createAgent({
    name: "production_assistant",
    model,
    systemPrompt: "Usa herramientas cuando anadan trazabilidad verificable.",
    tools: integration.tools,
    middleware: [integration.middleware],
  });

  const result = await agent.invoke({
    messages: [
      {
        role: "user",
        content: "Muestrame tu DID actual y prepara una firma HTTP POST para https://api.example.com/orders.",
      },
    ],
  });

  console.log(result.messages.at(-1)?.content);
  console.log(`Captured ${localEvents.length} sanitized observability events.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});