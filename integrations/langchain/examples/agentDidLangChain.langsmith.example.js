const { AgentIdentity, LocalKeySigner } = require("@agentdid/sdk");
const {
  createAgentDidIntegration,
  createLangSmithEventHandler,
  createLangSmithRunTree,
} = require("../src");

async function main() {
  const privateKey = process.env.CREATOR_PRIVATE_KEY;

  if (!privateKey) {
    throw new Error("Missing CREATOR_PRIVATE_KEY environment variable");
  }

  const signer = new LocalKeySigner(privateKey);
  const identity = new AgentIdentity({ controllerSigner: signer, network: "polygon" });
  const runtimeIdentity = await identity.create({
    name: "langsmith_demo_bot",
    description: "LangSmith local tracing demo for Agent-DID tools",
    coreModel: "gpt-4.1-mini",
    systemPrompt: "Trace every tool interaction as a local RunTree.",
    capabilities: ["audit:events", "identity:trace"],
  });

  const rootRun = createLangSmithRunTree({
    name: "agent_did_langchain_demo",
    inputs: { scenario: "langsmith-local-demo" },
    tags: ["example", "agent-did"],
  });

  const integration = createAgentDidIntegration({
    agentIdentity: identity,
    runtimeIdentity,
    expose: { signPayload: true, signHttp: true },
    observabilityHandler: createLangSmithEventHandler(rootRun, {
      extraFields: { component: "example", adapter: "langsmith" },
      tags: ["local-demo"],
    }),
  });

  const toolsByName = Object.fromEntries(integration.tools.map((tool) => [tool.name, tool]));
  await toolsByName.agent_did_get_current_identity.invoke({});
  await toolsByName.agent_did_sign_payload.invoke({ payload: "langsmith-demo-payload" });
  await toolsByName.agent_did_sign_http_request.invoke({
    method: "POST",
    url: "https://api.example.com/v1/tasks?debug=true",
    body: JSON.stringify({ taskId: 7, secret: "hidden" }),
  });

  await rootRun.end({ child_run_count: rootRun.child_runs.length });

  console.log(
    JSON.stringify(
      {
        child_run_count: rootRun.child_runs.length,
        trace: rootRun.toJSON(),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});