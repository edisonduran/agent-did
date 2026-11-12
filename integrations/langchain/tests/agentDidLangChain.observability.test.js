const { AgentIdentity, LocalKeySigner } = require("@agentdid/sdk");
const {
  composeEventHandlers,
  createAgentDidIntegration,
  createJsonLoggerEventHandler,
  createLangSmithEventHandler,
  createLangSmithRunTree,
  serializeObservabilityEvent,
} = require("../src");

describe("@agentdid/langchain observability", () => {
  const signer = LocalKeySigner.generate()[0];
  const agentIdentity = new AgentIdentity({ controllerSigner: signer });

  it("emits sanitized tool events through callbacks", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "ObservableBot",
      coreModel: "test",
      systemPrompt: "test",
      capabilities: ["http:sign"],
    });
    const events = [];

    const integration = createAgentDidIntegration({
      agentIdentity,
      runtimeIdentity,
      expose: { signPayload: true },
      observabilityHandler: composeEventHandlers((event) => events.push(event)),
    });

    const signPayload = integration.tools.find((tool) => tool.name === "agent_did_sign_payload");
    await signPayload.invoke({ payload: "approve:ticket:123" });

    expect(events.some((event) => event.eventType === "agent_did.tool.started")).toBe(true);
    expect(events.some((event) => event.eventType === "agent_did.tool.succeeded")).toBe(true);

    const startedEvent = events.find((event) => event.eventType === "agent_did.tool.started");
    expect(startedEvent.attributes.inputs.payload).toEqual({ redacted: true, length: 18 });
  });

  it("serializes sanitized events for JSON logging", () => {
    const logger = { info: jest.fn() };
    const handler = createJsonLoggerEventHandler(logger, {
      extraFields: { service: "agent-gateway" },
    });
    const event = {
      eventType: "agent_did.tool.failed",
      level: "error",
      attributes: {
        url: "https://user:secret@example.com/path?token=1#frag",
        headers: { Authorization: "Bearer top-secret", Accept: "application/json" },
        payload: "super-secret",
      },
    };

    handler(event);

    expect(logger.info).not.toHaveBeenCalled();

    const errorLogger = { error: jest.fn() };
    createJsonLoggerEventHandler(errorLogger)(event);
    expect(errorLogger.error).toHaveBeenCalledTimes(1);

    const record = serializeObservabilityEvent(event, { includeTimestamp: false });
    expect(record.attributes.url).toBe("https://example.com/path");
    expect(record.attributes.headers.Authorization).toBe("<redacted>");
    expect(record.attributes.payload).toEqual({ redacted: true, length: 12 });
  });

  it("maps tool lifecycle events into LangSmith child runs", () => {
    const rootRun = createLangSmithRunTree({
      name: "agent_did_root",
      inputs: { url: "https://api.example.com/tasks?token=secret" },
      tags: ["tests"],
    });
    const handler = createLangSmithEventHandler(rootRun, {
      includeTimestamp: false,
      extraFields: { service: "tests", payload: "should-redact" },
      tags: ["langsmith"],
    });

    handler({
      eventType: "agent_did.tool.started",
      level: "info",
      attributes: {
        tool_name: "agent_did_sign_payload",
        did: "did:agent:test:123",
        inputs: { payload: "very-secret-payload" },
      },
    });
    handler({
      eventType: "agent_did.tool.succeeded",
      level: "info",
      attributes: {
        tool_name: "agent_did_sign_payload",
        did: "did:agent:test:123",
        outputs: { signature_generated: true, key_id: "key-1" },
      },
    });

    expect(rootRun.inputs.url).toBe("https://api.example.com/tasks");
    expect(rootRun.child_runs).toHaveLength(1);

    const childRun = rootRun.child_runs[0];
    expect(childRun.name).toBe("agent_did_sign_payload");
    expect(childRun.run_type).toBe("tool");
    expect(childRun.inputs.inputs.payload).toEqual({ redacted: true, length: 19 });
    expect(childRun.outputs.attributes.outputs.signature_generated).toBe(true);
    expect(childRun.extra.source).toBe("agent_did_langchain");
  });

  it("can fan out to JSON logging and LangSmith simultaneously", () => {
    const logger = { info: jest.fn() };
    const rootRun = createLangSmithRunTree({ name: "agent_did_composed_root" });
    const capturedEvents = [];
    const handler = composeEventHandlers(
      (event) => capturedEvents.push(event),
      createJsonLoggerEventHandler(logger, { includeTimestamp: false, extraFields: { sink: "json" } }),
      createLangSmithEventHandler(rootRun, { includeTimestamp: false, extraFields: { sink: "langsmith" } })
    );

    handler({
      eventType: "agent_did.tool.started",
      level: "info",
      attributes: {
        tool_name: "agent_did_sign_http_request",
        did: "did:agent:test:compose",
        inputs: { url: "https://api.example.com/compose?debug=true", body: "secret-payload" },
      },
    });
    handler({
      eventType: "agent_did.tool.succeeded",
      level: "info",
      attributes: {
        tool_name: "agent_did_sign_http_request",
        did: "did:agent:test:compose",
        outputs: { header_names: ["Signature", "Signature-Input"] },
      },
    });

    const record = JSON.parse(logger.info.mock.calls[0][0]);

    expect(capturedEvents).toHaveLength(2);
    expect(record.sink).toBe("json");
    expect(record.attributes.inputs.url).toBe("https://api.example.com/compose");
    expect(record.attributes.inputs.body).toEqual({ redacted: true, length: 14 });
    expect(rootRun.child_runs).toHaveLength(1);
    expect(rootRun.child_runs[0].outputs.attributes.outputs.header_names).toEqual([
      "Signature",
      "Signature-Input",
    ]);
  });
});