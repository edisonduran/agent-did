const { AgentIdentity, LocalKeySigner } = require("@agentdid/sdk");
const {
  buildAgentDidSystemPrompt,
  createAgentDidIntegration,
} = require("../src");

describe("@agentdid/langchain", () => {
  const signer = LocalKeySigner.generate()[0];
  const agentIdentity = new AgentIdentity({ controllerSigner: signer });

  it("builds a system prompt section with the active Agent-DID context", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "PromptBot",
      description: "Testing middleware prompt composition",
      coreModel: "gpt-4.1-mini",
      systemPrompt: "Prompt test",
      capabilities: ["research:web", "report:write"],
    });

    const integration = createAgentDidIntegration({
      agentIdentity,
      runtimeIdentity,
    });

    const prompt = buildAgentDidSystemPrompt(integration.getCurrentIdentity(), "Never sign arbitrary payloads.");

    expect(prompt).toContain("Agent-DID identity context:");
    expect(prompt).toContain(runtimeIdentity.document.id);
    expect(prompt).toContain("research:web, report:write");
    expect(prompt).toContain("Never sign arbitrary payloads.");
  });

  it("creates tools that expose current identity, verification, HTTP signing, history and key rotation", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "ToolBot",
      description: "Testing LangChain tools",
      coreModel: "gpt-4.1-mini",
      systemPrompt: "Tool test",
      capabilities: ["http:sign"],
    });

    const integration = createAgentDidIntegration({
      agentIdentity,
      runtimeIdentity,
      expose: {
        signPayload: true,
        signHttp: true,
        verifySignatures: true,
        documentHistory: true,
        rotateKeys: true,
      },
    });

    const toolsByName = new Map(integration.tools.map((currentTool) => [currentTool.name, currentTool]));

    const identityResult = await toolsByName.get("agent_did_get_current_identity").invoke({});
    expect(identityResult.did).toBe(runtimeIdentity.document.id);

    const payload = "approve:ticket:123";
    const signatureResult = await toolsByName.get("agent_did_sign_payload").invoke({ payload });
    expect(signatureResult.did).toBe(runtimeIdentity.document.id);

    const verificationResult = await toolsByName.get("agent_did_verify_signature").invoke({
      payload,
      signature: signatureResult.signature,
    });
    expect(verificationResult.isValid).toBe(true);

    const signedHttp = await toolsByName.get("agent_did_sign_http_request").invoke({
      method: "POST",
      url: "https://api.example.com/tasks",
      body: JSON.stringify({ taskId: 7 }),
    });

    const isHttpValid = await AgentIdentity.verifyHttpRequestSignature({
      method: "POST",
      url: "https://api.example.com/tasks",
      body: JSON.stringify({ taskId: 7 }),
      headers: signedHttp.headers,
    });
    expect(isHttpValid).toBe(true);

    const history = await toolsByName.get("agent_did_get_document_history").invoke({});
    expect(Array.isArray(history)).toBe(true);
    expect(history.length).toBeGreaterThan(0);

    const initialKeyId = integration.getCurrentIdentity().authenticationKeyId;
    const rotated = await toolsByName.get("agent_did_rotate_key").invoke({});
    expect(rotated.verificationMethodId).not.toBe(initialKeyId);
    expect(integration.getCurrentIdentity().authenticationKeyId).toBe(rotated.verificationMethodId);
  });

  it("keeps HTTP signing opt-in by default", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "DefaultExposureBot",
      description: "Checks secure defaults",
      coreModel: "gpt-4.1-mini",
      systemPrompt: "Default exposure test",
    });

    const integration = createAgentDidIntegration({
      agentIdentity,
      runtimeIdentity,
    });

    expect(integration.tools.some((currentTool) => currentTool.name === "agent_did_sign_http_request")).toBe(false);
  });
});