const { AgentIdentity, InMemoryAgentRegistry, LocalKeySigner } = require("@agentdid/sdk");
const { createAgentDidTools } = require("../src");

describe("@agentdid/langchain security edge cases", () => {
  const signer = LocalKeySigner.generate()[0];
  const agentIdentity = new AgentIdentity({ controllerSigner: signer });

  beforeAll(() => {
    AgentIdentity.setRegistry(new InMemoryAgentRegistry());
  });

  it("sign_http_request rejects non-http/https URLs", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "SSRFTestBot",
      coreModel: "test",
      systemPrompt: "test",
    });

    const tools = createAgentDidTools({
      agentIdentity,
      runtimeIdentity,
      expose: { signHttp: true },
    });

    const signHttp = tools.find((t) => t.name.includes("sign_http_request"));
    expect(signHttp).toBeDefined();

    const result = await signHttp.invoke({
      method: "GET",
      url: "file:///etc/passwd",
    });

    expect(result.error).toBeDefined();
    expect(result.error).toContain("http");
  });

  it("sign_http_request rejects localhost targets by default", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "LocalhostRejectBot",
      coreModel: "test",
      systemPrompt: "test",
    });

    const tools = createAgentDidTools({
      agentIdentity,
      runtimeIdentity,
      expose: { signHttp: true },
    });

    const signHttp = tools.find((t) => t.name.includes("sign_http_request"));
    const result = await signHttp.invoke({
      method: "POST",
      url: "http://localhost:8080/tasks",
      body: "{}",
    });

    expect(result.error).toContain("Private or loopback");
  });

  it("sign_http_request rejects IPv6 loopback and private literals by default", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "Ipv6RejectBot",
      coreModel: "test",
      systemPrompt: "test",
    });
    const tools = createAgentDidTools({ agentIdentity, runtimeIdentity, expose: { signHttp: true } });
    const signHttp = tools.find((t) => t.name.includes("sign_http_request"));

    for (const url of ["http://[::1]:8080/tasks", "http://[fd00::1]/tasks", "http://[fe80::1]/tasks"]) {
      const result = await signHttp.invoke({ method: "POST", url, body: "{}" });
      expect(result.error).toContain("Private or loopback");
    }
  });

  it("sign_http_request signs a private target when allowPrivateNetworkTargets is set (the SDK policy honors it too)", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "PrivateAllowedBot",
      coreModel: "test",
      systemPrompt: "test",
    });
    const tools = createAgentDidTools({
      agentIdentity,
      runtimeIdentity,
      expose: { signHttp: true },
      allowPrivateNetworkTargets: true,
    });
    const signHttp = tools.find((t) => t.name.includes("sign_http_request"));

    const result = await signHttp.invoke({ method: "POST", url: "http://127.0.0.1:8080/tasks", body: "{}" });

    expect(result.error).toBeUndefined();
    expect(result.headers.Signature).toBeDefined();
  });

  it("sign_http_request rejects embedded credentials", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "CredentialRejectBot",
      coreModel: "test",
      systemPrompt: "test",
    });

    const tools = createAgentDidTools({
      agentIdentity,
      runtimeIdentity,
      expose: { signHttp: true },
    });

    const signHttp = tools.find((t) => t.name.includes("sign_http_request"));
    const result = await signHttp.invoke({
      method: "GET",
      url: "https://user:secret@example.com/data",
    });

    expect(result.error).toContain("embedded credentials");
  });

  it("tools return structured error on SDK failure instead of throwing", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "ErrorTestBot",
      coreModel: "test",
      systemPrompt: "test",
    });

    const tools = createAgentDidTools({
      agentIdentity,
      runtimeIdentity,
      expose: { resolveDid: true },
    });

    const resolveTool = tools.find((t) => t.name.includes("resolve_did"));
    const result = await resolveTool.invoke({ did: "did:agent:polygon:0xnonexistent" });

    expect(result.error).toBeDefined();
  });

  it("verify_signature handles malformed inputs gracefully", async () => {
    const runtimeIdentity = await agentIdentity.create({
      name: "MalformedInputBot",
      coreModel: "test",
      systemPrompt: "test",
    });

    const tools = createAgentDidTools({
      agentIdentity,
      runtimeIdentity,
      expose: { verifySignatures: true },
    });

    const verifyTool = tools.find((t) => t.name.includes("verify_signature"));

    const result = await verifyTool.invoke({
      payload: "test",
      signature: "not-a-valid-hex-signature",
    });

    // Should either return error or isValid false, not throw
    expect(result.error || result.isValid === false).toBeTruthy();
  });
});
