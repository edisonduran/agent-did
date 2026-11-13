const { AgentDidClient, AgentIdentity, LocalKeySigner } = require("@agentdid/sdk");
const { createAgentDidIntegration } = require("../src");

// Stands for a KMS or HSM key: the private key never leaves it.
class ExternalSigner {
  constructor() {
    [this.inner] = LocalKeySigner.generate();
  }

  sign(payload) {
    return this.inner.sign(payload);
  }

  getPublicKey() {
    return this.inner.getPublicKey();
  }
}

describe("@agentdid/langchain with an external signer", () => {
  it("signs payloads and HTTP requests through the signer and refuses tool rotation", async () => {
    const client = new AgentDidClient();
    const agentIdentity = new AgentIdentity({ controllerSigner: LocalKeySigner.generate()[0], client });
    const runtimeIdentity = await agentIdentity.create({
      name: "KmsBot",
      coreModel: "gpt-4.1-mini",
      systemPrompt: "kms test",
      signer: new ExternalSigner(),
    });
    expect(runtimeIdentity.agentPrivateKey).toBe("");
    expect(JSON.stringify(runtimeIdentity)).not.toContain("signer");

    const integration = createAgentDidIntegration({
      agentIdentity,
      runtimeIdentity,
      expose: { signPayload: true, signHttp: true, rotateKeys: true },
    });
    const toolsByName = new Map(integration.tools.map((currentTool) => [currentTool.name, currentTool]));

    const signed = await toolsByName.get("agent_did_sign_payload").invoke({ payload: "approve:1" });
    await expect(client.verifySignature(runtimeIdentity.document.id, "approve:1", signed.signature)).resolves.toBe(true);

    const request = { method: "POST", url: "https://api.example.com/v1/tasks", body: "{}" };
    const signedHttp = await toolsByName.get("agent_did_sign_http_request").invoke(request);
    await expect(client.verifyHttpRequestSignature({ ...request, headers: signedHttp.headers })).resolves.toBe(true);

    const rotated = await toolsByName.get("agent_did_rotate_key").invoke({});
    expect(JSON.stringify(rotated)).toContain("external signer");
  });
});
