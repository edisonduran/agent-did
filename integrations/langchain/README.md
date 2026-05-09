# @agentdid/langchain

Integracion funcional de Agent-DID para LangChain JS 1.x.

Esta variante es la referencia original en JavaScript/TypeScript y ahora mantiene parity operativa con la integracion Python en superficies clave: middleware/contexto, tools opt-in, seguridad por defecto, observabilidad callback/logger/LangSmith y ejemplos de operacion.

La matriz de parity entre ambas integraciones vive en `../../docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`.

## Compatibilidad objetivo

- `langchain` `^1.2.35`
- `@langchain/core` `^1.1.34`
- `@agentdid/sdk` `1.0.0-rc.1`
- Node.js 20+

## Estado

- Estado actual: `functional-mvp`
- Lenguaje objetivo: TypeScript / JavaScript
- Rol actual: referencia JS de la integracion LangChain de Agent-DID
- Parity objetivo: alineada con Python en README, ejemplos y observabilidad base

## Instalacion

```bash
npm install @agentdid/sdk@next langchain @langchain/core zod
```

Para habilitar el adaptador opcional de LangSmith:

```bash
npm install langsmith
```

Si publicas este paquete por separado:

```bash
npm install @agentdid/langchain@next
```

## Uso rapido

```ts
import { ethers } from "ethers";
import { createAgent } from "langchain";
import { AgentIdentity } from "@agentdid/sdk";
import { createAgentDidIntegration } from "@agentdid/langchain";

const signer = new ethers.Wallet(process.env.CREATOR_PRIVATE_KEY!);
const identity = new AgentIdentity({ signer });

const runtimeIdentity = await identity.create({
  name: "research_assistant",
  description: "Agente de investigacion con identidad verificable",
  coreModel: "gpt-4.1-mini",
  systemPrompt: "Eres un agente de investigacion preciso y trazable.",
  capabilities: ["research:web", "report:write"]
});

const integration = createAgentDidIntegration({
  agentIdentity: identity,
  runtimeIdentity,
  expose: {
    signHttp: true,
    verifySignatures: true,
    signPayload: false,
    rotateKeys: false,
    documentHistory: true
  }
});

const agent = createAgent({
  name: "research_assistant",
  model: "openai:gpt-4.1-mini",
  systemPrompt: "Responde con precision y usa herramientas cuando haga falta.",
  tools: integration.tools,
  middleware: [integration.middleware]
});

const result = await agent.invoke({
  messages: [
    {
      role: "user",
      content: "Muestrame tu DID actual y firma una solicitud POST a https://api.example.com/tasks"
    }
  ]
});

console.log(result.messages.at(-1)?.content);
```

En este flujo el SDK usa el path web-native canonico y bootstrappea el controller local para el ejemplo. La publicacion hospedada del `did:webvh` y su historia verificable es el siguiente paso de despliegue, no un requisito para probar la integracion local.

## Que agrega la integracion

- Middleware que inyecta en el sistema el DID actual, controlador, capacidades y metodo de autenticacion activo.
- Herramientas de consulta para identidad actual, resolucion DID y verificacion de firmas.
- Herramientas opcionales para firma de payloads, firma HTTP, historial documental y rotacion de clave.
- Observabilidad vendor-neutral via callback, logger estructurado y adaptador opcional de LangSmith con redaccion por defecto.

## Compatibilidad de API

- `createAgentDidIntegration(...)`: nombre recomendado.
- `createAgentDidPlugin(...)`: alias mantenido por compatibilidad retroactiva.

## Seguridad por defecto

- `signPayload` y `rotateKeys` vienen deshabilitados por defecto.
- `signHttp` tambien es opt-in y puede habilitarse para que el agente firme solicitudes salientes sin exponer la clave privada al modelo.
- Los destinos HTTP privados, loopback o con credenciales embebidas se rechazan por defecto.
- La clave privada nunca se inserta en mensajes, contexto ni estado del agente.

## Observabilidad

La factory publica acepta instrumentacion opcional sin acoplar el paquete a un backend especifico:

```js
const {
  composeEventHandlers,
  createAgentDidIntegration,
  createJsonLoggerEventHandler,
} = require("@agentdid/langchain");

const events = [];

const integration = createAgentDidIntegration({
  agentIdentity: identity,
  runtimeIdentity,
  expose: {
    signHttp: true,
    signPayload: true,
  },
  observabilityHandler: composeEventHandlers(
    (event) => events.push(event),
    createJsonLoggerEventHandler(console, {
      extraFields: { service: "agent-gateway" },
    })
  ),
});
```

Eventos emitidos:

- `agent_did.identity_snapshot.refreshed`
- `agent_did.tool.started`
- `agent_did.tool.succeeded`
- `agent_did.tool.failed`

Redaccion por defecto:

- `payload`, `body`, `signature` y `agent_private_key` se reemplazan por metadatos de longitud.
- `Authorization`, `Signature`, `Signature-Input`, `Cookie`, `Set-Cookie` y `X-API-Key` se redactan en headers.
- Las URLs se serializan sin query string, fragmento ni credenciales embebidas.

Helpers publicos disponibles:

- `composeEventHandlers(...)`
- `createJsonLoggerEventHandler(...)`
- `createLangSmithRunTree(...)`
- `createLangSmithEventHandler(...)`
- `serializeObservabilityEvent(...)`
- `sanitizeObservabilityAttributes(...)`

Ejemplo de LangSmith local sin cambiar la factory principal:

```js
const {
  createAgentDidIntegration,
  createLangSmithEventHandler,
  createLangSmithRunTree,
} = require("@agentdid/langchain");

const rootRun = createLangSmithRunTree({
  name: "agent_did_demo",
  inputs: { scenario: "local" },
  tags: ["agent-did", "demo"],
});

const integration = createAgentDidIntegration({
  agentIdentity: identity,
  runtimeIdentity,
  expose: { signHttp: true, signPayload: true },
  observabilityHandler: createLangSmithEventHandler(rootRun, {
    extraFields: { sink: "langsmith" },
    tags: ["local-demo"],
  }),
});
```

## Archivos relevantes

- `src/agentDidLangChain.js`: middleware, herramientas y helpers principales.
- `src/observability.js`: callbacks, logging JSON y saneamiento de eventos.
- `examples/agentDidLangChain.example.js`: ejemplo con `createAgent()` de LangChain 1.x.
- `examples/agentDidLangChain.didWbaDemo.example.js`: demo integrado con runtime `did:wba`, partner remoto `did:wba` y firma HTTP verificable.
- `examples/agentDidLangChain.observability.example.js`: ejemplo de callback + JSON logging saneado.
- `examples/agentDidLangChain.langsmith.example.js`: tracing local con `RunTree` de LangSmith y child runs saneados.
- `examples/agentDidLangChain.productionRecipe.example.js`: receta con guardas de entorno para un flujo mas cercano a produccion.
- `tests/agentDidLangChain.test.js`: pruebas de la integracion.
- `tests/agentDidLangChain.didWbaDemo.test.js`: prueba del flujo integrado `did:wba` con `createAgent()` y verificacion HTTP.
- `tests/agentDidLangChain.observability.test.js`: pruebas de observabilidad saneada.

## Demo integrado `did:wba`

Para ejecutar el demo integrado local de LangChain JS sin depender de credenciales externas:

```bash
cd integrations/langchain
node examples/agentDidLangChain.didWbaDemo.example.js
```

Este demo prueba en un solo flujo:

- identidad activa `did:wba`
- resolucion de una contraparte remota `did:wba`
- `createAgent(...)` con fake model reproducible
- firma HTTP Agent-DID verificable end-to-end

La cobertura automatizada equivalente vive en:

- `tests/agentDidLangChain.didWbaDemo.test.js`