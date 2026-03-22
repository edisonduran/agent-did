# F2-04 - Diseno de Integracion con Microsoft Agent Framework

## Objetivo

Definir una integracion de Agent-DID para Microsoft Agent Framework que reproduzca las capacidades ya implementadas en LangChain: identidad inyectada al runtime, herramientas verificables y firma segura sin exponer la clave privada al modelo.

## Estado actual

- Roadmap item: F2-04
- Estado: integracion funcional Python
- Paquete base: [../integrations/microsoft-agent-framework/README.md](../integrations/microsoft-agent-framework/README.md)
- Referencia funcional existente: [../integrations/langchain/README.md](../integrations/langchain/README.md)
- Superficie publica confirmada: documentacion oficial con foco visible en Python y samples Python/C#
- Decision actual: implementar en Python sobre el SDK Python existente de Agent-DID

## Hallazgos de investigacion

La documentacion oficial consultada confirma que Microsoft Agent Framework ofrece estas piezas relevantes para una integracion Agent-DID:

- `Agent` con `chat_client`, `instructions`, `tools` y `default_options`.
- `agent.run(...)` con herramientas adicionales por invocacion y soporte de streaming.
- `AgentSession` para conversaciones multi-turn stateful.
- `@tool` para registrar herramientas con schemas inferidos.
- `middleware` con contextos como `AgentContext` y `FunctionInvocationContext`.
- `BaseAgent` para agentes custom cuando se necesite encapsular logica determinista o API-backed.
- `WorkflowBuilder`, `executor` y `WorkflowContext` para composicion multi-agent.
- `request_info()` y `send_responses_streaming()` para human-in-the-loop.
- `checkpoint_storage` para pausa, persistencia y resume.
- `setup_observability()` para trazas y telemetria.

## Restriccion actual de lenguaje

Aunque Microsoft Agent Framework se presenta como multi-language SDK, en la documentacion visible consultada no quedo confirmada una ruta JavaScript/TypeScript equivalente a la de LangChain. La evidencia mas clara esta concentrada en:

- documentacion y ejemplos Python,
- repositorio con samples Python,
- referencia a samples dotnet.

Por eso, F2-04 no debe asumirse como un paquete JavaScript por defecto. La decision actual del proyecto es implementarlo en Python, y el siguiente paso ya puede comenzar porque el SDK Python de Agent-DID existe.

## Principios de diseno

1. Paridad funcional con la integracion de LangChain cuando la API del framework lo permita.
2. Seguridad por defecto: ninguna operacion sensible habilitada sin opt-in explicito.
3. Clave privada siempre encapsulada fuera del contexto del modelo.
4. Superficie pequena y estable, con una factory principal y herramientas auxiliares.
5. Compatibilidad con escenarios single-agent y multi-agent.

## Capacidades objetivo

- Exponer DID actual, controlador, capacidades y clave activa.
- Resolver documentos DID y verificar firmas.
- Firmar payloads o solicitudes HTTP cuando el host lo habilite.
- Consultar historial documental.
- Soportar rotacion de claves como operacion administrativa, deshabilitada por defecto.

## Superficies de adaptacion esperadas

- Registro de herramientas o funciones.
- Middleware, filtros o hooks del runtime.
- Enriquecimiento del contexto de sesion o conversation state.
- Intercepcion opcional de mensajes salientes para firma/verificacion.
- Integracion con `WorkflowBuilder` para escenarios multi-agent.
- Integracion con observabilidad y checkpointing para trazabilidad empresarial.

## API preliminar

```js
const integration = createAgentDidMicrosoftAgentFrameworkIntegration({
  agentIdentity,
  runtimeIdentity,
  expose: {
    signHttp: true,
    verifySignatures: true,
    signPayload: false,
    rotateKeys: false,
    documentHistory: true,
  },
});
```

## Entregables esperados

1. Factory principal del adaptador.
2. Mapeo de herramientas Agent-DID al mecanismo nativo del framework.
3. Inyeccion de identidad al contexto del agente.
4. Ejemplo runnable equivalente al de LangChain.
5. Suite de pruebas automatizadas.
6. Uso del SDK Python de Agent-DID como dependencia base.

## Riesgos tecnicos

- Cambios en la API estable del framework.
- Diferencias entre flujos single-agent y orchestration multi-agent.
- Ambiguedad entre herramientas del runtime y capacidades del modelo.
- Necesidad de versionar el adaptador si el framework cambia sus hooks.


## Recomendacion actual

La siguiente iteracion de F2-04 puede centrarse en endurecimiento y validacion de runtime real, no en scaffold adicional. El adaptador Python para tools, middleware ligero, contexto y observabilidad ya existe; el siguiente trabajo natural es ampliar recipes operativas o smoke tests contra el host runtime real cuando esa dependencia se adopte de forma estable.

## Criterio de cierre

F2-04 se considerara implementado cuando exista un paquete funcional bajo `integrations/microsoft-agent-framework/`, con ejemplo ejecutable, pruebas automatizadas y documentacion de uso equivalente a la ya disponible en LangChain.

## Artefactos de control

- Checklist de implementacion: `docs/F2-04-Microsoft-Agent-Framework-Implementation-Checklist.md`
- Checklist de review: `docs/F2-04-Microsoft-Agent-Framework-Integration-Review-Checklist.md`