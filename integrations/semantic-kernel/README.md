# agent-did-semantic-kernel

Integracion funcional de Agent-DID para Semantic Kernel con foco en Python.

Esta variante reutiliza el SDK Python real de Agent-DID para snapshot de identidad, resolucion, verificacion, firma opt-in, contexto de sesion, hooks tipo middleware y observabilidad estructurada sin exponer secretos al runtime visible por el modelo.

## Estado

- Estado actual: `functional`
- Roadmap: F2-04
- Lenguaje objetivo: Python
- Dependencia previa resuelta: SDK Python de Agent-DID
- Implementacion: funcional para tools base, contexto de identidad, middleware ligero y observabilidad saneada

El paquete ya expone una factory publica, tools reutilizables, helpers para contexto y middleware, observabilidad vendor-neutral y defaults seguros. Las operaciones sensibles siguen siendo opt-in: firma HTTP, firma arbitraria, rotacion de claves e historial documental no se habilitan por defecto.

## Hallazgos tecnicos confirmados

Segun la documentacion oficial y el runtime validado en CI, Semantic Kernel expone al menos estas superficies utiles para Agent-DID:

- `Kernel` como host principal para plugins y funciones.
- `KernelPlugin` y `kernel_function(...)` para registrar tools Agent-DID con schemas compatibles.
- `Kernel.invoke(...)` para ejecutar tools a traves del runtime real sin requerir una corrida LLM completa.
- `ChatCompletionAgent` como host agentico validado en la recipe operativa y el smoke test.
- composicion Python-first sin obligar una dependencia runtime en la instalacion por defecto.

## Decision de lenguaje

La decision implementada para F2-04 es:

1. Implementacion en Python.
2. Dependencia explicita del SDK Python existente de Agent-DID.
3. Sin compromiso de implementacion JS en esta fase.

## Objetivo

Integrar Agent-DID como capa de identidad verificable para agentes ejecutados sobre Semantic Kernel, de forma equivalente a lo ya disponible para LangChain:

- inyectar DID, controlador, capacidades y clave activa en el contexto operativo del agente,
- exponer herramientas para inspeccionar identidad, verificar firmas y resolver documentos,
- habilitar firma de payloads o solicitudes HTTP solo mediante opt-in,
- mantener la clave privada fuera del contexto visible para el modelo.

## Uso rapido

```python
from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams

identity = AgentIdentity(AgentIdentityConfig(signer_address="0x1234567890123456789012345678901234567890"))
runtime_identity = await identity.create(
    CreateAgentParams(
      name="semantic_kernel_assistant",
        core_model="gpt-4.1-mini",
        system_prompt="Eres un agente verificable y trazable.",
        capabilities=["identity:resolve", "signature:verify"],
    )
)

integration = create_agent_did_semantic_kernel_integration(
    agent_identity=identity,
    runtime_identity=runtime_identity,
    expose={"sign_http": True, "document_history": True},
)

agent_kwargs = integration.create_agent_kwargs("Usa herramientas Agent-DID cuando aporten evidencia.")
context_middleware = integration.create_context_middleware()
session_context = context_middleware({"session_id": "demo"})
```

El bundle devuelto incluye:

- `tools`: wrappers ligeros con `invoke(...)` y `ainvoke(...)`
- `get_current_identity()` y `get_current_document()`
- `compose_instructions(...)`
- `create_agent_kwargs(...)` para entregar `tools`, `instructions` y `context`
- `create_session_context(...)` para inyectar identidad Agent-DID en session state
- `create_context_middleware(...)` para hooks ligeros de enriquecimiento de contexto
- `create_semantic_kernel_plugin(...)` para registrar las tools en un runtime real de `semantic-kernel`

La API publica tambien exporta el alias conceptual `createAgentDidSemanticKernelIntegration(...)` para mantener continuidad con los artefactos de diseno, aunque la superficie Python-first recomendada es `create_agent_did_semantic_kernel_integration(...)`.

## Runtime real con semantic-kernel

La integracion sigue siendo liviana por defecto, pero ahora expone un extra opcional `runtime` para validar y usar un runtime real de Semantic Kernel mediante `semantic-kernel`.

```bash
python -m pip install -e ".[runtime]"
```

Ejemplo minimo de registro sobre el runtime real:

```python
from semantic_kernel.agents.chat_completion.chat_completion_agent import ChatCompletionAgent
from semantic_kernel.kernel import Kernel

plugin = integration.create_semantic_kernel_plugin(plugin_name="agent_did")
kernel = Kernel()
kernel.add_plugin(plugin)

agent = ChatCompletionAgent(
  name="Verifier",
  instructions=integration.compose_instructions("Usa Agent-DID cuando necesites evidencia verificable."),
  kernel=kernel,
  plugins=[plugin],
)

identity_result = await kernel.invoke(
  function_name="agent_did_get_current_identity",
  plugin_name="agent_did",
)
```

Ese path no fuerza ejecucion LLM en CI. La validacion de paridad se centra en dos cosas mas utiles para esta fase:

- que `semantic-kernel` acepte el plugin generado por la integracion
- que una tool Agent-DID real pueda invocarse a traves del runtime

## Recetas operativas

### Receta 1: runtime real con observabilidad compuesta

Use esta receta cuando quiera validar en local tres cosas a la vez sin depender de una corrida LLM completa:

- registro real del plugin en `semantic-kernel`
- invocacion de una tool Agent-DID desde `Kernel.invoke(...)`
- fan-out de observabilidad a memoria y logging JSON saneado

Ejecute:

```bash
cd integrations/semantic-kernel
python -m pip install -e .[dev]
python -m pip install -e .[runtime]
python examples/agent_did_semantic_kernel_operational_recipe_example.py
```

La recipe:

- crea una identidad efimera con `InMemoryAgentRegistry`
- compone `events.append` con `create_json_logger_event_handler(...)`
- registra el plugin Agent-DID en `Kernel`
- instancia `ChatCompletionAgent` sin requerir ejecucion de modelo
- invoca `agent_did_sign_payload` para demostrar compatibilidad de runtime y redaccion de observabilidad

Artefacto runnable asociado:

- `examples/agent_did_semantic_kernel_operational_recipe_example.py`

## Observabilidad

La factory publica acepta instrumentacion opcional sin acoplar el paquete a un backend especifico:

```python
import logging

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration
from agent_did_semantic_kernel.observability import compose_event_handlers, create_json_logger_event_handler

logger = logging.getLogger("agent_did_semantic_kernel")
events = []

integration = create_agent_did_semantic_kernel_integration(
  agent_identity=agent_identity,
  runtime_identity=runtime_identity,
  expose={"sign_http": True, "sign_payload": True},
  observability_handler=compose_event_handlers(
    events.append,
    create_json_logger_event_handler(logger, extra_fields={"service": "agent-gateway"}),
  ),
)
```

Eventos emitidos:

- `agent_did.identity_snapshot.refreshed`
- `agent_did.tool.started`
- `agent_did.tool.succeeded`
- `agent_did.tool.failed`
- `agent_did.context.created`
- `agent_did.middleware.context_injected`

## Defaults seguros

- `current_identity`, `resolve_did` y `verify_signatures` quedan habilitados por defecto.
- `sign_http`, `sign_payload`, `rotate_keys` y `document_history` permanecen deshabilitados por defecto.
- `sign_http` rechaza esquemas no HTTP(S), credenciales embebidas y targets privados o loopback salvo opt-in explicito con `allow_private_network_targets=True`.
- El contexto de sesion y middleware nunca inyectan `agent_private_key` ni firma cruda.
- La observabilidad redacta `payload`, `body`, `signature`, `private_key`, `token` y headers sensibles por defecto.

## Validacion local

```bash
cd sdk-python
python -m pip install -e .[dev]
cd ../integrations/semantic-kernel
python -m pip install -e .[dev]
python -m ruff check src/ tests/ examples/
python -m mypy src/
python -m pytest tests/ -q
python -m pip install -e .[runtime]
python -m pytest tests/test_runtime_smoke.py -q
python -m build
```

## Gobernanza de implementacion

- Checklist de implementacion: [../../docs/F2-04-Semantic-Kernel-Implementation-Checklist.md](../../docs/F2-04-Semantic-Kernel-Implementation-Checklist.md)
- Checklist de review recurrente: [../../docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md](../../docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md)
- Matriz de paridad: [../../docs/F2-04-Semantic-Kernel-Parity-Matrix.md](../../docs/F2-04-Semantic-Kernel-Parity-Matrix.md)
- Evaluacion de brecha de madurez: [../../docs/F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md](../../docs/F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md)

## Referencias

- Implementacion de referencia actual: [../langchain/README.md](../langchain/README.md)
- Documento de diseno: [../../docs/F2-04-Semantic-Kernel-Integration-Design.md](../../docs/F2-04-Semantic-Kernel-Integration-Design.md)
- Documentacion oficial: https://github.com/microsoft/semantic-kernel