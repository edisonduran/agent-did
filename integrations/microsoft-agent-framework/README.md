# agent-did-microsoft-agent-framework

Integracion funcional de Agent-DID para Microsoft Agent Framework con foco en Python.

Esta variante usa el paquete oficial `agent-framework --pre` documentado en Microsoft Learn y ya no se limita a wiring basico de `Agent(...)`: ahora cubre helpers nativos para `AgentExecutor` y `WorkflowBuilder`, observabilidad especializada con OpenTelemetry, recipes operativas profundas y validacion automatizada de runtime/orquestacion sin depender de proveedores externos.

## Estado

- Estado actual: `functional`
- Roadmap: F2-09
- Lenguaje objetivo: Python
- Runtime objetivo: `agent-framework>=1.0.0rc5,<1.1`
- Implementacion: funcional para tools nativas, `Agent`, `AgentExecutor`, `WorkflowBuilder`, observabilidad saneada y recipes operativas multi-step

Con el estado actual, la claim correcta para F2-09 ya no es solo “MVP de wiring basico”. El paquete tiene cierre operativo para el alcance gobernado en runtime/orchestrations, observabilidad y recipes, con CI dedicada y artefactos de gobernanza equivalentes al resto de integraciones Python del repositorio.

## Hallazgos tecnicos confirmados

La documentacion oficial en [Microsoft Learn](https://learn.microsoft.com/es-es/agent-framework/) y el runtime validado en local confirman superficies utiles para una integracion Agent-DID en Python:

- `Agent` como host principal con `instructions`, `tools`, `middleware` y `context_providers`.
- `tool(...)` y `FunctionTool` como superficie nativa para exponer herramientas.
- `AgentSession` para continuidad conversacional sin exponer secretos en prompts.
- `AgentExecutor` como unidad reusable para orquestaciones.
- `WorkflowBuilder` y `Workflow.run(...)` como superficie real para workflows multi-step.
- observabilidad nativa basada en OpenTelemetry dentro del propio runtime.

## Objetivo

Integrar Agent-DID como capa de identidad verificable para agentes y workflows construidos sobre Microsoft Agent Framework, con foco en:

- exponer el DID actual y capacidades verificables del agente,
- resolver documentos DID y verificar firmas desde tools nativas del host,
- habilitar firma de payloads y firma HTTP solo mediante opt-in,
- soportar secuencias de workflow y orquestacion sin perder continuidad de identidad,
- mantener la clave privada fuera del prompt y del contexto visible al modelo.

## Uso rapido

```python
from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration

integration = create_agent_did_microsoft_agent_framework_integration(
  agent_identity=agent_identity,
  runtime_identity=runtime_identity,
  expose={"sign_payload": True, "rotate_keys": True},
)

agent = integration.create_agent(
  client=chat_client,
  name="Verifier",
  base_instructions="Use Agent-DID tools when verifiable identity evidence is required.",
)
executor = integration.create_agent_executor(agent, executor_id="verifier_executor")
workflow = integration.build_workflow_chain([executor], name="identity_workflow")
```

El bundle devuelto incluye:

- `tools`: `FunctionTool` nativas de Agent Framework.
- `get_current_identity()` y `get_current_document()`.
- `get_tool(...)` para resolver tools por nombre sin duplicar wiring manual.
- `compose_instructions(...)`.
- `create_agent_kwargs(...)` para inyectar `instructions` y `tools`.
- `create_agent(...)` para construir un `Agent` listo para usar con el cliente del host.
- `create_agent_executor(...)` para adaptarlo a orquestaciones.
- `create_function_executor(...)` para reducers y handlers tipados compatibles con `fan-in`.
- `create_workflow_builder(...)` y `build_workflow_chain(...)` para recipes y runtime coverage de workflows.
- `build_fan_out_fan_in_workflow(...)`, `build_multi_selection_workflow(...)` y `build_switch_case_workflow(...)` para patrones avanzados del runtime.
- `add_verified_handoff(...)` sobre el `WorkflowBuilder` para insertar verificacion de identidad en los bordes de handoff con TTL por `action_class` (ver seccion de abajo).

## Verified handoffs (`add_verified_handoff`)

Inserta un verificador de Agent-DID en el borde entre dos executors de un workflow. Hard gate fail-closed con TTL por `action_class`, soporte de la race condition de rotacion de llave durante el handoff y disposicion de bloqueo via excepcion tipada (default) o callback opt-in.

```python
from agent_did_microsoft_agent_framework import (
    SignedHandoffMessage,
    VerificationBlockedError,
    create_agent_did_microsoft_agent_framework_integration,
)

integration = create_agent_did_microsoft_agent_framework_integration(...)

builder = integration.create_workflow_builder(start_executor=intake)
builder.add_edge(intake, enrichment)
builder.add_verified_handoff(
    from_executor=enrichment,
    to_executor=execution,
    action_class="reversible",        # irreversible | compensable | reversible
    allowed_dids=["did:wba:trusted"],
    require_signature=True,
    on_verification_blocked=None,     # default = raise VerificationBlockedError
    output_type=str,
)
```

Defaults TTL (overridables por workflow, no por encima de los topes para `irreversible` y cross-domain):

| `action_class` | TTL default |
|---|---|
| `irreversible` | 30 s (no widenable) |
| `compensable`  | 120 s |
| `reversible`   | 300 s |

Reglas adicionales:
- Cross-domain hops fuerzan re-verify (TTL = 0).
- Dentro del TTL: si la firma fue emitida bajo la llave previa y el agente roto su llave, se acepta via `verify_historical_signature` del SDK central.
- Fuera del TTL: solo se acepta firma contra el current key set; si la llave previa fue revocada -> `VerificationBlockedError(failing_gates=["key_lifecycle"])`.

Disposicion de bloqueo:
- Default: levanta `VerificationBlockedError(result, failing_gates, enforcement_note, checked_did, action_class)`.
- Opt-in: si registras `on_verification_blocked=callback`, recibe el mismo error. Devolver `None` detiene el workflow grasiosamente; devolver cualquier otro valor lo emite via `ctx.send_message(...)` como salida del verificador.

Observabilidad:
- `agent_did.workflow.handoff_verified` en exitos (incluye `from_did`, `action_class`, `ttl_seconds`, `decision_reason`).
- `agent_did.workflow.handoff_blocked` en bloqueos (incluye `failing_gates`, `decision_reason`).

Ejemplo end-to-end: [`examples/agent_did_microsoft_agent_framework_verified_handoff_example.py`](examples/agent_did_microsoft_agent_framework_verified_handoff_example.py).

### Credito de diseno

El diseno de esta API surgio de una conversacion publica con [@haroldmalikfrimpong-ops](https://github.com/haroldmalikfrimpong-ops) en `microsoft/agent-framework#4842`. Hilos de referencia:
- Discusion original (handoff boundary vs middleware): [microsoft/agent-framework#4842](https://github.com/microsoft/agent-framework/issues/4842).
- Issue concreto con la API completa lockeada: [edisonduran/agent-did#26](https://github.com/edisonduran/agent-did/issues/26).
- Race condition de key-rotation durante handoff: [microsoft/agent-framework#4842 (comentario)](https://github.com/microsoft/agent-framework/issues/4842#issuecomment-4327716940).


## Tools expuestas por defecto

- `agent_did_get_current_identity`
- `agent_did_resolve_did`
- `agent_did_verify_signature`

## Tools opt-in

- `agent_did_sign_payload`
- `agent_did_sign_http_request`
- `agent_did_rotate_key`
- `agent_did_get_document_history`

## Runtime y orquestacion

La validacion automatizada ya no se limita a `Agent(...)` y aceptación del bundle. Ahora cubre tambien:

- construccion de `AgentExecutor`
- armado de cadenas con `WorkflowBuilder`
- ejecucion real de un workflow multi-step con dos agentes stub
- patrones avanzados de `fan-out`, `fan-in`, `multi-selection` y `switch-case`
- continuidad de identidad a traves de firma, verificacion, rotacion de claves e historial documental antes y despues del workflow

## Recetas operativas

### Receta 1: workflow de identidad multi-step

Use esta receta cuando quiera validar una secuencia real de orquestacion con dos agentes y herramientas Agent-DID sin depender de un proveedor externo:

- firma antes de rotacion
- rotacion de clave activa
- firma despues de rotacion
- consulta de historial documental
- workflow planner → reviewer con `WorkflowBuilder`

Ejecute:

```bash
cd integrations/microsoft-agent-framework
python -m pip install -e .[dev]
python examples/agent_did_microsoft_agent_framework_workflow_recipe_example.py
```

Artefacto runnable asociado:

- `examples/agent_did_microsoft_agent_framework_workflow_recipe_example.py`

### Receta 2: patterns avanzados de workflow

Use esta receta cuando quiera validar patrones nativos adicionales del runtime:

- `fan-out` hacia ramas paralelas
- `fan-in` a un reductor final
- `multi-selection` basado en funcion de seleccion
- `switch-case` con `Case` y `Default`

Ejecute:

```bash
cd integrations/microsoft-agent-framework
python -m pip install -e .[dev]
python examples/agent_did_microsoft_agent_framework_advanced_workflow_recipe_example.py
```

Artefacto runnable asociado:

- `examples/agent_did_microsoft_agent_framework_advanced_workflow_recipe_example.py`

### Receta 3: recipe production-style con sesiones y observabilidad compuesta

Use esta receta cuando quiera validar operacion mas cercana a produccion sin credenciales externas:

- continuidad de sesion con `AgentSession`
- firma de payload
- firma HTTP opt-in
- rotacion de clave activa
- historial documental
- workflow multi-step
- fan-out de observabilidad a memoria, JSON logging y OpenTelemetry

Ejecute:

```bash
cd integrations/microsoft-agent-framework
python -m pip install -e .[dev]
python examples/agent_did_microsoft_agent_framework_production_recipe_example.py
```

Artefacto runnable asociado:

- `examples/agent_did_microsoft_agent_framework_production_recipe_example.py`

## Observabilidad

La integracion emite eventos saneados y puede proyectarlos a JSON logging o a spans OpenTelemetry:

```python
from agent_did_microsoft_agent_framework.observability import (
  compose_event_handlers,
  create_json_logger_event_handler,
  create_opentelemetry_event_handler,
  create_opentelemetry_tracer,
)
```

Eventos relevantes cubiertos por la integracion:

- `agent_did.identity_snapshot.refreshed`
- `agent_did.tool.started`
- `agent_did.tool.succeeded`
- `agent_did.tool.failed`
- `agent_did.workflow.executor_created`
- `agent_did.workflow.function_executor_created`
- `agent_did.workflow.builder_created`
- `agent_did.workflow.chain_built`
- `agent_did.workflow.fan_out_fan_in_built`
- `agent_did.workflow.multi_selection_built`
- `agent_did.workflow.switch_case_built`

La redaccion cubre `payload`, `body`, `signature`, headers sensibles y URLs con credenciales o query strings.

## Validacion local

```bash
cd sdk-python
python -m pip install -e .[dev]
cd ../integrations/microsoft-agent-framework
python -m pip install -e .[dev]
python -m ruff check src tests examples
python -m mypy src
python -m pytest tests -q
python examples/agent_did_microsoft_agent_framework_mvp_example.py
python examples/agent_did_microsoft_agent_framework_workflow_recipe_example.py
python examples/agent_did_microsoft_agent_framework_advanced_workflow_recipe_example.py
python examples/agent_did_microsoft_agent_framework_production_recipe_example.py
```

## Gobernanza de implementacion

- Checklist de implementacion: `../../docs/F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md`
- Checklist de review recurrente: `../../docs/F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md`
- Matriz de paridad: `../../docs/F2-09-Microsoft-Agent-Framework-Parity-Matrix.md`
- Evaluacion de brecha de madurez: `../../docs/F2-09-Microsoft-Agent-Framework-Maturity-Gap-Assessment.md`
- Documento de diseno: `../../docs/F2-09-Microsoft-Agent-Framework-Integration-Design.md`

## CI dedicada

La validacion del paquete queda cubierta por `.github/workflows/ci-microsoft-agent-framework.yml`, con lint, type-check, tests, smoke runtime de workflow/orchestracion y build del paquete.

## Conclusión

Para el alcance gobernado por F2-09, ya no queda una divergencia material abierta en runtime/orchestrations, observabilidad o recipes operativas. El siguiente trabajo natural pasa a ser mantenimiento incremental o extensiones no requeridas para la claim actual.
