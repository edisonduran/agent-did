# agent-did-langchain

Integracion funcional de Agent-DID para LangChain Python 1.2.x.

Esta variante complementa la integracion ya implementada en TypeScript/JavaScript y reutiliza el SDK Python real de Agent-DID como backend para snapshot de identidad, resolucion, verificacion, firma HTTP opt-in y rotacion controlada de claves.

La matriz de parity entre ambas integraciones vive en `../../docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`.

## Estado

- Estado actual: `functional-mvp`
- Lenguaje objetivo: Python
- Dependencia previa resuelta: SDK Python de Agent-DID (F2-01)
- Relacion con roadmap: complemento Python de la integracion LangChain ya entregada en JS
- Implementacion: funcional para fases base, operaciones opt-in y readiness de CI

El paquete ya expone una factory publica, helpers de contexto, tools reutilizables, rotacion de claves opt-in y validacion de objetivos HTTP con rechazo por defecto de esquemas inseguros y destinos privados/loopback.

Ahora tambien expone una capa ligera de observabilidad vendor-neutral basada en callbacks y/o logger, con redaccion por defecto de payloads, firmas, cuerpos HTTP y headers sensibles.

## Compatibilidad objetivo

- `agent-did-sdk ==1.0.0rc1`
- `langchain >=1.2.13,<1.3`
- `langchain-core >=1.2.20,<1.3`
- Python 3.10+

## Instalacion

Para el paquete publicado del release candidate, la ruta objetivo es:

```bash
python -m pip install agent-did-sdk==1.0.0rc1 agent-did-langchain==1.0.0rc1
```

Mientras la publicacion del RC corre, la validacion canonica en el repo sigue siendo:

```bash
python -m pip install -e ../../sdk-python
python -m pip install -e .[dev]
```

## Uso rapido

```python
from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams
from langchain.agents import create_agent

identity = AgentIdentity(AgentIdentityConfig(signer_address="0x1234567890123456789012345678901234567890"))
runtime_identity = await identity.create(
    CreateAgentParams(
        name="research_assistant",
        core_model="gpt-4.1-mini",
        system_prompt="Eres un agente preciso y trazable.",
        capabilities=["research:web", "report:write"],
    )
)

integration = create_agent_did_langchain_integration(
    agent_identity=identity,
    runtime_identity=runtime_identity,
    expose={"sign_http": True},
)

agent = create_agent(
    model="openai:gpt-4.1-mini",
    tools=integration.tools,
    system_prompt=integration.compose_system_prompt("Usa herramientas cuando aporten evidencia verificable."),
)
```

## Observabilidad

La factory publica acepta instrumentacion opcional sin acoplar el paquete a un backend especifico:

```python
import logging

from agent_did_langchain import create_agent_did_langchain_integration

logger = logging.getLogger("agent_did_langchain")
events = []

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    expose={"sign_http": True, "sign_payload": True},
    observability_handler=events.append,
    logger=logger,
)
```

Eventos emitidos:

- `agent_did.identity_snapshot.refreshed`
- `agent_did.tool.started`
- `agent_did.tool.succeeded`
- `agent_did.tool.failed`

Redaccion por defecto:

- `payload`, `body`, `signature` y `agent_private_key` se sustituyen por metadatos de longitud.
- `Authorization`, `Signature`, `Signature-Input`, `Cookie`, `Set-Cookie` y `X-API-Key` se redactan en headers.
- las URLs en eventos se normalizan sin query string, fragmento ni credenciales embebidas.

Esto permite conectar LangSmith, logging estructurado, trazas locales o callbacks propios sin exponer material sensible por defecto.

Si quiere reutilizar adaptadores listos para usar sin cambiar la API base, el paquete ahora expone:

- `compose_event_handlers(...)`: combina varios sinks/callbacks en un solo `observability_handler`.
- `create_json_logger_event_handler(logger, ...)`: emite cada evento como un registro JSON saneado, apto para pipelines de logging estructurado.
- `create_langsmith_run_tree(...)`: crea un `RunTree` local con inputs saneados para usarlo como raiz de tracing.
- `create_langsmith_event_handler(run_tree, ...)`: proyecta eventos Agent-DID en child runs de LangSmith, sin cambiar la factory principal.
- `serialize_observability_event(...)`: convierte un evento en un diccionario serializable para integrarlo con otros sistemas.

Tambien puede componer varios destinos al mismo tiempo, por ejemplo callback local + JSON logging + LangSmith:

```python
from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import (
    compose_event_handlers,
    create_json_logger_event_handler,
    create_langsmith_event_handler,
    create_langsmith_run_tree,
)

root_run = create_langsmith_run_tree(name="agent_did_demo", inputs={"scenario": "fanout"})

observability_handler = compose_event_handlers(
    local_events.append,
    create_json_logger_event_handler(logger, extra_fields={"sink": "json"}),
    create_langsmith_event_handler(root_run, extra_fields={"sink": "langsmith"}),
)

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    observability_handler=observability_handler,
)
```

Ejemplo de logging JSON estructurado:

```python
import logging

from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import create_json_logger_event_handler

logger = logging.getLogger("agent_did_langchain.json")

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    expose={"sign_http": True},
    observability_handler=create_json_logger_event_handler(
        logger,
        extra_fields={"service": "agent-gateway", "environment": "dev"},
    ),
)
```

Ejemplo de LangSmith sin cambiar la API base:

```python
from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import create_langsmith_event_handler, create_langsmith_run_tree

root_run = create_langsmith_run_tree(name="agent_did_demo", inputs={"scenario": "local"})

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    expose={"sign_http": True, "sign_payload": True},
    observability_handler=create_langsmith_event_handler(root_run),
)
```

## Recetas operativas

### Receta 1: callback local para debugging rapido

Use esta receta cuando quiera inspeccionar rapidamente el flujo de tools en desarrollo local o tests.

```python
events = []

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    observability_handler=lambda event: events.append(
        {
            "event_type": event.event_type,
            "level": event.level,
            "attributes": event.attributes,
        }
    ),
)
```

Util para:

- inspeccionar `agent_did.tool.failed`
- validar que la redaccion de payloads y headers aplica correctamente
- correlacionar snapshots de identidad con llamadas de tools

### Receta 2: logging JSON estructurado para agregacion

Use esta receta cuando quiera enviar observabilidad a archivos, stdout estructurado o pipelines centralizados.

```python
import logging

from agent_did_langchain.observability import create_json_logger_event_handler

logger = logging.getLogger("agent_did_langchain")
logger.setLevel(logging.INFO)

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    observability_handler=create_json_logger_event_handler(
        logger,
        extra_fields={"service": "agent-gateway", "environment": "prod"},
    ),
)
```

Use esta salida cuando necesite:

- enviar eventos a collectors sin parsear texto libre
- correlacionar eventos por `service`, `environment` o metadata propia
- mantener saneamiento de secretos antes del borde de logging

### Receta 3: LangSmith para tracing de tools

Use esta receta cuando quiera conservar la API publica del paquete y proyectar los eventos Agent-DID como child runs en LangSmith.

```python
from agent_did_langchain.observability import create_langsmith_event_handler, create_langsmith_run_tree

root_run = create_langsmith_run_tree(
    name="agent_did_production_session",
    project_name="agent-did-langchain",
    inputs={"scenario": "tool-tracing"},
    tags=["agent-did", "production"],
)

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    observability_handler=create_langsmith_event_handler(root_run),
)
```

Use LangSmith cuando necesite:

- seguir tool runs individuales con contexto saneado
- conservar el arbol de ejecucion para debugging de agentes
- auditar secuencias multi-tool sin leer secretos desde prompts u outputs

### Receta 4: fan-out a varios sinks

Use esta receta cuando necesite callback local, logging JSON y LangSmith al mismo tiempo.

```python
from agent_did_langchain.observability import (
    compose_event_handlers,
    create_json_logger_event_handler,
    create_langsmith_event_handler,
    create_langsmith_run_tree,
)

root_run = create_langsmith_run_tree(name="agent_did_fanout", inputs={"scenario": "fanout"})

observability_handler = compose_event_handlers(
    local_events.append,
    create_json_logger_event_handler(logger, extra_fields={"sink": "json"}),
    create_langsmith_event_handler(root_run, extra_fields={"sink": "langsmith"}),
)
```

Esta es la receta recomendada cuando quiera:

- debugging local y trazabilidad remota en paralelo
- mantener un sink humano y otro estructurado simultaneamente
- desacoplar la observabilidad del backend final

## Ejemplo orientado a produccion

El paquete incluye un ejemplo opt-in mas cercano a un despliegue real en:

- `examples/agent_did_langchain_production_recipe_example.py`

Ese ejemplo muestra:

- configuracion por variables de entorno
- uso de `create_agent(...)` con modelo real
- observabilidad compuesta con callback local, JSON logging y LangSmith opcional
- guardas para evitar ejecucion accidental sin credenciales o flags explicitos

Variables principales:

- `RUN_LANGCHAIN_PRODUCTION_EXAMPLE=1`: habilita la ejecucion real del agente
- `LANGCHAIN_MODEL`: modelo/provider para `create_agent(...)`, por ejemplo `openai:gpt-4.1-mini`
- `AGENT_DID_SIGNER_ADDRESS`: signer address del runtime local
- `OPENAI_API_KEY`: requerida si usa un modelo OpenAI real
- `LANGSMITH_TRACING=1`: habilita fan-out adicional a LangSmith si el entorno ya esta configurado

Si faltan credenciales o la flag de ejecucion, el ejemplo termina sin error y solo imprime instrucciones.

## Hallazgos tecnicos confirmados

La documentacion publica actual de LangChain Python confirma al menos estas superficies utiles:

- `create_agent(...)` como factory principal para agentes.
- `tools` como mecanismo nativo para exponer funciones al agente.
- `system_prompt` y `messages` como puntos base para inyectar identidad y contexto.
- `agent.invoke(...)` como interfaz directa de ejecucion.
- runtime construido sobre LangGraph, con soporte de durabilidad, streaming, human-in-the-loop y persistence en el ecosistema.
- LangSmith como camino recomendado para tracing y observabilidad.

## Que agrega la integracion

- Snapshot estable de identidad Agent-DID sin secretos.
- Composicion de `system_prompt` con DID, controlador, capacidades y reglas operativas.
- Tools para identidad actual, resolucion DID y verificacion de firmas.
- Tools opt-in para firma HTTP, firma de payload, historial documental y rotacion de claves.

## Objetivo arquitectonico

Mantener en Python el enfoque ya validado en JS:

- inyectar DID, controlador, capacidades y metadata verificable en el contexto del agente,
- exponer herramientas Agent-DID para resolucion, verificacion y firma opt-in,
- mantener la clave privada fuera del prompt y del estado visible al modelo,
- ofrecer una API de integracion pequena y consistente entre lenguajes.

## API publica del MVP

```python
from agent_did_langchain import create_agent_did_langchain_integration

integration = create_agent_did_langchain_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    expose={
        "verify_signatures": True,
        "sign_http": True,
        "rotate_keys": False,
    },
)
```

El objeto devuelto expone:

- `tools`
- `identity_snapshot`
- `get_current_identity()`
- `get_current_document()`
- `compose_system_prompt(base_prompt, additional_context=None)`

## Checklist operativo

La ejecucion del scaffold a paquete funcional esta desglosada en [../../docs/F1-03-LangChain-Python-Implementation-Checklist.md](../../docs/F1-03-LangChain-Python-Implementation-Checklist.md).

El plan tecnico cerrado por archivos, versiones objetivo y criterios de aceptacion esta en [../../docs/F1-03-LangChain-Python-Technical-Plan.md](../../docs/F1-03-LangChain-Python-Technical-Plan.md).

## Componentes principales

- `pyproject.toml`: metadata del paquete Python.
- `src/agent_did_langchain/__init__.py`: factory principal y exports publicos.
- `src/agent_did_langchain/config.py`: configuracion y defaults de exposicion.
- `src/agent_did_langchain/snapshot.py`: snapshot serializable de identidad.
- `src/agent_did_langchain/context.py`: composicion de prompt/contexto.
- `src/agent_did_langchain/tools.py`: herramientas Agent-DID para LangChain Python.
- `src/agent_did_langchain/integration.py`: ensamblaje publico del adaptador.
- `src/agent_did_langchain/observability.py`: eventos, redaccion y hooks de observabilidad.
- `tests/`: pruebas funcionales y de seguridad.
- `examples/agent_did_langchain_example.py`: quick start runnable.
- `examples/agent_did_langchain_did_wba_demo.py`: demo integrado con runtime `did:wba`, resolucion web y firma HTTP verificable.
- `examples/agent_did_langchain_observability_example.py`: callback tracing y redaccion segura.
- `examples/agent_did_langchain_secure_http_example.py`: firma HTTP verificable end-to-end.
- `examples/agent_did_langchain_langsmith_example.py`: tracing local sobre `RunTree` de LangSmith con child runs saneados.
- `examples/agent_did_langchain_multitool_agent_example.py`: flujo `create_agent(...)` con fake chat model y varias tools Agent-DID.
- `examples/agent_did_langchain_composed_observability_example.py`: fan-out simultaneo a callback local, JSON logging y LangSmith.
- `examples/agent_did_langchain_production_recipe_example.py`: ejemplo opt-in con variables de entorno, modelo real y observabilidad compuesta.

## Criterios de implementacion

1. Exponer DID actual, resolucion documental y verificacion de firmas mediante tools.
2. Permitir firma HTTP solo con opt-in explicito.
3. Mantener rotacion de claves deshabilitada por defecto y fuera de este MVP.
4. Inyectar identidad Agent-DID en el contexto del agente sin exponer secretos.
5. Incluir ejemplos runnable y pruebas automatizadas en Python.

## Seguridad operativa

- `sign_http` solo existe con opt-in.
- `sign_payload` solo existe con opt-in.
- `rotate_keys` solo existe con opt-in.
- Los secretos nunca se devuelven en outputs de tools.
- La observabilidad redacta payloads, firmas, cuerpos HTTP y headers sensibles por defecto.
- La firma HTTP rechaza por defecto `file://`, URLs con credenciales embebidas y destinos `localhost` o redes privadas.
- Si el caso de uso requiere firmar hacia targets internos controlados, puede habilitarse `allow_private_network_targets=True` en la factory.

## Ejemplos disponibles

- `examples/agent_did_langchain_example.py`: ensamblaje base, tool calls directos y opcion de demo con modelo real usando `RUN_LANGCHAIN_MODEL_EXAMPLE=1`.
- `examples/agent_did_langchain_did_wba_demo.py`: demo integrado sin dependencias externas con identidad activa `did:wba`, partner remoto `did:wba`, `create_agent(...)` local y verificacion de firma HTTP.
- `examples/agent_did_langchain_observability_example.py`: muestra eventos estructurados y la redaccion aplicada a inputs sensibles.
- `examples/agent_did_langchain_secure_http_example.py`: firma HTTP, devuelve headers verificables y valida la firma con el SDK Python.
- `examples/agent_did_langchain_json_logging_example.py`: emite eventos saneados como logs JSON listos para agregacion.
- `examples/agent_did_langchain_langsmith_example.py`: convierte eventos Agent-DID en child runs de LangSmith sin requerir cambios en la factory.
- `examples/agent_did_langchain_multitool_agent_example.py`: ejecuta `create_agent(...)` localmente con un fake chat model y muestra un recorrido multi-tool reproducible.
- `examples/agent_did_langchain_composed_observability_example.py`: demuestra composicion de handlers para emitir simultaneamente a tres sinks.
- `examples/agent_did_langchain_production_recipe_example.py`: receta opt-in para entorno real con guardas de credenciales, modelo configurable y fan-out de observabilidad.

## Demo integrado `did:wba`

Para ejecutar el demo integrado local de LangChain Python sin depender de credenciales externas:

```bash
cd integrations/langchain-python
python examples/agent_did_langchain_did_wba_demo.py
```

Este demo prueba en un solo flujo:

- identidad activa `did:wba`
- resolucion de una contraparte remota `did:wba`
- `create_agent(...)` con fake chat model reproducible
- firma HTTP Agent-DID verificable end-to-end

La cobertura automatizada equivalente vive en:

- `tests/test_did_wba_demo.py`

## Troubleshooting rapido

- Si una tool devuelve `error`, revise el evento `agent_did.tool.failed` para ver el contexto ya redactado.
- Si necesita correlacion entre prompt y snapshot de identidad, observe `agent_did.identity_snapshot.refreshed`.
- Si `sign_http_request` falla con targets locales, confirme si debe habilitar explicitamente `allow_private_network_targets=True`.
- Si usa LangSmith, cree un `RunTree` local y conectelo mediante `create_langsmith_event_handler(...)`.
- Si usa un backend externo de observabilidad, conectelo mediante `observability_handler` o `logger` en lugar de leer secretos desde outputs de tools.

## Validacion local recomendada

```bash
cd ../..
npm run langchain-python:install-dev
npm run lint:langchain-python
npm run typecheck:langchain-python
npm run test:langchain-python
```

## Referencias

- Integracion JS funcional: [../langchain/README.md](../langchain/README.md)
- Documento de diseno: [../../docs/F1-03-LangChain-Python-Integration-Design.md](../../docs/F1-03-LangChain-Python-Integration-Design.md)
- Documentacion oficial: https://docs.langchain.com/oss/python/langchain/overview