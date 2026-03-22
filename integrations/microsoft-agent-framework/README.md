# agent-did-microsoft-agent-framework

Integracion funcional de Agent-DID para Microsoft Agent Framework con foco en Python.

Esta variante reutiliza el SDK Python real de Agent-DID para snapshot de identidad, resolucion, verificacion, firma opt-in, contexto de sesion, hooks tipo middleware y observabilidad estructurada sin exponer secretos al runtime visible por el modelo.

## Estado

- Estado actual: `functional`
- Roadmap: F2-04
- Lenguaje objetivo: Python
- Dependencia previa resuelta: SDK Python de Agent-DID
- Implementacion: funcional para tools base, contexto de identidad, middleware ligero y observabilidad saneada

El paquete ya expone una factory publica, tools reutilizables, helpers para contexto y middleware, observabilidad vendor-neutral y defaults seguros. Las operaciones sensibles siguen siendo opt-in: firma HTTP, firma arbitraria, rotacion de claves e historial documental no se habilitan por defecto.

## Hallazgos tecnicos confirmados

Segun la documentacion oficial y la guia de migracion desde AutoGen, Microsoft Agent Framework expone al menos estas superficies utiles para Agent-DID:

- `Agent` como abstraccion principal para single-agent execution.
- `tools` registrables y herramientas dinamicas por invocacion.
- `AgentSession` para estado conversacional.
- `middleware` para concerns transversales como seguridad, logging y validacion.
- `WorkflowBuilder` y `executor` para orquestacion multi-agent basada en data flow.
- `request_info()` y `send_responses_streaming()` para human-in-the-loop.
- `checkpoint_storage` para persistencia y reanudacion.
- `setup_observability()` para trazabilidad operativa.

## Decision de lenguaje

La decision implementada para F2-04 es:

1. Implementacion en Python.
2. Dependencia explicita del SDK Python existente de Agent-DID.
3. Sin compromiso de implementacion JS en esta fase.

## Objetivo

Integrar Agent-DID como capa de identidad verificable para agentes ejecutados sobre Microsoft Agent Framework, de forma equivalente a lo ya disponible para LangChain:

- inyectar DID, controlador, capacidades y clave activa en el contexto operativo del agente,
- exponer herramientas para inspeccionar identidad, verificar firmas y resolver documentos,
- habilitar firma de payloads o solicitudes HTTP solo mediante opt-in,
- mantener la clave privada fuera del contexto visible para el modelo.

## Uso rapido

```python
from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams

identity = AgentIdentity(AgentIdentityConfig(signer_address="0x1234567890123456789012345678901234567890"))
runtime_identity = await identity.create(
    CreateAgentParams(
        name="maf_assistant",
        core_model="gpt-4.1-mini",
        system_prompt="Eres un agente verificable y trazable.",
        capabilities=["identity:resolve", "signature:verify"],
    )
)

integration = create_agent_did_microsoft_agent_framework_integration(
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

La API publica tambien exporta el alias conceptual `createAgentDidMicrosoftAgentFrameworkIntegration(...)` para mantener continuidad con los artefactos de diseno, aunque la superficie Python-first recomendada es `create_agent_did_microsoft_agent_framework_integration(...)`.

## Observabilidad

La factory publica acepta instrumentacion opcional sin acoplar el paquete a un backend especifico:

```python
import logging

from agent_did_microsoft_agent_framework import create_agent_did_microsoft_agent_framework_integration
from agent_did_microsoft_agent_framework.observability import compose_event_handlers, create_json_logger_event_handler

logger = logging.getLogger("agent_did_microsoft_agent_framework")
events = []

integration = create_agent_did_microsoft_agent_framework_integration(
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
cd ../integrations/microsoft-agent-framework
python -m pip install -e .[dev]
python -m ruff check src/ tests/ examples/
python -m mypy src/
python -m pytest tests/ -q
python -m build
```

## Gobernanza de implementacion

- Checklist de implementacion: [../../docs/F2-04-Microsoft-Agent-Framework-Implementation-Checklist.md](../../docs/F2-04-Microsoft-Agent-Framework-Implementation-Checklist.md)
- Checklist de review recurrente: [../../docs/F2-04-Microsoft-Agent-Framework-Integration-Review-Checklist.md](../../docs/F2-04-Microsoft-Agent-Framework-Integration-Review-Checklist.md)

## Referencias

- Implementacion de referencia actual: [../langchain/README.md](../langchain/README.md)
- Documento de diseno: [../../docs/F2-04-Microsoft-Agent-Framework-Integration-Design.md](../../docs/F2-04-Microsoft-Agent-Framework-Integration-Design.md)
- Documentacion oficial: https://learn.microsoft.com/agent-framework/