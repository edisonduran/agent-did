# F2-09 - Microsoft Agent Framework Implementation Checklist

## Baseline

- [x] El paquete declara estado `functional` y esa etiqueta coincide con la surface publicada.
- [x] `integrations/microsoft-agent-framework/README.md` describe comportamiento ya implementado, no futuro especulativo.
- [x] El diseno y la metadata del paquete apuntan al runtime oficial `agent-framework`.

## Factory y surface publica

- [x] Mantener `createAgentDidMicrosoftAgentFrameworkIntegration(...)` como alias conceptual del entrypoint Python-first.
- [x] Exponer `create_agent(...)` como helper principal para `Agent`.
- [x] Exponer helpers de orquestacion para `AgentExecutor` y `WorkflowBuilder`.
- [x] Exponer helpers para `fan-out`, `fan-in`, `multi-selection` y `switch-case`.

## Runtime y orchestration

- [x] Mapear tools Agent-DID a `FunctionTool` nativas del host.
- [x] Validar que el host acepta el bundle en `Agent(...)`.
- [x] Agregar cobertura automatizada sobre `AgentExecutor` y `WorkflowBuilder`.
- [x] Validar una secuencia multi-step con mas de una tool Agent-DID y un workflow real.
- [x] Validar patrones avanzados del runtime (`fan-out`, `fan-in`, `multi-selection`, `switch-case`).

## Seguridad

- [x] Mantener `sign_http`, `sign_payload`, `rotate_keys` y `document_history` como operaciones opt-in.
- [x] Asegurar que la clave privada no entra al prompt ni al contexto visible al modelo.
- [x] Mantener observabilidad y errores saneados por defecto.

## Observabilidad

- [x] Mantener fan-out de eventos saneados para logging JSON.
- [x] Mantener adaptador especializado a OpenTelemetry.
- [x] Agregar eventos explicitos de helper creation para workflow/orchestration.

## Documentacion y recipes

- [x] Mantener un ejemplo MVP runnable.
- [x] Agregar al menos una recipe runnable de workflow multi-step.
- [x] Agregar al menos una recipe runnable de workflow avanzado.
- [x] Agregar al menos una recipe production-style con sesion y observabilidad compuesta.
- [x] Cerrar README, matriz, maturity-gap, checklist de review y design en el mismo frente.

## CI

- [x] Agregar workflow dedicado en GitHub Actions para este paquete.
- [x] Ejecutar lint, mypy, tests, smoke runtime de workflow y build del paquete.

## Exit rule

- [x] F2-09 queda listo para review cuando no haya divergencias materiales abiertas en runtime/orchestrations, observabilidad o recipes para el scope gobernado del repositorio.