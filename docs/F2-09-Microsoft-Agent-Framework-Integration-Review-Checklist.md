# F2-09 - Microsoft Agent Framework Integration Review Checklist

Use esta checklist cuando una PR cambie tools, wiring de `Agent`, helpers de `WorkflowBuilder`, observabilidad o recipes del paquete en `integrations/microsoft-agent-framework/`.

## Review funcional

- [x] El README describe solamente comportamiento realmente implementado.
- [x] Las tools por defecto siguen limitadas a identidad actual, resolucion y verificacion.
- [x] Las capacidades sensibles siguen siendo opt-in.

## Review de runtime

- [x] Existe evidencia automatizada de que `Agent(...)` acepta el bundle publicado.
- [x] Existe evidencia automatizada de `AgentExecutor` y `WorkflowBuilder` sobre host real.
- [x] Al menos una prueba multi-step combina tools Agent-DID y workflow output.
- [x] Existen pruebas para patrones avanzados de `fan-out`, `fan-in`, `multi-selection` y `switch-case`.

## Review de observabilidad

- [x] Los eventos siguen redactando `payload`, `body`, `signature` y headers sensibles.
- [x] OpenTelemetry sigue proyectando atributos saneados.
- [x] Los helpers de workflow/orchestration emiten eventos estructurados cuando corresponde.

## Review de recipes

- [x] Existe recipe runnable de workflow multi-step.
- [x] Existe recipe runnable de workflow avanzado.
- [x] Existe recipe runnable production-style con sesion y observabilidad compuesta.
- [x] Las recipes no requieren credenciales externas para validar el wiring principal del host.

## Review de gobernanza

- [x] README, design, parity matrix, maturity-gap y checklist de implementacion se actualizaron en sync.
- [x] Existe workflow de CI dedicado para el paquete.

## Conclusión de review

- [x] No queda una divergencia material abierta en runtime/orchestrations, observabilidad o recipes para el alcance gobernado por F2-09.