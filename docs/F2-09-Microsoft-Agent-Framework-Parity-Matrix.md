# F2-09 - Microsoft Agent Framework Parity Matrix

## Objetivo

Comparar la integracion de Microsoft Agent Framework con las otras integraciones Python maduras del repositorio, separando:

1. surface funcional base
2. runtime/orchestrations verificables
3. observabilidad y recipes operativas

## Matriz

| Dimension | Microsoft Agent Framework | Semantic Kernel | LangChain Python |
| --- | --- | --- | --- |
| Factory publica y surface Python-first | Si | Si | Si |
| Tools Agent-DID con defaults seguros | Si | Si | Si |
| Inyeccion de identidad sin exponer secretos | Si | Si | Si |
| Observabilidad estructurada saneada | Si | Si | Si |
| Observabilidad con backend especializado | Si (OpenTelemetry) | Si (OpenTelemetry) | Si (LangSmith) |
| Cobertura runtime real del host principal | Si (`Agent`) | Si (`Kernel` / `ChatCompletionAgent`) | Si |
| Cobertura runtime avanzada sobre orquestacion | Si (`AgentExecutor` / `WorkflowBuilder`) | No aplica como primitive principal de F2-04 | Parcial, cubierta via otros patrones del stack |
| Recipes operativas profundas | Si | Si | Si |
| CI dedicada, lint, mypy, tests y build | Si | Si | Si |
| Artefacto explicito de madurez/paridad | Si | Si | Parcialmente distribuido |

## Lectura correcta de la matriz

### Donde Microsoft Agent Framework ya tiene paridad real

- el surface publico ya no es scaffold
- el host principal y la capa de tools son funcionales
- existe cobertura automatizada de workflow/orchestration, incluyendo patrones avanzados, y no solo de wiring basico
- la postura de saneamiento y observabilidad especializada ya es comparable con el resto del repositorio

### Donde la integracion cierra sus brechas materiales

- runtime: ya no se limita a `Agent(...)`; cubre `AgentExecutor` y `WorkflowBuilder`
- observabilidad: ya no se limita a eventos estructurados genericos; proyecta tambien a OpenTelemetry con redaccion validada
- recipes: ya no se limita a un ejemplo MVP; ahora incluye recipes de workflow multi-step y de operacion production-style con sesion y fan-out de observabilidad

## Conclusión

La descripcion correcta del estado actual es:

- Microsoft Agent Framework ya tiene paridad operativa cerrada para el alcance gobernado por F2-09 en runtime/orchestrations, observabilidad y recipes
- no queda una divergencia material abierta dentro de ese alcance
- las diferencias restantes son host-native y no representan un gap abierto de implementacion para este repositorio