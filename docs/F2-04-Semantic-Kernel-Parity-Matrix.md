# F2-04 - Semantic Kernel Parity Matrix

## Objetivo

Comparar la integracion de Semantic Kernel con las otras dos integraciones Python mas relevantes del repositorio:

- CrewAI
- LangChain Python

La comparacion separa tres cosas que antes estaban mezcladas:

1. paridad funcional base
2. paridad operativa verificable
3. divergencias aceptadas de madurez

---

## Matriz

| Dimension | Semantic Kernel | CrewAI | LangChain Python |
| --- | --- | --- | --- |
| Factory publica y surface Python-first | Si | Si | Si |
| Tools Agent-DID con defaults seguros | Si | Si | Si |
| Inyeccion de contexto e identidad sin secretos | Si | Si | Si |
| Observabilidad estructurada saneada | Si | Si | Si |
| Extra opcional para runtime real | Si (`.[runtime]` con `semantic-kernel`) | Si (`.[runtime]` con `crewai`) | No aplica como gap principal porque el runtime real ya forma parte del stack esperado |
| Smoke test automatizado contra runtime real | Si (`semantic-kernel`) | Si (`crewai`) | Parcialmente cubierto por su stack principal y recipes, pero con una estrategia distinta |
| Ejemplos base de uso | Si | Si | Si |
| Recipes operativas mas profundas | Parcial | Parcial | Mas maduras |
| Observabilidad con backend especializado | Parcial | Parcial | Mas madura |
| CI dedicada, lint, type-check, tests y build | Si | Si | Si |
| Artefacto explicito de madurez/paridad | Si | Si | Parcialmente distribuido en checklist, design y parity docs |

---

## Lectura Correcta De La Matriz

### Donde Semantic Kernel ya tiene paridad real

- la integracion ya no es scaffold
- el surface publico es funcional y consistente con el resto del repositorio
- la postura de seguridad y saneamiento de observabilidad ya es comparable
- ahora existe validacion automatizada contra un runtime real de Semantic Kernel via `semantic-kernel`

### Donde la paridad es suficiente pero no absoluta

- la validacion real de runtime hoy cubre registro del plugin, aceptacion por el agente y ejecucion de tools sin requerir corrida LLM completa
- eso iguala el nivel practico que CrewAI usa para smoke coverage, pero no prueba todavia escenarios mas pesados como sesiones largas, orchestrations o workflows multi-agent

### Donde LangChain Python sigue por delante

- recipes operativas mas profundas
- mayor madurez en adaptadores de tracing y observabilidad especializada
- mas superficie documentada para escenarios de produccion

---

## Conclusión

La descripcion correcta del estado actual es:

- Semantic Kernel tiene paridad funcional con CrewAI y LangChain Python para la capa base de Agent-DID
- Semantic Kernel ya tiene paridad operativa suficiente con CrewAI porque ambos cuentan con smoke validation sobre un runtime real en CI
- Semantic Kernel todavia no replica toda la madurez documental y observabilidad avanzada de LangChain Python, pero esa diferencia ya es explicita y no bloquea la fase actual
