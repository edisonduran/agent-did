# F2-04 - Semantic Kernel Maturity Gap Assessment

## Objetivo

Documentar lo que todavia separa a Semantic Kernel de la madurez operativa mas alta observada en las otras integraciones, sin confundir "funcional", "gobernado" y "totalmente equivalente en operacion".

Este documento es posterior al cierre funcional de F2-04. Su foco ya no es construir la integracion, sino dejar claro que gaps quedan y cuales ya fueron cerrados.

---

## Posicion Actual

Semantic Kernel ya cumple con el estandar del repositorio para:

- paquete Python funcional
- CI dedicada
- tests, lint, type-check y build
- defaults seguros para herramientas sensibles
- observabilidad estructurada saneada
- helpers de contexto, middleware y tools reutilizables
- validacion opcional contra un runtime real de Semantic Kernel mediante `semantic-kernel`

Eso significa que la integracion ya no debe describirse como scaffold ni como compatibilidad teorica.

---

## Baseline De Referencia

La referencia para esta evaluacion es combinada:

- CrewAI como baseline de paridad operativa ligera con smoke validation sobre runtime real
- LangChain Python como baseline de mayor profundidad operativa, observabilidad y recipes

La comparacion se hace sobre cinco dimensiones:

1. realismo del runtime
2. observabilidad
3. granularidad de pruebas
4. profundidad de recipes y ejemplos
5. criterios explicitos de madurez

---

## Gaps Cerrados Desde La Revision Anterior

### Cerrado - Validacion Contra Runtime Real

Estado actual:

- el paquete mantiene instalacion liviana por defecto
- ahora expone un extra `.[runtime]` para instalar `semantic-kernel`
- CI en Python 3.12 instala ese extra y ejecuta un smoke test dedicado
- la validacion confirma registro del plugin, aceptacion del plugin por `ChatCompletionAgent` y ejecucion real de una tool Agent-DID desde el runtime

Por que importa:

Este era el gap operativo mas importante. La integracion deja de apoyarse solo en compatibilidad por forma y pasa a tener compatibilidad verificada contra un host real.

Delta remanente:

- la cobertura actual no extiende todavia a `AgentSession`, orchestration o workflows multi-agent
- eso ya no es un bloqueo de fase, sino una mejora futura de profundidad

### Cerrado - Artefacto Explicito De Paridad Y Madurez

Estado actual:

- existe una matriz dedicada de paridad para Semantic Kernel
- existe esta evaluacion dedicada de brecha de madurez

Por que importa:

Antes la respuesta a la pregunta "tiene paridad o no" dependia de leer varias piezas separadas. Ahora la respuesta queda gobernada por artefactos especificos y auditables.

Delta remanente:

- algunos documentos historicos del repositorio todavia pueden describir divergencias con lenguaje menos preciso
- ese ajuste documental es secundario frente a la cobertura principal ya cerrada

---

## Gaps Restantes

### P3 - Cobertura De Host Avanzado

Estado actual:

- el smoke path prueba runtime real con `ChatCompletionAgent` y plugins Agent-DID

Gap restante:

- falta coverage automatizado para superficies mas avanzadas mencionadas en el diseno, como sesiones extensas, orchestration o persistencia/checkpoint

Impacto:

No bloquea la paridad operativa base, pero si limita la confianza para claims mas ambiciosos sobre escenarios multi-agent y de larga duracion.

### P3 - Observabilidad Especializada

Estado actual:

- la observabilidad actual es estructurada, saneada y reusable

Gap restante:

- no existe todavia un adaptador equivalente a backends especializados del ecosistema LangChain

Impacto:

Es una diferencia de madurez avanzada, no una brecha funcional ni un riesgo inmediato de seguridad.

### P3 - Recipes Operativas Mas Profundas

Estado actual:

- el paquete documenta uso rapido, defaults seguros y ahora su ruta de runtime real
- el paquete ahora incluye una recipe operativa runnable que combina runtime real, invocacion de tool y observabilidad compuesta sin exigir corrida LLM

Gap restante:

- faltan recipes mas profundas para escenarios de produccion completos, por ejemplo flujos con varias tools expuestas, politicas de observabilidad por entorno o patrones mas cercanos a despliegue real

Impacto:

La integracion es usable y ahora mas prescriptiva para validacion local/CI, pero sigue menos desarrollada que LangChain Python para adopcion operativa avanzada.

Delta:

- el gap deja de ser "no hay recipe operativa" y pasa a "hay recipe base, pero todavia no hay catalogo amplio de recipes de produccion"


---

## Regla De Decision

Semantic Kernel puede describirse correctamente como "comparable en madurez operativa a CrewAI" cuando:

1. mantiene disciplina de CI y gobernanza
2. conserva validacion automatizada contra un runtime real
3. sigue documentando de forma explicita sus divergencias aceptadas

Semantic Kernel puede describirse como "equivalente en madurez operativa a LangChain Python" solo cuando, ademas de lo anterior:

1. amplie coverage a superficies avanzadas del host
2. cierre parte de la brecha de recipes operativas
3. documente o implemente una postura mas profunda de observabilidad especializada

Con el estado actual, la descripcion correcta es:

- integracion funcional
- alineada con la gobernanza del repositorio
- comparable en madurez operativa a CrewAI
- todavia por debajo de LangChain Python en profundidad operativa avanzada, pero con gaps explicitos y no bloqueantes
