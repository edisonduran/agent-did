> **Historical document (archived by M-21, 2026-11).** Retained for context only; claims here may be stale. Current sources of truth: [INDEX](../INDEX.md), [External Conformance Matrix](../External-Conformance-Matrix.md).

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

## Gaps Materiales Restantes

No queda ninguna divergencia material abierta en las tres areas que bloqueaban la claim de paridad total.

### Cerrado - Cobertura De Host Avanzado

Estado actual:

- la suite runtime ahora prueba una secuencia multi-step sobre `semantic-kernel` con firma, verificacion, rotacion e historial
- la prueba confirma continuidad de contexto e identidad activa antes y despues de la rotacion

Impacto:

- ya no existe bloqueo material para declarar paridad operativa total dentro del alcance actual de F2-04
- futuras extensiones a orchestration o persistencia serian mejoras incrementales, no prerequisitos para la claim actual

### Cerrado - Observabilidad Especializada

Estado actual:

- la integracion mantiene observabilidad estructurada saneada
- ahora tambien expone un adaptador especializado a OpenTelemetry con mapping estable de lifecycle y pruebas de redaccion

Impacto:

- ya no existe una diferencia material frente a LangChain Python en profundidad de observabilidad para el alcance del repositorio
- la diferencia de backend concreto LangSmith vs OpenTelemetry ya no es un gap, sino una eleccion de ecosistema

### Cerrado - Recipes Operativas Mas Profundas

Estado actual:

- el paquete documenta uso rapido, defaults seguros y ahora su ruta de runtime real
- el paquete incluye una recipe base de runtime real
- el paquete ahora incluye recipes adicionales para observabilidad compuesta con OpenTelemetry y para una secuencia operativa de produccion sin corrida LLM obligatoria

Impacto:

La integracion ya no queda por debajo de LangChain Python en recipes operativas para el alcance que el repositorio exige hoy.


---

## Regla De Decision

Semantic Kernel puede describirse correctamente como "comparable en madurez operativa a CrewAI" cuando:

1. mantiene disciplina de CI y gobernanza
2. conserva validacion automatizada contra un runtime real
3. sigue documentando de forma explicita sus divergencias aceptadas

Semantic Kernel puede describirse como "equivalente en madurez operativa a LangChain Python" porque ya cumple, ademas de lo anterior:

1. coverage avanzado sobre host real
2. recipes operativas comparables
3. una postura mas profunda de observabilidad especializada

## Condiciones Minimas Para Declarar Paridad Total Con LangChain Python

La expresion "paridad total con LangChain Python" ya puede usarse porque existe evidencia verificable de estos cinco minimos al mismo tiempo:

1. Cobertura avanzada de host en CI.
2. Postura de observabilidad especializada documentada y validada.
3. Recipes operativas de produccion comparables.
4. Regla de claims y gaps explicitamente cerrada en docs.
5. Ninguna divergencia material abierta en runtime, observabilidad o recipes.

### Minimo 1 - Cobertura avanzada de host en CI

Debe existir validacion automatizada, no solo recipe manual, para al menos:

- un flujo sessionful o multi-step sobre el host real
- una prueba que ejerza mas de una tool Agent-DID en la misma corrida
- una prueba que confirme que el contexto inyectado sigue disponible a lo largo de la secuencia

No basta con probar registro del plugin y una invocacion aislada.

### Minimo 2 - Observabilidad especializada documentada y validada

Debe existir una superficie mas profunda que la observabilidad estructurada generica, con al menos uno de estos caminos:

- adaptador dedicado a OpenTelemetry u otra capa nativa/comun del ecosistema Semantic Kernel
- proyeccion estructurada de eventos Agent-DID a spans, traces o telemetria equivalente

Ademas, debe haber prueba automatizada que confirme:

- preservacion de redaccion de secretos
- consistencia del mapping de eventos clave
- documentacion de cuando usar esa capa y cuando no

### Minimo 3 - Recipes operativas de produccion comparables

La integracion debe ofrecer al menos dos recipes adicionales a la base actual:

- una recipe multi-tool o sessionful
- una recipe de observabilidad por entorno o de despliegue operativo

Esas recipes deben ser mas que snippets: tienen que explicar objetivo, prerequisitos, limite de claim y resultado esperado.

### Minimo 4 - Regla de claims y gaps cerrada en docs

Los siguientes artefactos deben alinearse en el mismo PR cuando se cierre la brecha:

- `docs/F2-04-Semantic-Kernel-Parity-Matrix.md`
- `docs/archive/F2-04-Semantic-Kernel-Maturity-Gap-Assessment.md`
- `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md`
- `docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md`
- `integrations/semantic-kernel/README.md`

La conclusion de todos debe pasar de "comparable a CrewAI" a una formulacion que ya permita decir "equivalente en madurez operativa a LangChain Python" sin reservas importantes.

### Minimo 5 - Ninguna divergencia material abierta

Antes de declarar paridad total, no debe quedar abierta ninguna divergencia material en estas tres areas:

- cobertura de host avanzado
- observabilidad especializada
- recipes operativas profundas

Si alguna de esas tres sigue en estado parcial, la claim correcta sigue siendo "paridad funcional base" o "comparabilidad operativa", no "paridad total".

Con el estado actual, la descripcion correcta es:

- integracion funcional
- alineada con la gobernanza del repositorio
- equivalente a LangChain Python en madurez operativa para el alcance actual de runtime, observabilidad y recipes
- sin divergencias materiales abiertas en runtime, observabilidad o recipes
