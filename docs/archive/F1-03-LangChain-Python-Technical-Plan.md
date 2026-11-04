> **Historical document (archived by M-21, 2026-11).** Retained for context only; claims here may be stale. Current sources of truth: [INDEX](../INDEX.md), [External Conformance Matrix](../External-Conformance-Matrix.md).

# F1-03 - LangChain Python Technical Implementation Plan

## Objetivo

Convertir `integrations/langchain-python/` desde scaffold de diseno a un paquete funcional, verificable y mantenible, consistente con la integracion LangChain JS ya implementada y con el SDK Python de Agent-DID ya disponible.

Este documento cierra el plan tecnico por:

1. archivos a crear o modificar,
2. decisiones de arquitectura,
3. versiones objetivo de dependencias,
4. criterios de aceptacion por bloque,
5. orden de ejecucion recomendado.

---

## Decisiones Base

### 1. Superficie de integracion objetivo

La referencia funcional existente es la integracion JS en:

- `integrations/langchain/src/agentDidLangChain.js`

La variante Python debe mantener **paridad conceptual**, no copia literal de abstracciones internas.

### 2. Enfoque de arquitectura para Python

La implementacion Python se construira sobre cuatro piezas principales:

1. **snapshot de identidad**
2. **composicion explicita de contexto/system prompt**
3. **tools reutilizables**
4. **factory de integracion**

No se tomara como requisito de Fase 1 una capa tipo middleware si la API publica de LangChain Python no la necesita de forma estable. La prioridad es una integracion robusta sobre superficies publicas y estables.

### 3. Politica de seguridad por defecto

Por defecto la integracion Python debe exponer solo:

- identidad actual,
- resolucion DID,
- verificacion de firmas.

Las operaciones sensibles deben ser opt-in explicito:

- `sign_http`
- `sign_payload`
- `rotate_keys`

La clave privada nunca debe entrar en:

- prompts,
- mensajes,
- contexto del modelo,
- salidas de tools,
- logs de error estructurados.

---

## Versiones Objetivo Verificadas

Verificacion realizada el `2026-03-21`.

### LangChain JS

- `langchain`: ultima version publicada verificada `1.2.35`
- `@langchain/core`: ultima version publicada verificada `1.1.34`

### LangChain Python

- `langchain`: ultima version publicada verificada `1.2.13`
- `langchain-core`: ultima version publicada verificada `1.2.20`

### Decision

El MVP debe fijar compatibilidad objetivo explicita en la linea `1.2`:

- JS: `langchain ^1.2.35`, `@langchain/core ^1.1.34`
- Python: `langchain >=1.2.13,<1.3`, `langchain-core >=1.2.20,<1.3`

No se recomienda dejar la compatibilidad como "ultima version disponible" sin documentarla.

---

## Alcance del MVP

El MVP funcional de LangChain Python debe incluir:

1. factory publica de integracion,
2. snapshot de identidad Agent-DID,
3. composicion de `system_prompt` con contexto verificable,
4. tool para identidad actual,
5. tool para resolucion DID,
6. tool para verificacion de firmas,
7. tests del paquete,
8. ejemplo runnable,
9. documentacion actualizada.

Queda fuera del MVP inicial:

1. rotacion de claves desde tools,
2. firma arbitraria de payload habilitada por defecto,
3. CI dedicado del paquete en la misma iteracion de primer merge,
4. dependencias a superficies no estables de LangChain Python.

---

## Plan Tecnico por Archivos

### A. Alinear referencia JS con la ultima patch estable

#### Archivo

- `integrations/langchain/package.json`

#### Cambio

- actualizar versiones objetivo de `langchain` y `@langchain/core`

#### Criterios de aceptacion

1. `langchain` apunta a `^1.2.35`
2. `@langchain/core` apunta a `^1.1.34`
3. las pruebas del paquete JS siguen verdes
4. el README JS sigue describiendo correctamente la compatibilidad objetivo

---

### B. Convertir metadata Python de scaffold a paquete instalable

#### Archivo

- `integrations/langchain-python/pyproject.toml`

#### Cambio

- declarar dependencias del paquete
- declarar dependencias de desarrollo
- incorporar configuracion minima de calidad
- actualizar semantica de estado cuando el MVP este listo

#### Dependencias objetivo

- `agent-did-sdk >=0.1.0`
- `langchain >=1.2.13,<1.3`
- `langchain-core >=1.2.20,<1.3`

#### Dev dependencies recomendadas

- `pytest>=8.0`
- `ruff>=0.4`
- `mypy>=1.10`

#### Criterios de aceptacion

1. el paquete se instala con `python -m pip install -e .`
2. las dependencias resuelven sin conflicto
3. el archivo deja de representar solo un scaffold vacio
4. el estado del paquete refleja al menos un `mvp` implementado al cerrar Fase 1

---

### C. Definir configuracion publica y defaults de exposicion

#### Archivo nuevo

- `integrations/langchain-python/src/agent_did_langchain/config.py`

#### Responsabilidad

- definir configuracion publica del adaptador
- definir flags de exposicion y sus defaults

#### Defaults esperados

- `current_identity = True`
- `resolve_did = True`
- `verify_signatures = True`
- `sign_http = False`
- `sign_payload = False`
- `rotate_keys = False`
- `document_history = False`

#### Criterios de aceptacion

1. la configuracion valida tipos y estructura
2. los defaults reflejan la postura de seguridad del proyecto
3. las capacidades sensibles solo aparecen con opt-in explicito

---

### D. Construir snapshot de identidad

#### Archivo nuevo

- `integrations/langchain-python/src/agent_did_langchain/snapshot.py`

#### Responsabilidad

- derivar una vista estable y serializable de `runtime_identity`

#### Campos minimos

- `did`
- `controller`
- `name`
- `description`
- `version`
- `capabilities`
- `member_of`
- `authentication_key_id`
- `created`
- `updated`

#### Criterios de aceptacion

1. el snapshot es deterministic
2. no incluye secretos
3. mantiene equivalencia conceptual con la integracion JS

---

### E. Componer contexto y system prompt

#### Archivo nuevo

- `integrations/langchain-python/src/agent_did_langchain/context.py`

#### Responsabilidad

- generar el bloque textual de identidad Agent-DID
- combinarlo con un `system_prompt` base

#### Helpers esperados

- `build_agent_did_system_prompt(...)`
- `compose_system_prompt(...)`

#### Criterios de aceptacion

1. el prompt incluye DID, controller, capacidades y metodo de autenticacion activo
2. el prompt incluye reglas claras de no inventar DID ni fabricar headers autenticados
3. no aparece material secreto en el contexto generado

---

### F. Implementar tools minimas del paquete

#### Archivo nuevo

- `integrations/langchain-python/src/agent_did_langchain/tools.py`

#### Fase 1 - Tools obligatorias

1. `get_current_identity`
2. `resolve_did`
3. `verify_signature`

#### Fase 2 - Tool sensible opt-in

4. `sign_http_request`

#### Reglas de implementacion

- usar el SDK Python real como backend
- devolver errores estructurados en vez de excepciones crudas al agente
- no devolver secretos
- validar URL en firma HTTP

#### Criterios de aceptacion

1. las tools minimas existen y son invocables
2. `resolve_did` usa el resolutor real del SDK
3. `verify_signature` responde de forma estable ante inputs validos e invalidos
4. `sign_http_request` solo existe si `sign_http = True`
5. `sign_http_request` rechaza esquemas no `http/https`

---

### G. Ensamblar la integracion publica

#### Archivo nuevo

- `integrations/langchain-python/src/agent_did_langchain/integration.py`

#### Responsabilidad

- ensamblar config, snapshot, contexto y tools
- exponer una API pequena y usable desde LangChain Python

#### Interfaz esperada del objeto de integracion

- `tools`
- `identity_snapshot`
- `get_current_identity()`
- `get_current_document()`
- `compose_system_prompt(base_prompt, additional_context=None)`

#### Criterios de aceptacion

1. el objeto es usable con `create_agent(...)`
2. no depende de APIs privadas o inestables de LangChain Python
3. replica la intencion funcional del paquete JS

---

### H. Activar la factory publica del paquete

#### Archivo

- `integrations/langchain-python/src/agent_did_langchain/__init__.py`

#### Cambio

- reemplazar el `NotImplementedError`
- exportar factory y tipos publicos

#### Criterios de aceptacion

1. `create_agent_did_langchain_integration(...)` existe y funciona
2. importar el paquete no falla
3. la superficie publica queda explicitamente cerrada

---

### I. Agregar pruebas del paquete

#### Archivos nuevos

- `integrations/langchain-python/tests/test_snapshot.py`
- `integrations/langchain-python/tests/test_context.py`
- `integrations/langchain-python/tests/test_tools.py`
- `integrations/langchain-python/tests/test_security.py`
- `integrations/langchain-python/tests/test_integration.py`

#### Cobertura minima

##### `test_snapshot.py`

1. snapshot contiene todos los campos esperados
2. no contiene secretos

##### `test_context.py`

1. system prompt contiene DID, controller y capacidades
2. el contexto adicional se concatena correctamente

##### `test_tools.py`

1. `get_current_identity` devuelve DID correcto
2. `resolve_did` devuelve documento resoluble
3. `verify_signature` valida firmas reales
4. entradas malformadas devuelven error estructurado

##### `test_security.py`

1. `sign_http_request` rechaza `file://`
2. `sign_http_request` rechaza otros esquemas no permitidos
3. ninguna tool devuelve material secreto
4. las tools sensibles no existen cuando no estan habilitadas

##### `test_integration.py`

1. la factory devuelve el objeto esperado
2. `compose_system_prompt(...)` funciona con prompt vacio y no vacio
3. el conjunto de tools se alinea con la configuracion de exposicion

---

### J. Agregar ejemplo runnable

#### Archivo nuevo

- `integrations/langchain-python/examples/agent_did_langchain_example.py`

#### Responsabilidad

- mostrar ensamblaje de `create_agent(...)` con:
  - identity
  - prompt compuesto
  - tools

#### Criterios de aceptacion

1. el ejemplo no hardcodea secretos
2. el ejemplo ilustra el flujo minimo real
3. el ejemplo es coherente con el quick start JS

---

### K. Actualizar documentacion del paquete y del track

#### Archivos

- `integrations/langchain-python/README.md`
- `docs/archive/F1-03-LangChain-Python-Integration-Design.md`
- `docs/F1-03-LangChain-Python-Implementation-Checklist.md`

#### Cambios

- convertir README de scaffold a MVP implementado
- reflejar versiones objetivo
- marcar fases completadas en checklist
- mantener visible lo aun no implementado

#### Criterios de aceptacion

1. la documentacion coincide con el estado real del paquete
2. no describe al SDK Python como dependencia pendiente
3. deja claro que es MVP y que queda para iteraciones posteriores

---

## Orden de Ejecucion Recomendado

1. `integrations/langchain/package.json`
2. `integrations/langchain-python/pyproject.toml`
3. `integrations/langchain-python/src/agent_did_langchain/config.py`
4. `integrations/langchain-python/src/agent_did_langchain/snapshot.py`
5. `integrations/langchain-python/src/agent_did_langchain/context.py`
6. `integrations/langchain-python/src/agent_did_langchain/tools.py`
7. `integrations/langchain-python/src/agent_did_langchain/integration.py`
8. `integrations/langchain-python/src/agent_did_langchain/__init__.py`
9. `integrations/langchain-python/tests/test_snapshot.py`
10. `integrations/langchain-python/tests/test_context.py`
11. `integrations/langchain-python/tests/test_tools.py`
12. `integrations/langchain-python/tests/test_security.py`
13. `integrations/langchain-python/tests/test_integration.py`
14. `integrations/langchain-python/examples/agent_did_langchain_example.py`
15. `integrations/langchain-python/README.md`
16. `docs/archive/F1-03-LangChain-Python-Integration-Design.md`
17. `docs/F1-03-LangChain-Python-Implementation-Checklist.md`

---

## Definicion de Done

La integracion LangChain Python se considerara suficientemente cerrada para el repo cuando:

1. exista la factory publica funcional,
2. el paquete exponga tools de identidad actual, resolucion y verificacion,
3. la firma HTTP exista como opt-in seguro,
4. haya ejemplo runnable,
5. haya pruebas funcionales y de seguridad,
6. la documentacion deje de hablar de scaffold puro,
7. la compatibilidad objetivo con LangChain quede documentada y validada.

---

## Recomendacion Final

La mejor ruta tecnica es implementar primero un MVP funcional de LangChain Python sobre superficies publicas estables de LangChain 1.2, sin intentar replicar literalmente el middleware JS si eso introduce acoplamiento innecesario.

La integracion JS debe seguir tratandose como referencia funcional, y la variante Python debe buscar equivalencia conceptual, seguridad por defecto y validacion automatizada antes de expandir nuevos frentes adicionales mas alla de los ya entregados para CrewAI, Semantic Kernel y Microsoft Agent Framework.