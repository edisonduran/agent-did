# F1-03 - Matriz de Parity de Integraciones LangChain TS vs Python

## Objetivo

Definir la parity operativa entre las integraciones LangChain de TypeScript y Python, mas alla de la parity del SDK core.

Esta matriz responde cuatro preguntas:

1. Que significa parity de integracion en este repositorio.
2. Que capacidades ya estan alineadas entre TS y Python.
3. Que gaps siguen abiertos en README, ejemplos y observabilidad.
4. Que calidad minima debe mantenerse para considerar ambas integraciones en parity sostenida.

---

## Alcance de parity

La parity de integracion se define en cinco dimensiones:

1. **Parity de API publica**
   Ambas integraciones deben exponer factories, helpers de contexto y tools equivalentes aunque respeten modismos del lenguaje.

2. **Parity de seguridad por defecto**
   Las exposiciones sensibles deben ser opt-in y la validacion de destinos HTTP debe comportarse de forma equivalente.

3. **Parity de observabilidad**
   Ambas integraciones deben emitir eventos saneados, permitir fan-out de handlers y soportar logging estructurado sin exponer secretos.

4. **Parity de ejemplos y operacion**
   Cada integracion debe tener ejemplos base, ejemplos de observabilidad y una receta mas cercana a produccion.

5. **Parity documental**
   README, docs de diseno y ejemplos deben describir capacidades equivalentes y dejar claros los gaps restantes.

---

## Referencias canonicas

- TS package: `integrations/langchain/`
- Python package: `integrations/langchain-python/`
- Diseno Python: `docs/F1-03-LangChain-Python-Integration-Design.md`
- Parity SDK core: `docs/F2-01-TS-Python-Parity-Matrix.md`

---

## Matriz actual

| Area | TypeScript | Python | Estado | Notas |
|---|---|---|---|---|
| Factory principal | `createAgentDidIntegration(...)` | `create_agent_did_langchain_integration(...)` | ✅ | Family parity mantenida. |
| Snapshot de identidad | `buildAgentDidIdentitySnapshot(...)` | `build_agent_did_identity_snapshot(...)` | ✅ | Campos equivalentes. |
| Inyeccion de contexto | `createAgentDidMiddleware(...)` + `buildAgentDidSystemPrompt(...)` | `compose_system_prompt(...)` + bundle method | ✅ | Diferente forma, mismo objetivo. |
| Tools basicas | identidad actual, resolve DID, verify signature | identidad actual, resolve DID, verify signature | ✅ | Parity funcional. |
| Tools sensibles opt-in | sign payload, sign HTTP, rotate key, history | sign payload, sign HTTP, rotate key, history | ✅ | Defaults endurecidos y alineados. |
| Seguridad HTTP | esquema valido, sin credenciales embebidas, bloqueo loopback/privado por defecto | esquema valido, sin credenciales embebidas, bloqueo loopback/privado por defecto | ✅ | TS alineado con Python. |
| Propagacion `http_security` al SDK | Validacion local en tool; no propaga opciones al SDK `signHttpRequest` | Propaga `HttpTargetValidationOptions` al SDK via `http_security` param cuando `allow_private_network_targets=True` | ⚠️ | Python adelanta a TS. TS debe propagar `httpSecurity` al SDK para parity completa. |
| Callback de observabilidad | `observabilityHandler` | `observability_handler` | ✅ | Eventos saneados en ambos paquetes. |
| Fan-out de handlers | `composeEventHandlers(...)` | `compose_event_handlers(...)` | ✅ | Vendor-neutral. |
| Logging JSON | `createJsonLoggerEventHandler(...)` | `create_json_logger_event_handler(...)` | ✅ | Misma estrategia de saneamiento. |
| Serializacion de eventos | `serializeObservabilityEvent(...)` | `serialize_observability_event(...)` | ✅ | Misma forma conceptual. |
| Ejemplo base | `agentDidLangChain.example.js` | `agent_did_langchain_example.py` | ✅ | Ambos muestran create_agent/createAgent + tools. |
| Ejemplo de observabilidad | `agentDidLangChain.observability.example.js` | `agent_did_langchain_observability_example.py` | ✅ | Parity operativa minima lograda. |
| Receta tipo produccion | `agentDidLangChain.productionRecipe.example.js` | `agent_did_langchain_production_recipe_example.py` | ✅ | Ambos usan guardas de entorno. |
| Demo integrado `did:wba` | `agentDidLangChain.didWbaDemo.example.js` | `agent_did_langchain_did_wba_demo.py` | ✅ | Ambos muestran runtime `did:wba`, partner remoto `did:wba`, `createAgent`/`create_agent` local y firma HTTP verificable sin credenciales externas. |
| Smoke cross-package `did:wba` | `npm run smoke:langchain-didwba` ejecuta el demo JavaScript publicado y valida su contrato JSON. | El mismo comando ejecuta el demo Python publicado y valida su contrato JSON en la misma corrida. | ✅ | Este smoke es gate de parity operativa entre ambos demos, no solo una conveniencia local. |
| Integracion LangSmith dedicada | `createLangSmithRunTree(...)` + `createLangSmithEventHandler(...)` | Adapter dedicado disponible | ✅ | Ambos paquetes exponen adaptador dedicado sin cambiar la factory principal. |
| Profundidad de suite automatizada | tests funcionales, seguridad y observabilidad | tests funcionales, seguridad, observabilidad y modulos internos | ⚠️ | Python sigue mas granular. |

---

## Quality Gates para parity de integracion

### TypeScript

1. `npm --prefix integrations/langchain test`
2. Ejemplos nuevos deben mantener guardas para no requerir credenciales accidentalmente.
3. Los eventos de observabilidad deben seguir saliendo saneados.

### Python

1. `python -m pytest integrations/langchain-python/tests -q`
2. `python -m ruff check integrations/langchain-python/src integrations/langchain-python/tests integrations/langchain-python/examples`
3. `python -m mypy integrations/langchain-python/src`

### Cross-integration

1. README de TS y Python deben describir el mismo modelo conceptual.
2. Los defaults de seguridad deben seguir alineados.
3. La taxonomia de eventos de observabilidad debe seguir equivalente.
4. Si se agrega un demo integrado relevante en una integracion, la otra debe ofrecer un demo equivalente o documentar explicitamente la divergencia.
5. Si cambia el contrato de salida o la ruta de ejecucion del demo integrado `did:wba`, el smoke cross-package y el walkthrough canonico deben actualizarse en el mismo cambio.

---

## Estado actual

### Logrado

1. Ya existe parity funcional de tools principales.
2. TS y Python comparten defaults de seguridad mas coherentes.
3. TS ya tiene observabilidad callback/logger saneada equivalente en intencion a Python.
4. TS ya tiene ejemplos adicionales para observabilidad y receta de produccion.
5. README y ejemplos de TS quedan alineados con la narrativa de Python.
6. TS y Python ya exponen demos integrados equivalentes para el flujo `did:wba` con resolucion web y firma HTTP verificable.
7. El repositorio ya tiene un smoke cross-package que ejecuta ambos demos y valida su contrato operativo compartido.

### Gaps abiertos no bloqueantes

1. Python mantiene una modularizacion interna mas fina que TS.
2. La suite TS aun es menos granular que la suite Python.

---

## Definicion de Done

La parity de integraciones LangChain TS vs Python se considera mantenida cuando:

1. Esta matriz sigue siendo correcta.
2. README y ejemplos de ambos paquetes describen capacidades equivalentes.
3. Los defaults de seguridad permanecen opt-in y alineados.
4. La observabilidad sigue saneando payloads, firmas, cuerpos HTTP y headers sensibles.
5. Nuevas capacidades de una integracion se portan a la otra o se documentan como excepcion explicita.

---

## Changelog

| Fecha | Cambio |
|-------|--------|
| 2026-03-22 | Se agregaron demos integrados `did:wba` equivalentes para LangChain TS y Python, junto con cobertura automatizada y referencias en README. La parity de ejemplos operativos se mantiene. |
| 2026-03-22 | Licencia del repositorio migrada de MIT a Apache-2.0. Actualizado `package.json` (langchain TS) y `pyproject.toml` (langchain-python). Sin cambios funcionales en la superficie de integración. |
| 2026-03-22 | Rename de scope npm: `@agent-did/langchain` → `@agentdid/langchain` y `@agent-did/sdk` → `@agentdid/sdk` para alinear con la organización npm `@agentdid`. Sin cambios en la API pública ni en la lógica funcional. |