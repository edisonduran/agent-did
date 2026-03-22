# F2-05 - Rubrica de Madurez CrewAI vs LangChain

## Objetivo

Definir de forma explicita que significa considerar a CrewAI "tan maduro como LangChain" dentro de este repositorio.

Esta rubrica evita confundir:

1. integracion funcional,
2. gobernanza alineada,
3. madurez operativa comparable.

---

## Referencia canonica

La referencia de comparacion para CrewAI es la superficie combinada ya existente en:

- `integrations/langchain/`
- `integrations/langchain-python/`

Artefactos de apoyo:

- `docs/F1-03-LangChain-TS-Python-Integration-Parity-Matrix.md`
- `docs/F2-05-CrewAI-Maturity-Gap-Assessment.md`
- `docs/F2-05-CrewAI-Integration-Review-Checklist.md`

---

## Niveles de madurez

### Nivel 1 - Funcional

La integracion:

- expone una factory publica estable,
- ofrece tools reutilizables,
- mantiene defaults seguros,
- incluye pruebas basicas,
- y tiene documentacion suficiente para usarse correctamente.

### Nivel 2 - Operable

La integracion, ademas:

- emite observabilidad estructurada saneada,
- tiene CI dedicado,
- incluye ejemplos reproducibles,
- valida su contrato con el runtime host al menos en un smoke path,
- y mantiene checklists de implementacion y review.

### Nivel 3 - Comparable a LangChain

La integracion, ademas:

- mantiene una rubrica explicita de comparacion,
- cubre ejemplos base, observabilidad y receta production-style,
- separa la suite de pruebas por dominios,
- documenta cualquier divergencia intencional frente a LangChain,
- y deja las brechas restantes como no bloqueantes y explicitamente aceptadas.

---

## Dimensiones de comparacion

La comparacion se mantiene sobre cinco dimensiones:

1. seguridad por defecto
2. observabilidad y trazabilidad
3. realismo de runtime
4. cobertura operativa de ejemplos y pruebas
5. gobernanza y criterio explicito de madurez

---

## Matriz actual

| Dimension | LangChain | CrewAI | Estado | Notas |
|---|---|---|---|---|
| Factory publica | `createAgentDidIntegration(...)` y `create_agent_did_langchain_integration(...)` | `create_agent_did_crewai_integration(...)` | ✅ | Surface publica estable y documentada. |
| Tools basicas | identidad actual, resolve DID, verify signature | identidad actual, resolve DID, verify signature | ✅ | Parity funcional. |
| Tools sensibles opt-in | sign payload, sign HTTP, rotate key, history | sign payload, sign HTTP, rotate key, history | ✅ | Defaults endurecidos y alineados. |
| Seguridad HTTP | validacion de esquema, credenciales embebidas y targets privados/loopback | validacion equivalente | ✅ | Misma postura de seguridad. |
| Observabilidad estructurada | eventos saneados, fan-out, JSON logging, adaptadores adicionales | eventos saneados, fan-out, JSON logging | ✅ | CrewAI cubre la base operativa; LangChain mantiene mas profundidad opcional. |
| Runtime host validado | ejemplos y runtime de LangChain validados | smoke path real de CrewAI en CI | ✅ | CrewAI ya no es solo compatibilidad teorica. |
| Ejemplo base | si | si | ✅ | Wiring principal cubierto. |
| Ejemplo de observabilidad | si | si | ✅ | Callback y logging estructurado cubiertos. |
| Receta production-style | si | si | ✅ | CrewAI ya cubre guardas de entorno, outputs estructurados y signing. |
| Topologia de pruebas | funcional, seguridad, observabilidad y modulos internos | wiring, operaciones, seguridad, observabilidad y runtime smoke | ✅ | CrewAI ya no concentra la suite en archivos amplios. |
| Rubrica explicita de madurez | parity y referencias operativas existentes | rubrica dedicada en este documento | ✅ | El criterio de comparacion queda institucionalizado. |
| Integraciones de trazado avanzadas | mayor profundidad opcional | menor profundidad opcional | ⚠️ | Divergencia aceptable mientras siga documentada. |

---

## Quality Gates para sostener la madurez

### CrewAI

1. `python -m ruff check integrations/crewai/src integrations/crewai/tests integrations/crewai/examples`
2. `python -m mypy integrations/crewai/src integrations/crewai/tests`
3. `python -m pytest integrations/crewai/tests -q`
4. El CI debe mantener el smoke path real con `.[runtime]`.
5. README, diseño, assessment y checklist de review deben seguir consistentes.

### Decision de comparabilidad

CrewAI puede describirse como "comparable en madurez operativa a LangChain" mientras se mantenga lo siguiente:

1. la seguridad por defecto sigue siendo opt-in y coherente,
2. la observabilidad sigue saneando payloads, firmas, cuerpos y headers sensibles,
3. existe al menos una validacion automatizada con runtime real de CrewAI,
4. los ejemplos siguen cubriendo wiring base, observabilidad y recipe operativa,
5. cualquier divergencia restante se documenta como intencional y no como gap oculto.

---

## Divergencias aceptadas hoy

Las siguientes diferencias no bloquean la comparabilidad actual:

1. CrewAI no expone todavia un adaptador de tracing tan profundo como LangChain.
2. CrewAI concentra structured outputs y secure signing dentro de una recipe operativa, no en ejemplos aun mas atomizados.
3. La profundidad futura de tests internos debe responder al crecimiento real del paquete, no a una simetria artificial.

---

## Regla de mantenimiento

Si una nueva capacidad mueve el claim de madurez de CrewAI, se deben actualizar en la misma PR:

1. esta rubrica,
2. `docs/F2-05-CrewAI-Maturity-Gap-Assessment.md`,
3. `docs/F2-05-CrewAI-Integration-Review-Checklist.md`,
4. y el README de `integrations/crewai/`.