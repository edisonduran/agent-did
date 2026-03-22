# F2-05 - Diseno de Integracion con CrewAI

## Objetivo

Consolidar una integracion de Agent-DID para CrewAI orientada a Python, alineada con las superficies publicas del framework y ya implementada sobre el SDK Python existente de Agent-DID.

## Estado actual

- Roadmap item: F2-05
- Estado: integracion funcional con toolkit de tools, observabilidad estructurada, callbacks, guardrails y outputs estructurados
- Paquete base: [../integrations/crewai/README.md](../integrations/crewai/README.md)
- Referencia funcional existente: [../integrations/langchain/README.md](../integrations/langchain/README.md)
- Decision actual: mantener la cobertura funcional sobre tools, callbacks, guardrails y helpers explicitos de `Agent`, `Task` y `Crew`

## Hallazgos de investigacion

La documentacion oficial de CrewAI confirma piezas relevantes para una integracion Agent-DID:

- `Agent` como unidad principal con memoria, tools, razonamiento, knowledge sources y callbacks por paso.
- `Task` con herramientas por tarea, contexto entre tareas, callbacks, guardrails y outputs estructurados.
- `Crew` con memoria compartida, callbacks de task/step, planning, streaming, usage metrics y output logs.
- `BaseTool` y `@tool` para herramientas custom sync y async.
- `kickoff()`, `kickoff_async()`, `akickoff()` y variantes por lote para ejecucion.
- replay CLI y logs para observabilidad y reproducibilidad.

## Principios de diseno

1. Implementacion Python-first.
2. Paridad conceptual con la integracion de LangChain donde sea posible.
3. Clave privada siempre encapsulada fuera del contexto del modelo.
4. Operaciones sensibles siempre bajo opt-in.
5. Integracion nativa con tools, callbacks, guardrails y outputs estructurados.

## Capacidades objetivo

- Exponer DID actual, controlador, capacidades y clave activa.
- Resolver documentos DID y verificar firmas desde tools reutilizables.
- Firmar payloads o solicitudes HTTP mediante herramientas opt-in.
- Emitir eventos estructurados Agent-DID para tool lifecycle, snapshots y callbacks saneados.
- Adjuntar trazabilidad Agent-DID a callbacks de task o step.
- Reforzar outputs con guardrails o validaciones basadas en firma y estructura.

## Superficies de adaptacion esperadas

- `BaseTool` o `@tool` para operaciones Agent-DID.
- `step_callback` y `task_callback` para auditoria.
- `guardrail` y `guardrails` para validar salidas sensibles.
- `output_json` y `output_pydantic` para contratos de salida verificables.
- `memory`, `context` y `knowledge_sources` como puntos de enriquecimiento no secreto.

## API preliminar

```python
integration = create_agent_did_crewai_integration(
    agent_identity=agent_identity,
    runtime_identity=runtime_identity,
    expose={
        "sign_http": True,
        "verify_signatures": True,
        "sign_payload": False,
        "rotate_keys": False,
        "document_history": True,
    },
)
```

## Entregables esperados

1. Factory principal del adaptador.
2. Toolkit Agent-DID para CrewAI.
3. Integracion con observabilidad estructurada, callbacks y logging saneado.
4. Guardrails opcionales para validar outputs y firmas.
5. Helpers explicitos para `Agent`, `Task` y `Crew`.
6. Outputs estructurados reutilizables para `output_pydantic`.
7. Ejemplo runnable con wiring compatible con `Agent`, `Task` y `Crew`.
8. Suite automatizada de pruebas Python y validacion de build.
9. Smoke path opcional contra runtime real de CrewAI dentro del CI soportado.

## Riesgos tecnicos

- Diferencias entre tool-level integration y callback-level auditing.
- Riesgo de duplicar contexto sensible en memoria o logs si no se controla bien.
- Posible necesidad de separar integracion para `Agent.kickoff()` directa vs `Crew.kickoff()`.

## Recomendacion actual

La siguiente iteracion de F2-05 ya no es cerrar el paquete base, sino cerrar los gaps operativos restantes respecto de LangChain: una suite de pruebas aun mas granular y una rubrica de madurez mas explicita. La validacion con runtime real de CrewAI ya queda cubierta por un smoke path dedicado en CI sobre Python 3.12, y la cobertura de ejemplos ya incluye wiring base, observabilidad y una receta production-style.

## Criterio de cierre

F2-05 se considera implementado en el alcance actual del repo: existe un paquete funcional bajo `integrations/crewai/`, con ejemplo ejecutable, helpers de `Agent`/`Task`/`Crew`, pruebas automatizadas, validacion de build y documentacion de uso equivalente a la ya disponible en LangChain.

## Artefactos de control

- Checklist de implementacion: `docs/F2-05-CrewAI-Implementation-Checklist.md`
- Checklist de review: `docs/F2-05-CrewAI-Integration-Review-Checklist.md`
- Evaluacion de madurez y gaps restantes: `docs/F2-05-CrewAI-Maturity-Gap-Assessment.md`