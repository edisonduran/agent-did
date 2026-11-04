> **Historical document (archived by M-21, 2026-11).** Retained for context only; claims here may be stale. Current sources of truth: [INDEX](../INDEX.md), [External Conformance Matrix](../External-Conformance-Matrix.md).

# F1-03 - Diseno Complementario de Integracion LangChain Python

## Objetivo

Planear la variante Python de la integracion LangChain para Agent-DID, de forma consistente con la integracion JS ya implementada y apoyada en el SDK Python ya disponible.

El plan tecnico cerrado derivado de este diseno esta en [F1-03-LangChain-Python-Technical-Plan.md](F1-03-LangChain-Python-Technical-Plan.md).

## Estado actual

- Hito relacionado: F1-03 ya completado para la integracion LangChain JS
- Estado de esta variante: MVP funcional implementado
- Paquete base: [../integrations/langchain-python/README.md](../../integrations/langchain-python/README.md)
- Dependencia previa resuelta: SDK Python de Agent-DID (F2-01)
- Referencia funcional existente: [../integrations/langchain/README.md](../../integrations/langchain/README.md)

## Hallazgos de investigacion

La documentacion oficial actual de LangChain Python confirma estas superficies relevantes:

- `create_agent(...)` como entry point principal.
- `tools` para integrar funciones o capacidades externas.
- `system_prompt` y `messages` para contexto e inyeccion de identidad.
- `agent.invoke(...)` como flujo basico de ejecucion.
- runtime construido sobre LangGraph, lo que deja abierta la puerta a durabilidad, human-in-the-loop y persistence.
- LangSmith como camino de observabilidad y tracing.

## Principios de diseno

1. Paridad conceptual con la integracion JS existente.
2. Implementacion Python-first, construida sobre el SDK Python ya implementado.
3. Clave privada siempre encapsulada fuera del contexto del modelo.
4. Operaciones sensibles con opt-in explicito.
5. API pequena, clara y razonablemente equivalente entre lenguajes.

## Capacidades objetivo

- Exponer DID actual, controlador, capacidades y metadata verificable.
- Resolver documentos DID y verificar firmas desde tools reutilizables.
- Firmar payloads o solicitudes HTTP mediante opt-in.
- Inyectar identidad Agent-DID en el contexto del agente.
- Mantener la misma filosofia de seguridad por defecto que la integracion JS.

## Superficies de adaptacion esperadas

- `create_agent(...)` como punto de ensamblaje.
- tools custom para DID actual, resolucion, verificacion y firma.
- inyeccion de `system_prompt` o contexto inicial con identidad verificable.
- hooks de observabilidad via LangSmith cuando convenga trazar operaciones sensibles.

## API preliminar

```python
integration = create_agent_did_langchain_integration(
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

1. Factory principal del adaptador Python.
2. Toolkit Agent-DID para LangChain Python.
3. Inyeccion de identidad al contexto del agente.
4. Ejemplo runnable equivalente al paquete JS.
5. Suite automatizada de pruebas Python.

## Estado del MVP implementado

La implementacion actual ya entrega:

- factory publica `create_agent_did_langchain_integration(...)`
- snapshot de identidad sin secretos
- composicion de `system_prompt`
- tools para identidad actual, resolucion DID y verificacion de firmas
- firma HTTP opt-in
- firma de payload opt-in
- rotacion de claves opt-in
- rechazo por defecto de destinos HTTP privados o loopback
- pruebas funcionales y de seguridad del paquete

La readiness actual tambien incluye comandos locales y CI dedicado para el paquete.

## Riesgos tecnicos

- Riesgo de divergencia entre la API moderna de LangChain Python y la variante JS ya implementada.
- Posibles diferencias entre la API moderna de LangChain Python y la ya usada en JS.
- Riesgo de divergencia entre la variante Python y la JS si no se controla la API conceptual comun.

## Estado actual del bloqueo

El SDK Python ya no es un blocker.

La siguiente iteracion depende de trabajo de implementacion en `integrations/langchain-python/`, no de una dependencia externa pendiente. El checklist operativo esta en [F1-03-LangChain-Python-Implementation-Checklist.md](../F1-03-LangChain-Python-Implementation-Checklist.md).

## Recomendacion actual

La siguiente iteracion deberia centrarse en endurecimiento adicional, ejemplos mas ricos y observabilidad, manteniendo la paridad conceptual con JS sin introducir dependencias a APIs privadas de LangChain Python.

## Criterio de cierre

La variante Python de LangChain se considerara lista cuando exista un paquete funcional bajo `integrations/langchain-python/`, con ejemplo ejecutable, pruebas automatizadas y documentacion equivalente a la ya disponible en la integracion JS.