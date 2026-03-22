# F2-09 - Diseno de Integracion con Microsoft Agent Framework

## Objetivo

Definir una integracion de Agent-DID para Microsoft Agent Framework que reproduzca la postura de seguridad y la profundidad operativa ya alcanzadas en las otras integraciones Python del repositorio: identidad verificable, tools nativas del host, workflows reutilizables y observabilidad especializada sin exponer secretos al modelo.

## Estado actual

- Roadmap item: F2-09
- Estado: integracion funcional Python
- Paquete base: [../integrations/microsoft-agent-framework/README.md](../integrations/microsoft-agent-framework/README.md)
- Dependencia base: `agent-framework>=1.0.0rc5,<1.1`
- Superficie publica confirmada: `Agent`, `FunctionTool`, `AgentExecutor`, `WorkflowBuilder`, `Workflow.run(...)` y `AgentSession`
- Decision actual: implementar en Python sobre el SDK Python existente de Agent-DID y validar el host real mediante clientes stub locales para runtime y orquestacion

## Hallazgos de investigacion

La documentacion oficial consultada confirma que Microsoft Agent Framework ofrece estas piezas relevantes para una integracion Agent-DID:

- `Agent` como host principal con `instructions`, `tools` y `run(...)`.
- `tool(...)` como mecanismo nativo para proyectar funciones Python al runtime.
- `AgentExecutor` como wrapper reusable para orquestacion.
- `WorkflowBuilder` para componer grafos o cadenas de agentes y ejecutores.
- `Workflow.run(...)` como superficie verificable para ejecutar workflows sin credenciales de modelo cuando se usa un cliente stub local.
- `AgentSession` para continuidad conversacional y recipes production-style.
- observabilidad nativa basada en OpenTelemetry.

## Principios de diseno

1. Python-first y sin suposiciones sobre otros lenguajes en esta fase.
2. Seguridad por defecto: ninguna operacion sensible habilitada sin opt-in explicito.
3. Clave privada siempre encapsulada fuera del prompt y del contexto visible al modelo.
4. Surface pequena y estable: factory principal, tools nativas, helper de `Agent`, helper de `AgentExecutor` y helper de `WorkflowBuilder`.
5. Evidencia automatizada de runtime y orquestacion antes de cerrar cualquier claim de madurez.

## Capacidades objetivo

- Exponer DID actual, controlador, capacidades y clave activa.
- Resolver documentos DID y verificar firmas.
- Firmar payloads y solicitudes HTTP mediante opt-in.
- Consultar historial documental.
- Soportar rotacion de claves como operacion administrativa deshabilitada por defecto.
- Encadenar agentes en workflows sin perder continuidad de identidad ni de observabilidad.

## Superficies de adaptacion implementadas

- `FunctionTool` nativas de Agent Framework para las operaciones Agent-DID.
- `Agent` con instructions compuestas e identidad verificable.
- `AgentExecutor` para adaptar agentes a orquestaciones.
- `WorkflowBuilder` y `build_workflow_chain(...)` para runtime multi-step.
- observabilidad saneada con logging JSON y adaptador OpenTelemetry.

## Riesgos tecnicos

- La API del framework sigue siendo prerelease y puede cambiar sus hooks.
- Los flujos de workflow pueden diferir entre host local stub y proveedores reales.
- Las herramientas siguen dependiendo de que el cliente del host soporte o no function invoking para el loop LLM completo; por eso la cobertura gobernada valida wiring, secuencia de workflow y continuity, no reasoning/tool-calling de un proveedor externo.

## Criterio de cierre

F2-09 se considera implementado con cierre operativo cuando existan simultaneamente:

1. paquete funcional bajo `integrations/microsoft-agent-framework/`
2. runtime coverage real de `Agent`, `AgentExecutor` y `WorkflowBuilder`
3. recipes operativas profundas y ejecutables
4. observabilidad especializada con OpenTelemetry y pruebas de redaccion
5. CI dedicada y artefactos de gobernanza alineados

## Artefactos de control

- Checklist de implementacion: `docs/F2-09-Microsoft-Agent-Framework-Implementation-Checklist.md`
- Checklist de review: `docs/F2-09-Microsoft-Agent-Framework-Integration-Review-Checklist.md`
- Matriz de paridad: `docs/F2-09-Microsoft-Agent-Framework-Parity-Matrix.md`
- Evaluacion de brecha de madurez: `docs/F2-09-Microsoft-Agent-Framework-Maturity-Gap-Assessment.md`