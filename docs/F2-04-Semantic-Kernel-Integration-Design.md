# F2-04 - Diseno de Integracion con Semantic Kernel

## Objetivo

Definir una integracion de Agent-DID para Semantic Kernel que reproduzca las capacidades ya implementadas en LangChain: identidad inyectada al runtime, herramientas verificables y firma segura sin exponer la clave privada al modelo.

## Estado actual

- Roadmap item: F2-04
- Estado: integracion funcional Python
- Paquete base: [../integrations/semantic-kernel/README.md](../integrations/semantic-kernel/README.md)
- Referencia funcional existente: [../integrations/langchain/README.md](../integrations/langchain/README.md)
- Superficie publica confirmada: `Kernel`, `KernelPlugin`, `Kernel.invoke(...)` y `ChatCompletionAgent`
- Decision actual: implementar en Python sobre el SDK Python existente de Agent-DID y validar el host real mediante `semantic-kernel`

## Hallazgos de investigacion

La documentacion oficial consultada confirma que Semantic Kernel ofrece estas piezas relevantes para una integracion Agent-DID:

- `Kernel` como host principal de plugins y funciones.
- `KernelPlugin` para agrupar tools Agent-DID en una superficie reusable.
- `kernel_function(...)` y `KernelFunctionFromMethod` para proyectar callables Python tipados al runtime.
- `Kernel.invoke(...)` como superficie verificable para ejecutar tools sin depender de una sesion LLM completa.
- `ChatCompletionAgent` como host agentico compatible para recipes operativas y smoke tests.

## Restriccion actual de lenguaje

Aunque Semantic Kernel tiene presencia multi-language, en este repositorio la ruta validada y gobernada para F2-04 es Python. La evidencia implementada y probada esta concentrada en:

- el paquete Python publicado en `integrations/semantic-kernel/`,
- el smoke test de runtime real sobre `semantic-kernel`,
- las recipes operativas del paquete y su CI dedicada.

Por eso, F2-04 no debe asumirse como un paquete JavaScript por defecto. La decision actual del proyecto es implementarlo en Python, con compatibilidad real verificada contra el host `semantic-kernel`.

## Principios de diseno

1. Paridad funcional con la integracion de LangChain cuando la API del framework lo permita.
2. Seguridad por defecto: ninguna operacion sensible habilitada sin opt-in explicito.
3. Clave privada siempre encapsulada fuera del contexto del modelo.
4. Superficie pequena y estable, con una factory principal y herramientas auxiliares.
5. Compatibilidad con escenarios single-agent y multi-agent.

## Capacidades objetivo

- Exponer DID actual, controlador, capacidades y clave activa.
- Resolver documentos DID y verificar firmas.
- Firmar payloads o solicitudes HTTP cuando el host lo habilite.
- Consultar historial documental.
- Soportar rotacion de claves como operacion administrativa, deshabilitada por defecto.

## Superficies de adaptacion esperadas

- Registro de herramientas o funciones.
- Plugins y funciones del runtime.
- Enriquecimiento del contexto de sesion o conversation state.
- Intercepcion opcional de mensajes salientes para firma/verificacion a nivel de host.
- Integracion con `ChatCompletionAgent` como superficie runnable de referencia.
- Integracion con observabilidad saneada para trazabilidad empresarial.

## API publica

```python
integration = createAgentDidSemanticKernelIntegration(
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

plugin = integration.create_semantic_kernel_plugin(plugin_name="agent_did")
```

## Entregables esperados

1. Factory principal del adaptador.
2. Mapeo de herramientas Agent-DID al mecanismo nativo del framework.
3. Inyeccion de identidad al contexto del agente.
4. Ejemplo runnable equivalente al de LangChain.
5. Suite de pruebas automatizadas.
6. Uso del SDK Python de Agent-DID como dependencia base.

## Riesgos tecnicos

- Cambios en la API estable del framework.
- Diferencias entre flujos single-agent y orchestration multi-agent.
- Ambiguedad entre herramientas del runtime y capacidades del modelo.
- Necesidad de versionar el adaptador si el framework cambia sus hooks.


## Recomendacion actual

La siguiente iteracion de F2-04 puede centrarse en endurecimiento y validacion de runtime real, no en scaffold adicional. El adaptador Python para tools, plugins, contexto y observabilidad ya existe; el siguiente trabajo natural es ampliar recipes operativas o smoke tests contra superficies mas profundas del host `semantic-kernel`.

## Criterio de cierre

F2-04 se considerara implementado cuando exista un paquete funcional bajo `integrations/semantic-kernel/`, con ejemplo ejecutable, pruebas automatizadas y documentacion de uso equivalente a la ya disponible en LangChain.

## Artefactos de control

- Checklist de implementacion: `docs/F2-04-Semantic-Kernel-Implementation-Checklist.md`
- Checklist de review: `docs/F2-04-Semantic-Kernel-Integration-Review-Checklist.md`