# agent-did-langchain

Scaffold de diseno para la integracion de Agent-DID con LangChain Python.

Importante: esta variante complementa la integracion ya implementada en TypeScript/JavaScript. El SDK Python ya existe; el trabajo pendiente ahora es implementar esta integracion sobre esa base.

## Estado

- Estado actual: `design-scaffold`
- Lenguaje objetivo: Python
- Dependencia previa resuelta: SDK Python de Agent-DID (F2-01)
- Relacion con roadmap: complemento Python de la integracion LangChain ya entregada en JS
- Implementacion: pendiente

Este directorio no contiene una integracion funcional todavia. Su objetivo actual es dejar documentada la forma esperada del adaptador Python y servir como punto de partida para la implementacion.

## Hallazgos tecnicos confirmados

La documentacion publica actual de LangChain Python confirma al menos estas superficies utiles:

- `create_agent(...)` como factory principal para agentes.
- `tools` como mecanismo nativo para exponer funciones al agente.
- `system_prompt` y `messages` como puntos base para inyectar identidad y contexto.
- `agent.invoke(...)` como interfaz directa de ejecucion.
- runtime construido sobre LangGraph, con soporte de durabilidad, streaming, human-in-the-loop y persistence en el ecosistema.
- LangSmith como camino recomendado para tracing y observabilidad.

## Objetivo

Crear una integracion Python para LangChain que replique el enfoque ya validado en JS:

- inyectar DID, controlador, capacidades y metadata verificable en el contexto del agente,
- exponer herramientas Agent-DID para resolucion, verificacion y firma opt-in,
- mantener la clave privada fuera del prompt y del estado visible al modelo,
- ofrecer una API de integracion pequena y consistente entre lenguajes.

## API conceptual propuesta

```python
from agent_did_langchain import create_agent_did_langchain_integration

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

La forma concreta del adaptador debera acoplarse a las primitivas oficiales de LangChain Python disponibles en el momento de implementarlo.

## Checklist operativo

La ejecucion del scaffold a paquete funcional esta desglosada en [../../docs/F1-03-LangChain-Python-Implementation-Checklist.md](../../docs/F1-03-LangChain-Python-Implementation-Checklist.md).

## Componentes previstos

- `pyproject.toml`: metadata del paquete Python.
- `src/agent_did_langchain/__init__.py`: factory principal y estado del scaffold.
- `src/agent_did_langchain/tools.py`: herramientas Agent-DID para LangChain Python.
- `src/agent_did_langchain/context.py`: inyeccion de identidad y system prompt.
- `src/agent_did_langchain/signing.py`: firma y verificacion segura.
- `tests/`: pruebas cuando exista implementacion funcional.

## Criterios de implementacion

1. Exponer DID actual, resolucion documental y verificacion de firmas mediante tools.
2. Permitir firma HTTP solo con opt-in explicito.
3. Mantener rotacion de claves y firma arbitraria deshabilitadas por defecto.
4. Inyectar identidad Agent-DID en el contexto del agente sin exponer secretos.
5. Incluir ejemplo runnable y pruebas automatizadas en Python.

## Referencias

- Integracion JS funcional: [../langchain/README.md](../langchain/README.md)
- Documento de diseno: [../../docs/F1-03-LangChain-Python-Integration-Design.md](../../docs/F1-03-LangChain-Python-Integration-Design.md)
- Documentacion oficial: https://docs.langchain.com/oss/python/langchain/overview