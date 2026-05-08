# Estrategia de Divulgacion de 2 Semanas — Agent-DID

## Estado

Documento de preparacion para un proyecto todavia pre-adopcion. No asume una audiencia existente ni una base de usuarios activa.

## Principio de trabajo

En el estado actual, la meta no es "anunciar el pivote" de forma amplia. La meta es dejar lista una presencia minima, coherente y reutilizable para cuando aparezca alguno de estos triggers:

- primer hilo externo donde el pivote cambie expectativas tecnicas
- primera demo publica activa con algo concreto que mostrar
- primer feedback inbound relevante
- release candidate o ventana real de evaluacion externa

Hasta que exista uno de esos triggers, la estrategia correcta es preparacion silenciosa + siembra dirigida.

## Objetivos de Fase 6

1. Unificar el mensaje canonico del proyecto y del pivote.
2. Dejar listas las superficies minimas de descubribilidad.
3. Tener drafts reutilizables para Discussion y outreach corto sin necesidad de improvisar.
4. Definir criterios explicitos para saber cuando vale la pena comunicar en abierto.

## No objetivos

- No hacer anuncio masivo en redes por el solo hecho de haber terminado una fase interna.
- No comunicar el pivote como si hubiera usuarios previos que necesiten migracion inmediata.
- No abrir un ciclo de outreach generalista antes de tener validacion, demo o feedback externo real.

## Mensaje canonico

Agent-DID no se presenta como un metodo DID nuevo. Se presenta como un patron de aplicacion sobre `did:webvh` para identidad de agentes, composicion agent-controller y autenticacion runtime.

El mensaje externo debe mantener tres limites:

1. `did:webvh` es el camino canonico y recomendado.
2. EVM/on-chain queda diferido fuera del core 1.0; no se presenta como perfil activo ni como piso normativo.
3. Agent-DID prueba identidad/delegacion y parte de la autorizacion; no prueba por si solo la correccion del razonamiento interno del agente.

## Superficies minimas a dejar listas

1. README alineado con el posicionamiento actual.
2. Changelog/RFC/ADR consistentes entre si.
3. Runbooks y smokes demostrables para enseñar algo real, no solo narrativa.
4. Draft de GitHub Discussion listo pero sin publicar hasta trigger.
5. Draft de outreach corto listo pero sin publicar hasta trigger.

## Secuencia recomendada

### Semana 1 — Preparacion silenciosa

1. Consolidar FAQ corta del pivote.
2. Revisar que README, changelog, ADR y docs no se contradigan.
3. Preparar borrador de Discussion largo.
4. Preparar version corta para X/LinkedIn.

### Semana 2 — Siembra dirigida

1. Revisar issues, PRs o conversaciones externas ya activas donde el cambio sea relevante.
2. Comentar solo donde el mensaje aporte contexto tecnico real.
3. Registrar respuestas o preguntas repetidas para refinar FAQ y posicionamiento.

## Gates para pasar a comunicacion abierta

No abrir outreach amplio hasta que se cumpla al menos uno:

- existe demo publica o artefacto facil de evaluar
- hay al menos una conversacion externa activa que justifique centralizar contexto
- hay release candidate o ventana explicita de feedback
- existe interes inbound suficiente para que un Discussion publico tenga valor de referencia

## Acciones permitidas antes del gate

- comentarios tecnicos puntuales en hilos ya activos
- respuestas a feedback inbound
- preparacion de borradores y FAQs
- ordenamiento de docs y superficies del repo

## Acciones a diferir hasta despues del gate

- post general en GitHub Discussions como anuncio amplio
- notas de outreach abiertas en X/LinkedIn
- difusion a listas amplias de integradores sin contexto previo

## Criterio de exito

Fase 6 se considera bien ejecutada si al cerrar esta etapa:

1. el proyecto tiene mensaje coherente y reusable
2. no se forza una campana publica sin audiencia
3. existe un plan claro para convertir el primer trigger externo en visibilidad util
4. las primeras interacciones externas pueden responderse con materiales ya listos