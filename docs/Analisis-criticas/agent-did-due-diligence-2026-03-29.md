# Due diligence técnica y estratégica — Agent-DID

**Proyecto analizado:** `edisonduran/Agent-citizen-identification`  
**Fecha:** 2026-03-29  
**Objetivo:** evaluar el proyecto como oportunidad técnica y estratégica, incluyendo comparables, calidad de implementación, riesgos y recomendaciones.

---

# 1. Resumen ejecutivo

🏷 **Proyecto:** Agent-DID (`edisonduran/Agent-citizen-identification`)  
⭐️ **Score general inicial:** **7.2/10**  
🎯 **Tesis:** busca resolver un problema real y subatendido: dar identidad verificable a agentes de IA que actúan autónomamente.  
📊 **Mercado:** infraestructura de identidad, seguridad y auditabilidad para agentes AI; mercado potencialmente grande, pero aún inmaduro y fragmentado.  
🔥 **Ventaja principal:** integra identidad verificable dentro de frameworks que ya usan los desarrolladores (LangChain, CrewAI, Semantic Kernel, Microsoft Agent Framework), en lugar de exigir un stack nuevo.  
⚠️ **Riesgo principal:** puede quedarse como una reference implementation técnicamente interesante pero sin adopción, especialmente si grandes vendors capturan esta capa con soluciones propietarias.  
✅ **Veredicto:** **INVESTIGAR MÁS**. No es humo, pero tampoco es todavía una apuesta obvia o madura.

## Conclusión corta

Agent-DID tiene una tesis fuerte, mejor ejecución técnica de la esperada y una arquitectura conceptualmente bien orientada. Sin embargo, todavía presenta señales claras de etapa temprana, con varios riesgos en interoperabilidad, gestión de claves, hardening de seguridad y semántica de producción.

En una frase:

> **No es humo, pero tampoco es todavía un ganador claro. Es un proyecto serio en fase temprana con potencial real, pero aún lejos de verse como infraestructura crítica madura.**

---

# 2. Qué hace el proyecto

Agent-DID se posiciona como una **capa de identidad criptográfica para agentes de IA**, construida sobre:

- **W3C DID**
- **Verifiable Credentials**
- **Ed25519**
- firma de requests HTTP
- resolución DID
- anclaje opcional on-chain o web-based (`did:wba`, `did:web`)

Además, busca insertarse como middleware dentro de frameworks agentic ya existentes:

- LangChain JS
- LangChain Python
- CrewAI
- Semantic Kernel
- Microsoft Agent Framework

## Tesis de producto

No intenta ser otro framework de agentes. Intenta convertirse en la **capa de identidad del stack agentic**:

- quién es este agente,
- qué puede hacer,
- cómo firmó esta acción,
- cómo revoco o actualizo su identidad,
- cómo audito su conducta.

Esa tesis es correcta y vale la pena tomarla en serio.

---

# 3. Lo que sí me gustó

## 3.1 El problema es real

Hoy la mayoría de agentes:

- usan credenciales humanas o compartidas,
- no tienen identidad portable,
- no dejan trazabilidad criptográfica fuerte,
- no tienen un modelo limpio de revocación,
- mezclan autenticación, autorización y runtime de forma improvisada.

Para casos como:

- agentes que llaman APIs sensibles,
- agentes que delegan tareas a otros agentes,
- entornos regulados,
- trazabilidad y accountability,

el problema es legítimo.

## 3.2 No parece humo puro

El repo muestra señales reales de trabajo:

- ~300 archivos
- SDK en TypeScript con código y tests
- SDK en Python con código y tests
- integraciones con múltiples frameworks
- smoke tests y scripts de conformance
- documentación extensa

Señales observadas:

- **11 tests TS**
- **16 tests Python**
- **38 archivos de código de integración**
- **37 documentos**

Conclusión: **sí hay sustancia técnica**.

## 3.3 Estrategia de integración bien pensada

En vez de pedirle al desarrollador adoptar un nuevo paradigma, el proyecto se inserta dentro de herramientas conocidas. Eso reduce fricción de adopción y es una buena decisión estratégica.

## 3.4 Enfoque híbrido “with or without blockchain”

Esto me parece acertado. Si obligara blockchain en todos los casos, sería mucho menos atractivo.

El enfoque híbrido:

- on-chain cuando se necesita inmutabilidad o revocación global,
- web-based cuando se busca baja fricción,

es bastante más pragmático.

---

# 4. Lo que me preocupa a nivel estratégico

## 4.1 Se ve temprano a pesar del empaque

El repositorio está muy bien presentado, pero observé:

- versión **0.1.0**
- Python marcado como **Alpha**
- historial visible muy corto
- pocas señales externas de adopción real

Eso suele significar:

- tesis fuerte,
- implementación inicial seria,
- pero todavía sin validación real de mercado.

## 4.2 Riesgo de “spec theater”

El proyecto habla como si estuviera construyendo un estándar consolidado. Pero por ahora parece más bien:

> **protocolo propuesto + reference implementation**

que estándar adoptado.

Tener un RFC propio y un compliance checklist propio **no equivale** a haber ganado interoperabilidad de mercado.

## 4.3 Riesgo brutal de mercado

Aunque la tesis sea correcta, esta capa puede ser capturada por grandes vendors:

- Microsoft (Entra + Agent Framework)
- Google (A2A / identidad federada)
- OpenAI / Anthropic (policy + runtime layers)
- vendors enterprise de IAM/PAM

El proyecto necesita una cuña clara para no quedar desplazado.

---

# 5. Proyectos similares encontrados

## 5.1 AgentID — `Pedroshakoor/Agent-ID`

GitHub: <https://github.com/Pedroshakoor/Agent-ID>

### Qué es

Capa de identidad para agentes con enfoque más enterprise y pragmático:

- identity provider
- credenciales cortas tipo JWT
- auditoría automática
- políticas y verificación
- integraciones con frameworks

### Comparación con Agent-DID

- más pragmático para enterprise,
- menos “self-sovereign / DID-purist”,
- más cercano a producto de seguridad operable,
- menos elegante como estándar abierto.

### Lectura

Si el comprador es empresa, AgentID puede tener mejor GTM.  
Si el objetivo es protocolo abierto e interoperable, Agent-DID tiene una narrativa conceptualmente más ambiciosa.

---

## 5.2 `dantber/agent-did`

GitHub: <https://github.com/dantber/agent-did>

### Qué es

Toolkit W3C DID + VC para agentes con:

- `did:key`
- credentials
- capability delegation
- revocation
- CLI

### Comparación con Agent-DID

- más pequeño y enfocado,
- más toolkit que plataforma,
- menos ambición de integrarse a múltiples frameworks.

### Lectura

Es el comparable open source más cercano conceptualmente.  
Agent-DID parece más ambicioso en integración; este se siente más limpio como toolkit base.

---

## 5.3 Attestix — `VibeTensor/attestix`

GitHub: <https://github.com/VibeTensor/attestix>

### Qué es

Infraestructura de attestation para agentes con:

- DID
- VCs
- compliance
- EU AI Act
- reputación
- herramientas MCP

### Comparación con Agent-DID

- más cargado hacia compliance,
- más ancho en alcance,
- menos puro como identity layer mínima.

### Lectura

Si el wedge comercial es compliance y regulación, Attestix puede tener una narrativa más inmediata.

---

## 5.4 EtereCitizen — `icaroholding/EtereCitizen`

GitHub: <https://github.com/icaroholding/EtereCitizen>

### Qué es

Protocolo de identidad + trust + commerce para agentes:

- DID
- reputación on-chain
- reviews
- pagos / comercio
- API + SDK + MCP

### Comparación con Agent-DID

- más ambicioso y más orientado a network effects,
- menos minimalista,
- más difícil de ejecutar.

### Lectura

Interesante, pero más complejo. Agent-DID está mejor enfocado si su ambición es ser capa técnica de identidad.

---

## 5.5 AIP — `The-Nexus-Guard/aip`

GitHub: <https://github.com/The-Nexus-Guard/aip>

### Qué es

Identity + trust chains + encrypted messaging para agentes.

### Comparación con Agent-DID

- más orientado a red descentralizada y mensajería segura,
- menos centrado en integraciones empresariales,
- más “agent network” que “identity middleware”.

### Lectura

Buen comparable si se piensa en confianza entre agentes, pero menos directo para enterprise infra.

---

## Ranking de comparables por cercanía

1. **AgentID**
2. **dantber/agent-did**
3. **Attestix**
4. **AIP**
5. **EtereCitizen**

---

# 6. Arquitectura real del proyecto

El repo tiene cuatro grandes bloques.

## 6.1 SDK TypeScript

Responsable de:

- crear Agent-DID documents,
- firma Ed25519,
- verificación,
- firma de requests HTTP,
- resolución DID,
- rotación de claves,
- historial documental.

## 6.2 SDK Python

Replica casi la misma superficie:

- create / sign / verify / resolve / revoke,
- resolver universal,
- adapters para EVM,
- tests y scripts de conformance.

## 6.3 Smart contract `AgentRegistry`

Contrato mínimo para:

- registrar DID,
- guardar `documentRef`,
- revocar,
- delegar revocación,
- transferir ownership.

## 6.4 Integraciones de framework

Se integra con:

- LangChain,
- CrewAI,
- Semantic Kernel,
- Microsoft Agent Framework.

## Lectura arquitectónica

Está bien pensado como **middleware de identidad** y no como reemplazo del runtime agentic. Eso es correcto.

---

# 7. Lo técnicamente bueno

## 7.1 Separación conceptual saludable

Separan:

- identidad,
- registro,
- resolución,
- firma,
- integraciones.

Eso evita que todo quede acoplado en una sola capa.

## 7.2 Esfuerzo real de paridad TS/Python

No es un repo donde Python es solo marketing. Existe SDK Python real con módulos, tests y fixtures de interoperabilidad.

## 7.3 Inserción en frameworks existentes

Desde producto técnico, esta es una decisión fuerte: reducir fricción de adopción al integrarse con herramientas que ya usan los desarrolladores.

## 7.4 Código real, no solo narrativa

El repositorio tiene una cantidad razonable de implementación efectiva en:

- `sdk/src`
- `sdk-python/src`
- `integrations/*/src`
- `contracts/src`

---

# 8. Problemas técnicos serios

Aquí está el núcleo del diagnóstico.

## 8.1 Interoperabilidad DID débil o incompleta

### Problema A: método `did:agent`

El SDK genera DIDs del tipo:

- `did:agent:<network>:<hash>`

Eso puede funcionar internamente, pero no es un DID method ampliamente reconocido como:

- `did:key`
- `did:web`
- `did:ethr`

Por tanto, la promesa de interoperabilidad queda debilitada si el método principal depende de un namespace propio.

### Problema B: `publicKeyMultibase` simplificado

En el código se observa una construcción equivalente a:

- `publicKeyMultibase: "z" + publicKeyHex`

Eso no parece una codificación multibase/multicodec rigurosa.  
Es una simplificación peligrosa.

### Impacto

El sistema puede funcionar dentro de su propio universo, pero no necesariamente será interoperable con tooling real del ecosistema DID/VC.

### Conclusión

La narrativa de estándar abierto parece ir por delante de la implementación real de interoperabilidad.

---

## 8.2 Modelo de claves todavía inmaduro

### Problema A: el SDK devuelve la private key al crear identidad

El método `create()` retorna:

- documento
- `agentPrivateKey`

Eso sirve para DX y demos, pero es una mala señal para producción.

En un sistema serio, la clave debería residir en:

- KMS
- HSM
- wallet seguro
- enclave
- proveedor de firma abstraído

### Problema B: `blockchainAccountId` decorativo o no controlable

En la implementación observada, ese campo se genera de forma que no necesariamente corresponde a una cuenta realmente controlada por el agente o su operador.

### Impacto

El documento puede declarar una cuenta blockchain que no representa una identidad operativa real.

### Conclusión

Para una capa de identidad seria, esto es una bandera roja.

---

## 8.3 Rotación de claves con posible problema de auditabilidad histórica

La rotación:

- añade un nuevo `verificationMethod`,
- reemplaza `authentication` para marcar solo la nueva clave como activa.

El problema es que la verificación parece depender de claves activas actuales.

### Riesgo

Firmas históricas hechas con claves anteriores podrían dejar de validarse correctamente después de una rotación.

### Impacto

Eso debilita directamente la propuesta de valor principal del sistema:

- trazabilidad,
- auditoría,
- accountability,
- no repudio razonable.

### Qué debería ocurrir

El sistema debería poder verificar:

> “esta firma fue válida con la clave que estaba activa en ese momento”

no solo:

> “esta firma coincide con la clave activa actual”.

---

## 8.4 Riesgo de replay en firmas HTTP

La firma HTTP cubre:

- request-target
- host
- date
- content-digest
- created timestamp

Eso está bien como base, pero no vi mecanismos robustos de:

- nonce único,
- jti,
- replay cache server-side,
- idempotency token firmado.

### Riesgo

Un request firmado capturado dentro de la ventana válida podría ser reusado.

### Conclusión

Control temporal sin anti-replay fuerte no es suficiente para operaciones sensibles.

---

## 8.5 Resolver “production” demasiado dependiente de fallback

El `UniversalResolverClient`:

- usa caché,
- consulta registry,
- busca document source,
- y cae a fallback.

Eso es razonable para disponibilidad, pero riesgoso en una capa de identidad.

### Problema

Si:

- falta `documentRef`,
- falla la fuente primaria,
- o el sistema cae a un resolver in-memory,

puede terminar resolviendo identidades a partir de estado local o alternativo, aunque la fuente principal esté inconsistente.

### Conclusión

En sistemas de confianza, el fallback no puede degradar silenciosamente la verdad del sistema.

---

## 8.6 `documentRef` y storage model flojamente acoplados

El `documentRef` se calcula como hash canónico del documento, pero eso no define por sí solo cómo recuperar el documento si no existe una fuente consistente detrás.

### Riesgo

Puede haber estados donde exista:

- DID registrado,
- referencia registrada,
- pero documento no resolvible.

### Conclusión

El modelo de storage/resolución aún no está totalmente cerrado como infraestructura fiable.

---

# 9. Evaluación del smart contract

## 9.1 Lo bueno

El contrato `AgentRegistry.sol` es simple y entendible. Para un MVP está razonablemente diseñado para:

- register
- revoke
- set document ref
- delegate revoke
- transfer ownership
- pause/unpause

## 9.2 Problemas

### Problema A: registro en dos pasos

El flujo actual es esencialmente:

1. registrar DID
2. registrar `documentRef`

Si la segunda transacción falla, el DID existe on-chain pero queda huérfano.

### Impacto

Produce estados inconsistentes y DIDs irre-solubles.

### Qué sería mejor

- operación atómica,
- commit/finalize robusto,
- o recovery flow explícito.

---

### Problema B: el contrato es demasiado mínimo para la promesa

La tesis del proyecto habla de:

- identidad verificable,
- revocación global,
- auditabilidad,
- accountability.

Pero el contrato actual es más bien un registry básico que una capa completa de policy o governance.

---

### Problema C: centralización administrativa

El contrato tiene:

- `admin`
- `pause()` / `unpause()`

No es necesariamente malo, pero debe explicarse bien porque choca con la estética de “self-sovereign / trustless” si no hay una narrativa clara de gobernanza.

---

# 10. Seguridad y hardening

## 10.1 Claim de SSRF protection no totalmente respaldada

El módulo HTTP en Python se describe como si tuviera protección SSRF, pero en el código observado el control visible se reduce básicamente a validar el esquema `http` / `https`.

No vi evidencia clara de hardening como:

- bloqueo de loopback,
- bloqueo de redes privadas,
- protección contra metadata endpoints,
- verificación DNS robusta,
- mitigación de rebinding.

### Conclusión

La claim pública parece más fuerte que la implementación mostrada.

---

## 10.2 Uso de estado global de clase

Tanto TS como Python usan estado compartido/global para:

- resolver,
- registry,
- history store.

### Problemas potenciales

- contaminación entre tenants,
- tests frágiles,
- comportamiento no aislado,
- problemas en entornos multi-agent.

### Conclusión

Para una librería seria de infraestructura, preferiría instancias explícitas y aislamiento por contexto.

---

## 10.3 Hygiene de repo mejorable

Se observaron artefactos como:

- `__pycache__`
- `.pyc`
- `.coverage`

Eso no rompe la seguridad por sí solo, pero reduce confianza en el proceso de release engineering.

En un proyecto de trust infrastructure, esos detalles importan.

---

# 11. Inconsistencias de producto / packaging

Observé inconsistencias como:

- licencia Apache en raíz,
- README Python indicando MIT,
- URLs de homepage/repository inconsistentes,
- naming mezclado entre repo y producto.

### Lectura

Esto transmite una mezcla de:

- buen empuje técnico,
- pero gobernanza y packaging todavía inmaduros.

Para un proyecto cuyo valor es confianza, la consistencia externa importa mucho.

---

# 12. Juicio sobre calidad del código

## Lo positivo

El código no parece improvisado al nivel hackathon. Sí hay:

- estructura modular,
- nomenclatura razonable,
- tests,
- documentación,
- esfuerzo de diseño.

## Lo negativo

Donde baja la nota es en factores críticos para esta categoría:

- simplificaciones criptográficas peligrosas,
- claims de interoperabilidad algo inflados,
- lifecycle de claves todavía inmaduro,
- storage/resolution model incompleto,
- semántica de producción todavía borrosa.

---

# 13. Riesgos criptográficos / de diseño más importantes

## Riesgo 1 — Interoperabilidad falsa o incompleta

Parece DID-compatible, pero algunos detalles sugieren que la compatibilidad real con tooling externo no está cerrada.

## Riesgo 2 — Auditabilidad incompleta tras rotación

Si firmas históricas dejan de validarse tras rotar claves, se rompe parte esencial de la tesis.

## Riesgo 3 — Replay en HTTP signatures

Falta protección anti-replay más robusta.

## Riesgo 4 — Declaraciones de identidad parcialmente decorativas

Si `blockchainAccountId` no representa una cuenta controlable, el documento pierde credibilidad.

## Riesgo 5 — Orfandad entre registry y document storage

Muy probable si el flujo on-chain/off-chain falla a mitad.

---

# 14. Qué tendría que corregir para verse invertible o presentable

## Prioridad 1 — Corregir la capa de identidad

### Deben hacer

- definir rigurosamente el DID method principal,
- o apoyarse más en métodos existentes (`did:key`, `did:web`, `did:ethr`),
- codificar `publicKeyMultibase` correctamente,
- aclarar qué es estándar y qué es extensión propia.

### Por qué importa

Sin esto, la claim de interoperabilidad queda débil.

---

## Prioridad 2 — Profesionalizar custodia de claves

### Deben hacer

- no devolver private keys por defecto,
- soportar signer abstractions,
- integrar KMS/HSM/wallet providers,
- separar explícitamente demo mode de production mode.

### Por qué importa

Es obligatorio si quieren vender seguridad enterprise.

---

## Prioridad 3 — Arreglar verificación histórica y rotación

### Deben hacer

- permitir verificación de firmas históricas,
- versionar vigencia temporal de `verificationMethod`,
- distinguir clave activa actual vs clave válida al momento de firmar.

### Por qué importa

Sin eso, el “audit trail” queda conceptualmente roto.

---

## Prioridad 4 — Endurecer HTTP signing

### Deben hacer

- nonce o `jti` por request,
- anti-replay store,
- expiraciones cortas explícitas,
- guidance server-side para verificación robusta.

---

## Prioridad 5 — Hacer atómico el registro on-chain

### Deben hacer

- registro + `documentRef` en una sola operación,
- o flujo commit/finalize,
- o modelo donde el documento sea resoluble sin depender de un segundo write frágil.

---

## Prioridad 6 — Resolver de verdad el storage model

### Deben hacer

- especificar fuente canónica del DID document,
- política clara de resolución,
- consistencia entre hash, URL, IPFS, RPC y caché,
- semántica precisa de fallback.

---

## Prioridad 7 — Hardening real

### Deben hacer

- SSRF hardening real,
- tests de seguridad más agresivos,
- threat model público,
- auditoría externa.

---

## Prioridad 8 — Limpiar producto y release engineering

### Deben hacer

- licencias consistentes,
- URLs correctas,
- packaging limpio,
- sin `__pycache__`, `.coverage`, `.pyc`,
- naming consistente entre repo, packages y protocolo.

---

# 15. Qué tan cerca está de “production ready”

Mi escala estimada:

- **Idea:** 8.5/10
- **Arquitectura conceptual:** 7.5/10
- **Calidad de implementación MVP:** 7/10
- **Rigor criptográfico / interoperabilidad:** 5.5/10
- **Seguridad production-grade:** 5/10
- **Packaging / governance / distribución:** 5/10

## Nota global técnica

**6.4/10**

### Interpretación

No significa que el proyecto sea malo. Significa:

> **interesante, serio y prometedor, pero todavía no listo para tratarse como infraestructura crítica madura.**

---

# 16. Conclusión estratégica final

## Lo que sí es

- un proyecto técnicamente serio,
- con una tesis real,
- con más profundidad que el promedio,
- con potencial como middleware de identidad para agentes.

## Lo que todavía no es

- un estándar consolidado,
- una capa criptográfica madura,
- una infraestructura enterprise lista para alta confianza.

## Lectura honesta

No lo descartaría. Pero tampoco lo vendería hoy como “la capa definitiva de identidad para agentes”.

La formulación correcta sería:

> **Reference implementation prometedora de identidad verificable para agentes, con buena arquitectura y ambición correcta, pero todavía necesitada de más rigor en interoperabilidad, key management y hardening de producción.**

---

# 17. Recomendación como oportunidad

## Clasificación

**Seguimiento activo**, no convicción alta todavía.

## Señales que me harían subirlo de categoría

- auditoría externa criptográfica o de contrato,
- integración con un caso real enterprise,
- packages publicados con adopción,
- corrección de problemas de interoperabilidad,
- signer/KMS abstraction seria,
- verificación histórica bien resuelta,
- storage/resolver semantics sólidas.

## Mayor upside

Si logra convertirse en:

> **la capa neutral de identidad y auditabilidad entre frameworks de agentes**,

hay valor real.

## Mayor riesgo

Que el mercado termine resolviendo este problema con:

- IAM enterprise adaptado a agentes,
- tokens efímeros + policy engines,
- identidad propietaria embebida por proveedores,

sin necesidad de un stack DID abierto.

---

# 18. Veredicto final en una línea

> **Agent-DID merece seguimiento serio: el problema es real y la arquitectura promete, pero todavía está más cerca de una reference implementation ambiciosa que de una infraestructura de identidad verdaderamente madura.**
