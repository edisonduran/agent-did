# F2-01 — Python SDK Blueprint & Construction Checklist

**Tipo:** Guía de construcción (GPS)  
**Proyecto:** Agent-citizen-identification  
**Feature:** F2-01 — SDK Python con paridad de funcionalidad  
**Fecha de creación:** 2026-03-21  
**Última actualización:** 2026-03-21  
**Referencia base:** SDK TypeScript (`sdk/`) v0.1.0 — 52 tests, 11/11 MUST, 5/5 SHOULD  

---

## 0. Índice rápido

| Sección | Contenido |
|---------|-----------|
| [1](#1-objetivo-y-alcance) | Objetivo y alcance |
| [2](#2-decisiones-de-diseño) | Decisiones de diseño |
| [3](#3-estructura-de-paquete) | Estructura del paquete |
| [4](#4-dependencias-python) | Dependencias Python |
| [5](#5-mapeo-de-módulos-ts--python) | Mapeo de módulos TS → Python |
| [6](#6-checklist-de-construcción) | **CHECKLIST DE CONSTRUCCIÓN** (el GPS) |
| [7](#7-api-pública-de-referencia) | API pública de referencia |
| [8](#8-mapeo-de-tests) | Mapeo de tests |
| [9](#9-vectores-de-interoperabilidad) | Vectores de interoperabilidad |
| [10](#10-criterios-de-aceptación-globales) | Criterios de aceptación |
| [11](#11-notas-de-implementación) | Notas de implementación |
| [12](#12-desbloqueos) | Qué desbloquea este SDK |

---

## 1. Objetivo y alcance

Construir un SDK Python que ofrezca **paridad funcional completa** con el SDK TypeScript, cumpliendo todos los controles RFC-001. Este SDK:

1. Permite crear, firmar, resolver, verificar y revocar Agent-DIDs desde Python.
2. Soporta HTTP Bot Auth (IETF HTTP Message Signatures).
3. Se conecta al mismo smart contract `AgentRegistry.sol` vía Web3.py.
4. Comparte los mismos **vectores de interoperabilidad** que el SDK TS para garantizar cross-language compatibility.
5. Desbloquea las integraciones Python: LangChain-Python, CrewAI, Semantic Kernel.

**Fuera de alcance (por ahora):**
- ZKP para verificación de capabilities (F3-03).
- Integración directa con frameworks de agentes (son features separadas).
- CLI tool (puede ser post-MVP).

---

## 2. Decisiones de diseño

| Decisión | Elección | Justificación |
|----------|----------|---------------|
| **Python mínimo** | 3.10+ | Soporte nativo de `match`, `ParamSpec`, `TypeAlias`, `dataclasses(slots)` |
| **Modelos de datos** | Pydantic v2 | Validación, serialización JSON, inmutabilidad, documentación automática de schema |
| **Criptografía Ed25519** | `PyNaCl` (libsodium binding) | Determinista, rápida, misma curva que `@noble/curves`. Alternativa: `cryptography` |
| **SHA-256** | `hashlib` (stdlib) | Sin dependencia externa |
| **Keccak-256** | `pysha3` o `eth-hash[pycryptodome]` | Para generar DIDs compatibles con EVM |
| **EVM interaction** | `web3.py` v6+ | Equivalente a `ethers.js` — firmas, contratos, providers |
| **HTTP client** | `httpx` (async) | Async-first, equivalente a `fetch()`. Soporte sync también |
| **Async pattern** | `async/await` nativo | Todas las operaciones I/O son async; se puede usar `asyncio.run()` como facade sync |
| **Testing** | `pytest` + `pytest-asyncio` | Estándar de la industria Python |
| **Build/Publish** | `pyproject.toml` + `hatchling` | PEP 621 moderno, sin `setup.py` |
| **Nombre del paquete** | `agent-did-sdk` (PyPI: `agent-did-sdk`) | Consistente con `@agent-did/sdk` en npm |
| **Multibase encoding** | `bases` o manual z-prefix + hex | Para claves públicas Ed25519 |

---

## 3. Estructura de paquete

```
sdk-python/
├── pyproject.toml                    # PEP 621 metadata + dependencies
├── README.md
├── LICENSE
├── src/
│   └── agent_did_sdk/
│       ├── __init__.py               # Re-exports (API pública)
│       ├── py.typed                  # PEP 561 marker
│       │
│       ├── core/
│       │   ├── __init__.py
│       │   ├── types.py              # Pydantic models (AgentDIDDocument, etc.)
│       │   ├── identity.py           # AgentIdentity class
│       │   └── time_utils.py         # Timestamp normalization
│       │
│       ├── crypto/
│       │   ├── __init__.py
│       │   └── hash.py               # hash_payload, format_hash_uri, generate_agent_metadata_hash
│       │
│       ├── registry/
│       │   ├── __init__.py
│       │   ├── types.py              # AgentRegistry protocol, AgentRegistryRecord
│       │   ├── evm_types.py          # EvmAgentRegistryContract protocol, EvmTxResponse
│       │   ├── in_memory.py          # InMemoryAgentRegistry
│       │   ├── evm_registry.py       # EvmAgentRegistry adapter
│       │   └── web3_client.py        # Web3AgentRegistryContractClient (≈ EthersClient)
│       │
│       └── resolver/
│           ├── __init__.py
│           ├── types.py              # DIDResolver protocol, DIDDocumentSource protocol
│           ├── in_memory.py          # InMemoryDIDResolver
│           ├── universal.py          # UniversalResolverClient
│           ├── http_source.py        # HttpDIDDocumentSource
│           └── jsonrpc_source.py     # JsonRpcDIDDocumentSource
│
└── tests/
    ├── conftest.py                   # Shared fixtures
    ├── fixtures/
    │   └── interop-vectors.json      # MISMO archivo que sdk/tests/fixtures/
    │
    ├── test_identity.py              # ≈ AgentIdentity.test.ts
    ├── test_crypto.py                # ≈ crypto.test.ts
    ├── test_time.py                  # ≈ time.test.ts
    ├── test_in_memory_registry.py    # ≈ EvmAgentRegistry.test.ts (in-memory part)
    ├── test_evm_registry.py          # ≈ EvmAgentRegistry.test.ts
    ├── test_web3_client.py           # ≈ EthersAgentRegistryContractClient.test.ts
    ├── test_in_memory_resolver.py
    ├── test_universal_resolver.py    # ≈ UniversalResolverClient.test.ts
    ├── test_http_source.py           # ≈ HttpDIDDocumentSource.test.ts
    ├── test_jsonrpc_source.py        # ≈ JsonRpcDIDDocumentSource.test.ts
    ├── test_interop_vectors.py       # ≈ InteropVectors.test.ts (CRITICAL)
    └── test_security_edge_cases.py   # ≈ SecurityEdgeCases.test.ts
```

---

## 4. Dependencias Python

### Runtime

| Paquete | Versión | Uso | Equivale a (TS) |
|---------|---------|-----|------------------|
| `pydantic` | >=2.0 | Modelos de datos tipados | Interfaces TypeScript |
| `pynacl` | >=1.5 | Ed25519 sign/verify, keypair generation | `@noble/curves` |
| `web3` | >=6.0 | EVM provider, contratos, Keccak256, wallets | `ethers` |
| `httpx` | >=0.27 | HTTP client async (fetch equivalent) | `globalThis.fetch` |

### Dev

| Paquete | Versión | Uso |
|---------|---------|-----|
| `pytest` | >=8.0 | Test runner |
| `pytest-asyncio` | >=0.23 | Async test support |
| `pytest-cov` | >=5.0 | Coverage |
| `ruff` | >=0.4 | Linting + formatting |
| `mypy` | >=1.10 | Type checking |

---

## 5. Mapeo de módulos TS → Python

| TS Module | TS File | Python Module | Python File | Notas |
|-----------|---------|---------------|-------------|-------|
| `core/types` | `types.ts` | `core.types` | `types.py` | Interfaces → Pydantic models |
| `core/AgentIdentity` | `AgentIdentity.ts` | `core.identity` | `identity.py` | Clase principal; static methods → class methods |
| `core/time` | `time.ts` | `core.time_utils` | `time_utils.py` | `datetime` stdlib |
| `crypto/hash` | `hash.ts` | `crypto.hash` | `hash.py` | `hashlib` stdlib |
| `registry/types` | `types.ts` | `registry.types` | `types.py` | Protocols (PEP 544) |
| `registry/evm-types` | `evm-types.ts` | `registry.evm_types` | `evm_types.py` | Protocols |
| `registry/InMemoryAgentRegistry` | `InMemoryAgentRegistry.ts` | `registry.in_memory` | `in_memory.py` | Dict store |
| `registry/EvmAgentRegistry` | `EvmAgentRegistry.ts` | `registry.evm_registry` | `evm_registry.py` | web3.py adapter |
| `registry/EthersAgentRegistryContractClient` | `EthersAgentRegistryContractClient.ts` | `registry.web3_client` | `web3_client.py` | web3.py contract calls |
| `resolver/types` | `types.ts` | `resolver.types` | `types.py` | Protocols |
| `resolver/InMemoryDIDResolver` | `InMemoryDIDResolver.ts` | `resolver.in_memory` | `in_memory.py` | Dict store |
| `resolver/UniversalResolverClient` | `UniversalResolverClient.ts` | `resolver.universal` | `universal.py` | Cache + events |
| `resolver/HttpDIDDocumentSource` | `HttpDIDDocumentSource.ts` | `resolver.http_source` | `http_source.py` | httpx + SSRF guard |
| `resolver/JsonRpcDIDDocumentSource` | `JsonRpcDIDDocumentSource.ts` | `resolver.jsonrpc_source` | `jsonrpc_source.py` | httpx + SSRF guard |

---

## 6. Checklist de construcción

> **Convención:** Marcar `[x]` cuando esté implementado Y testeado. Marcar `[~]` si implementado pero sin tests. Marcar `[ ]` si pendiente.

### Fase A — Scaffolding y tipos base

- [x] **A1.** Crear directorio `sdk-python/` con `pyproject.toml` y metadata PEP 621
- [x] **A2.** Configurar pytest + pytest-asyncio + ruff + mypy
- [x] **A3.** Crear `src/agent_did_sdk/__init__.py` con re-exports placeholder
- [x] **A4.** Crear `src/agent_did_sdk/py.typed` (PEP 561)

### Fase B — Módulo `crypto`

- [x] **B1.** `crypto/hash.py` — `hash_payload(payload: str) -> str`
  - SHA-256 con `hashlib`, prefijo `0x`, error si vacío
- [x] **B2.** `crypto/hash.py` — `format_hash_uri(hash_hex: str) -> str`
  - Strip `0x`, formatear `hash://sha256/{hash}`
- [x] **B3.** `crypto/hash.py` — `generate_agent_metadata_hash(payload: str) -> str`
  - Combina B1 + B2
- [x] **B4.** `tests/test_crypto.py` — 8 tests (determinismo, vacío, formato, metadata hash)
  - **Verificar:** mismos hashes que SDK TS para mismos inputs

### Fase C — Módulo `core/time_utils`

- [x] **C1.** `time_utils.py` — `is_unix_timestamp_string(value: str) -> bool`
- [x] **C2.** `time_utils.py` — `unix_string_to_iso(value: str) -> str`
- [x] **C3.** `time_utils.py` — `iso_to_unix_string(value: str) -> str`
- [x] **C4.** `time_utils.py` — `normalize_timestamp_to_iso(value: str | None) -> str | None`
- [x] **C5.** `tests/test_time.py` — 12 tests (detección, conversión, normalización, edge cases)

### Fase D — Módulo `core/types` (Pydantic models)

- [x] **D1.** `AgentMetadata` model
  - Campos: `name`, `description?`, `version`, `core_model_hash`, `system_prompt_hash`, `capabilities?`, `member_of?`
- [x] **D2.** `VerifiableCredentialLink` model
- [x] **D3.** `VerificationMethod` model
  - Campos: `id`, `type`, `controller`, `public_key_multibase?`, `blockchain_account_id?`
- [x] **D4.** `AgentDIDDocument` model (RFC-001 compliant)
  - Campos: `context` (serializado como `@context`), `id`, `controller`, `created`, `updated`, `agent_metadata`, `compliance_certifications?`, `verification_method`, `authentication`
  - **Config:** `model_config = ConfigDict(populate_by_name=True)` con aliases JSON-LD
- [x] **D5.** `CreateAgentParams` model
- [x] **D6.** `CreateAgentResult` model (document + agent_private_key)
- [x] **D7.** `UpdateAgentDocumentParams` model
- [x] **D8.** `RotateVerificationMethodResult` model
- [x] **D9.** `SignHttpRequestParams` model
- [x] **D10.** `VerifyHttpRequestSignatureParams` model
- [x] **D11.** `AgentDocumentHistoryEntry` model + `AgentDocumentHistoryAction` literal type
- [x] **D12.** Tests de serialización JSON (verificar que el JSON output sea idéntico al TS)

### Fase E — Módulo `registry`

- [x] **E1.** `registry/types.py` — `AgentRegistryRecord` dataclass
- [x] **E2.** `registry/types.py` — `AgentRegistry` Protocol (register, set_document_reference, revoke, get_record, is_revoked)
- [x] **E3.** `registry/evm_types.py` — `EvmTxResponse`, `EvmAgentRegistryContract` Protocol, `EvmAgentRegistryAdapterConfig`
- [x] **E4.** `registry/in_memory.py` — `InMemoryAgentRegistry` (dict-based)
- [x] **E5.** `tests/test_in_memory_registry.py` — 8 tests (register, reference, revoke, get, is_revoked)
- [x] **E6.** `registry/evm_registry.py` — `EvmAgentRegistry` adapter (usa contract client)
- [x] **E7.** `registry/web3_client.py` — `Web3AgentRegistryContractClient` (web3.py contract calls)
  - Manejar formatos tuple y object de respuesta
  - `safe_str()` equivalent
  - Normalización temporal
- [x] **E8.** `tests/test_evm_registry.py` — 3 tests con mock contract
- [x] **E9.** `tests/test_web3_client.py` — 2 tests incluyendo invalid shape → error

### Fase F — Módulo `resolver`

- [x] **F1.** `resolver/types.py` — `DIDResolver` Protocol (register_document, resolve, remove)
- [x] **F2.** `resolver/types.py` — `DIDDocumentSource` Protocol (get_by_reference, store_by_reference?)
- [x] **F3.** `resolver/types.py` — `UniversalResolverConfig`, `ResolverCacheStats`, `ResolverResolutionEvent`, `ResolverResolutionStage`
- [x] **F4.** `resolver/in_memory.py` — `InMemoryDIDResolver` (deep copy con `.model_copy(deep=True)`)
- [x] **F5.** `tests/test_in_memory_resolver.py` — 4 tests (register, resolve, remove, not found, deep copy)
- [x] **F6.** `resolver/http_source.py` — `HttpDIDDocumentSource`
  - httpx async client
  - SSRF protection: solo http/https
  - IPFS gateway failover
  - Multi-URL failover
- [x] **F7.** `tests/test_http_source.py` — 5 tests (OK, 404, failover, SSRF reject, IPFS)
- [x] **F8.** `resolver/jsonrpc_source.py` — `JsonRpcDIDDocumentSource`
  - JSON-RPC 2.0 envelope
  - SSRF protection
  - Multi-endpoint failover
  - Error codes (-32004 → None, otros → raise)
- [x] **F9.** `tests/test_jsonrpc_source.py` — 5 tests (resolve, failover, not-found, SSRF, throw)
- [x] **F10.** `resolver/universal.py` — `UniversalResolverClient`
  - Cache con TTL
  - Registry lookup → document source → cache
  - Fallback resolver
  - Event emission
  - Cache stats
- [x] **F11.** `tests/test_universal_resolver.py` — 3 tests (cache, fallback, error)

### Fase G — Módulo `core/identity` (la clase principal)

- [x] **G1.** `AgentIdentity.__init__(config)` — signer + network
- [x] **G2.** `AgentIdentity.create(params) -> CreateAgentResult`
  - Generar Ed25519 keypair (PyNaCl)
  - Generar DID con Keccak256 (web3.py)
  - Hash de model y prompt
  - Construir documento JSON-LD
  - Registrar en resolver + registry
  - Guardar historial
- [x] **G3.** `AgentIdentity.sign_message(payload, private_key) -> str`
  - Ed25519 sign, retornar hex
- [x] **G4.** `AgentIdentity.sign_http_request(params) -> dict[str, str]`
  - Construir signature base (request-target, host, date, content-digest)
  - Ed25519 sign, base64 encode
  - Retornar headers: Signature, Signature-Input, Signature-Agent, Date, Content-Digest
- [x] **G5.** `AgentIdentity.verify_signature(did, payload, signature, key_id?) -> bool` (classmethod)
  - Resolver DID → verificar revocación → verificar con clave(s)
- [x] **G6.** `AgentIdentity.verify_http_request_signature(params) -> bool` (classmethod)
  - Parsear headers Signature + Signature-Input
  - Reconstruir signature base
  - Verificar Ed25519
  - Validar content-digest
  - Verificar time skew
- [x] **G7.** `AgentIdentity.resolve(did) -> AgentDIDDocument` (classmethod)
- [x] **G8.** `AgentIdentity.revoke_did(did)` (classmethod)
- [x] **G9.** `AgentIdentity.update_did_document(did, patch) -> AgentDIDDocument` (classmethod)
- [x] **G10.** `AgentIdentity.rotate_verification_method(did) -> RotateVerificationMethodResult` (classmethod)
- [x] **G11.** `AgentIdentity.get_document_history(did) -> list[AgentDocumentHistoryEntry]` (classmethod)
- [x] **G12.** `AgentIdentity.set_resolver(resolver)` / `set_registry(registry)` (classmethod)
- [x] **G13.** `AgentIdentity.use_production_resolver(config)` (classmethod)
- [x] **G14.** `AgentIdentity.use_production_resolver_from_http(config)` (classmethod)
- [x] **G15.** `AgentIdentity.use_production_resolver_from_json_rpc(config)` (classmethod)
- [x] **G16.** `tests/test_identity.py` — 16 tests
  - Crear agente válido, verificar estructura RFC-001
  - Firmar y verificar payload
  - Firmar y verificar HTTP request
  - Resolver DID
  - Revocar y fallar verificación post-revocación
  - Actualizar documento
  - Rotar verification method (2+ ciclos)
  - Historial de documento
  - Parámetros mínimos / parámetros completos

### Fase H — Interoperabilidad cross-language

- [x] **H1.** Copiar `sdk/tests/fixtures/interop-vectors.json` a `tests/fixtures/`
- [x] **H2.** `tests/test_interop_vectors.py` — Verificar firma de mensaje
  - Dado: DID + publicKey + payload + signatureHex del fixture
  - Verificar que Ed25519 verify pase
- [x] **H3.** `tests/test_interop_vectors.py` — Verificar firma HTTP
  - Dado: method + url + body + headers del fixture
  - Verificar que `verify_http_request_signature()` retorne True
- [x] **H4.** **GATE:** Los vectores de interop DEBEN pasar idénticos al SDK TS

### Fase I — Seguridad edge cases

- [x] **I1.** `tests/test_security_edge_cases.py` — SSRF HttpDIDDocumentSource
  - Reject `file://`, `data://` → None
  - Accept `https://` → OK
- [x] **I2.** `tests/test_security_edge_cases.py` — SSRF JsonRpcDIDDocumentSource
  - Reject `file://`, `javascript:` → None
- [x] **I3.** `tests/test_security_edge_cases.py` — Web3Client invalid shape → error

### Fase J — Polish y publicación

- [x] **J1.** Completar `__init__.py` con todos los re-exports
- [x] **J2.** `mypy --strict` pasa sin errores
- [x] **J3.** `ruff check` + `ruff format` pasa sin errores
- [x] **J4.** `pytest --cov` reporta ≥85% coverage (86% actual)
- [x] **J5.** `README.md` con usage examples, installation, API reference
- [x] **J6.** Agregar script `test:python` en el `package.json` raíz
- [x] **J7.** Agregar step al CI (`ci.yml`) para Python SDK tests
- [x] **J8.** Agregar entry en conformance suite (o smoke independiente)

---

## 7. API pública de referencia

Todas las funciones/clases que el `__init__.py` debe re-exportar:

```python
# Core
from .core.types import (
    AgentMetadata,
    VerifiableCredentialLink,
    VerificationMethod,
    AgentDIDDocument,
    CreateAgentParams,
    CreateAgentResult,
    UpdateAgentDocumentParams,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    VerifyHttpRequestSignatureParams,
    AgentDocumentHistoryAction,
    AgentDocumentHistoryEntry,
)
from .core.identity import AgentIdentity
from .core.time_utils import (
    is_unix_timestamp_string,
    unix_string_to_iso,
    iso_to_unix_string,
    normalize_timestamp_to_iso,
)

# Crypto
from .crypto.hash import hash_payload, format_hash_uri, generate_agent_metadata_hash

# Registry
from .registry.types import AgentRegistry, AgentRegistryRecord
from .registry.evm_types import EvmTxResponse, EvmAgentRegistryContract, EvmAgentRegistryAdapterConfig
from .registry.in_memory import InMemoryAgentRegistry
from .registry.evm_registry import EvmAgentRegistry
from .registry.web3_client import Web3AgentRegistryContractClient

# Resolver
from .resolver.types import (
    DIDResolver,
    DIDDocumentSource,
    UniversalResolverConfig,
    ResolverCacheStats,
    ResolverResolutionEvent,
    ResolverResolutionStage,
)
from .resolver.in_memory import InMemoryDIDResolver
from .resolver.universal import UniversalResolverClient
from .resolver.http_source import HttpDIDDocumentSource, HttpDIDDocumentSourceConfig
from .resolver.jsonrpc_source import JsonRpcDIDDocumentSource, JsonRpcDIDDocumentSourceConfig
```

---

## 8. Mapeo de tests

| # | Test TS | Test Python | Tests min | Prioridad |
|---|---------|-------------|-----------|-----------|
| 1 | `crypto.test.ts` | `test_crypto.py` | 4 | B4 |
| 2 | `time.test.ts` | `test_time.py` | 6 | C5 |
| 3 | `AgentIdentity.test.ts` | `test_identity.py` | 15 | G16 |
| 4 | `EvmAgentRegistry.test.ts` | `test_evm_registry.py` | 3 | E8 |
| 5 | `EthersAgentRegistryContractClient.test.ts` | `test_web3_client.py` | 2 | E9 |
| 6 | `UniversalResolverClient.test.ts` | `test_universal_resolver.py` | 3 | F11 |
| 7 | `HttpDIDDocumentSource.test.ts` | `test_http_source.py` | 5 | F7 |
| 8 | `JsonRpcDIDDocumentSource.test.ts` | `test_jsonrpc_source.py` | 4 | F9 |
| 9 | `InteropVectors.test.ts` | `test_interop_vectors.py` | 2 | H2-H3 |
| 10 | `SecurityEdgeCases.test.ts` | `test_security_edge_cases.py` | 5 | I1-I3 |
| | | **Total mínimo** | **~49** | |

---

## 9. Vectores de interoperabilidad

El archivo `sdk/tests/fixtures/interop-vectors.json` contiene vectores pre-calculados con el SDK TS. El SDK Python DEBE producir resultados idénticos.

### Vector de mensaje

```
DID:         did:agent:polygon:0xinteropfixture
Public key:  z678cd8acdfbc5713c5eec46e89b0934543fe7e51602794360f421eba84cb1a5a
Payload:     "interop-message:v1"
Signature:   aa5a5535a83b073888ca98605bffa187438f69a5d56bf04032bd9f79eda1e362...
```

**Verificación:** `Ed25519.verify(signature_bytes, payload_bytes, public_key_bytes)` debe retornar `True`.

### Vector HTTP

```
Method: POST
URL:    https://api.example.com/v1/interop?mode=fixture
Body:   {"fixture":true}
Date:   Mon, 01 Jan 2024 00:00:00 GMT
```

Con headers `Signature`, `Signature-Input`, `Signature-Agent`, `Content-Digest` pre-calculados.

**Verificación:** `AgentIdentity.verify_http_request_signature(params)` debe retornar `True`.

### Regla de oro

> Si los vectores de interop pasan en Python, el SDK es compatible cross-language con el SDK TS.

---

## 10. Criterios de aceptación globales

El SDK Python se considera **completo** cuando:

1. ✅ Todos los items del checklist (Sección 6) están marcados `[x]`
2. ✅ 49+ tests pasan (`pytest`)
3. ✅ Vectores de interoperabilidad pasan idénticos al TS (`test_interop_vectors.py`)
4. ✅ `mypy --strict` sin errores
5. ✅ `ruff check` sin errores
6. ✅ Coverage ≥85%
7. ✅ CI integrado y passing
8. ✅ Los 11 MUST + 5 SHOULD de RFC-001 se pueden verificar con el SDK Python

---

## 11. Notas de implementación

### 11.1 Ed25519 — Diferencias clave

En TypeScript:
```typescript
import { ed25519 } from '@noble/curves/ed25519';
const privKey = ed25519.utils.randomPrivateKey();       // 32 bytes
const pubKey = ed25519.getPublicKey(privKey);            // 32 bytes
const sig = ed25519.sign(message, privKey);              // 64 bytes
ed25519.verify(sig, message, pubKey);                    // boolean
```

En Python (PyNaCl):
```python
from nacl.signing import SigningKey, VerifyKey
signing_key = SigningKey.generate()                       # 32 bytes seed
verify_key = signing_key.verify_key                       # 32 bytes
signed = signing_key.sign(message)                        # signature + message
signature = signed.signature                              # 64 bytes
verify_key.verify(message, signature)                     # raises or returns
```

**Diferencia importante:** `@noble/curves` usa la private key raw (32 bytes) directamente como seed. PyNaCl usa `SigningKey` que internamente es el seed. Para interoperabilidad, debemos almacenar y transmitir el **seed (32 bytes)** como hex, no la expanded key (64 bytes).

### 11.2 Keccak256 para generación de DID

En TypeScript:
```typescript
import { ethers } from 'ethers';
const hash = ethers.keccak256(ethers.toUtf8Bytes(data));
```

En Python:
```python
from web3 import Web3
hash = Web3.keccak(text=data).hex()
```

### 11.3 JSON-LD serialization con Pydantic

```python
class AgentDIDDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    context: list[str] = Field(alias="@context")
    id: str
    controller: str
    # ...
    agent_metadata: AgentMetadata = Field(alias="agentMetadata")
    verification_method: list[VerificationMethod] = Field(alias="verificationMethod")
    
    # Para serializar con aliases JSON-LD:
    def model_dump_jsonld(self) -> dict:
        return self.model_dump(by_alias=True, exclude_none=True)
```

### 11.4 Protocol classes (equivalente a interfaces TS)

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class AgentRegistry(Protocol):
    async def register(self, did: str, controller: str, document_ref: str | None = None) -> None: ...
    async def set_document_reference(self, did: str, document_ref: str) -> None: ...
    async def revoke(self, did: str) -> None: ...
    async def get_record(self, did: str) -> AgentRegistryRecord | None: ...
    async def is_revoked(self, did: str) -> bool: ...
```

### 11.5 HTTP Signature Base String

El formato de la signature base DEBE ser byte-a-byte idéntico al del SDK TS:

```
(request-target): post /v1/interop?mode=fixture
host: api.example.com
date: Mon, 01 Jan 2024 00:00:00 GMT
content-digest: sha-256=:base64hash=:
```

Separador: `\n` (LF, no CRLF).

### 11.6 Multibase encoding

La clave pública se almacena con prefijo `z` + hex de los 32 bytes:
```python
public_key_multibase = "z" + public_key_bytes.hex()
```

---

## 12. Desbloqueos

Completar F2-01 desbloquea directamente:

| Feature | Descripción | Impacto |
|---------|-------------|---------|
| **F2-04** | Semantic Kernel Integration (Python) | Microsoft ecosystem runtime |
| **F2-05** | CrewAI Integration | Independent agent framework |
| **LangChain Python** | integrations/langchain-python | Largest AI framework |
| **SDK Python en PyPI** | Publicación open-source | Adopción orgánica Python/ML community |

---

## Orden de ejecución recomendado

```
A (scaffold) → B (crypto) → C (time) → D (types) → E (registry) → F (resolver) → G (identity) → H (interop) → I (security) → J (polish)
```

Cada fase es autocontenida y testeable independientemente. Las dependencias van de izquierda a derecha: los módulos de la derecha importan de los de la izquierda, nunca al revés.

---

*Documento creado como planning artifact del proyecto Agent-citizen-identification.*  
*Actualizar el checklist de la Sección 6 a medida que avanza la implementación.*
