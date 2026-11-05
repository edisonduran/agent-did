# src/AgentRegistry.sol

> **Status: deferred, optional EVM profile.** These contracts are not part of the core `1.0.0` release gate. The core `@agentdid/sdk` does not depend on them; the optional adapter is [`@agentdid/evm`](../evm/README.md) (see `docs/RFC-001-EVM-Profile.md`).

Contrato mínimo compatible con el adaptador `@agentdid/evm` (ver `evm/`).

## Setup rápido (Hardhat)

```bash
cd contracts
npm install
cp .env.example .env
```

Smoke test end-to-end (desde la raíz del repo):

```bash
npm run smoke:e2e
```

Compilar contrato:

```bash
npm run build
```

Desplegar en localhost (requiere nodo local activo):

```bash
npm run deploy:local
```

Desplegar en Sepolia:

```bash
npm run deploy:sepolia
```

Exportar ABI para el SDK:

```bash
npm run export:abi
```

Esto genera: `evm/examples/abi/AgentRegistry.abi.json`.

## Funciones expuestas

- `registerAgentAttested(string did, string controller, string documentRef, Attestation attestation)`: requiere una firma EIP-712 del `registrar` (ver abajo)
- `registrar()` / `setRegistrar(address)` (solo admin) y `registrationDigest(...)`
- `setDocumentRef(string did, string documentRef)`
- `revokeAgent(string did)`
- `setRevocationDelegate(string did, address delegate, bool authorized)`
- `transferAgentOwnership(string did, address newOwner)`
- `isRevocationDelegate(string did, address delegate)`
- `getAgentRecord(string did)`
- `isRevoked(string did)`

## ABI esperada por el SDK

```solidity
function registerAgentAttested(
  string did,
  string controller,
  string documentRef,
  (address owner, uint256 deadline, bytes signature) attestation
) external;
function setDocumentRef(string did, string documentRef) external;
function revokeAgent(string did) external;
function setRevocationDelegate(string did, address delegate, bool authorized) external;
function transferAgentOwnership(string did, address newOwner) external;
function isRevocationDelegate(string did, address delegate) external view returns (bool);
function getAgentRecord(string did)
  external
  view
  returns (string did, string controller, string createdAt, string revokedAt, string documentRef);
function isRevoked(string did) external view returns (bool);
```

## Notas de uso

- `createdAt` y `revokedAt` se almacenan como timestamp Unix en formato string para mantener compatibilidad directa con el adaptador actual.
- Política formal de revocación: puede revocar el `owner` del DID o un delegado autorizado explícitamente por DID.
- `owner` puede transferirse con `transferAgentOwnership` para soportar cambios de custodio/controlador operativo.

## Registro con atestación del registrador

El contrato no puede comprobar por sí mismo que quien registra un DID sea su controlador (los DID son cadenas opacas). Para evitar que cualquiera registre el DID de otro y se quede como `owner` (con permiso para revocarlo), `registerAgentAttested` exige una firma EIP-712 del `registrar` sobre `Registration(did, controller, documentRef, owner, deadline)`:

- El registrador (por defecto el admin que despliega, rotable con `setRegistrar`) verifica fuera de cadena que `owner` controla el DID y firma la atestación.
- Cualquiera puede enviar la transacción; el `owner` del registro es el de la atestación, no `msg.sender`.
- La firma queda ligada a este contrato y a esta cadena (dominio EIP-712), caduca en `deadline` y no se puede reutilizar: un DID solo se registra una vez.
- El registrador es una autoridad de confianza: este modelo traslada la comprobación de control del DID fuera de cadena, no la elimina. Sin su firma nadie puede registrar.
- `registerAgent` y `registerAgentWithDocument` ya no existen. `documentRef` puede ser vacío y fijarse luego con `setDocumentRef`.

## Conexión desde el SDK

Usa el ejemplo: `evm/examples/evm-registry-wiring.ts`.

Variables mínimas para ese ejemplo:

- `RPC_URL`
- `CREATOR_PRIVATE_KEY`
- `AGENT_REGISTRY_ADDRESS`
- `REGISTRAR_PRIVATE_KEY` (solo para la demo, que firma la atestación en local)
