# temaPdS — Ecosistem VC + registre pe blockchain (inspirat de EBSI)

Implementare de tip “end-to-end” pentru un ecosistem de **Verifiable Credentials (VC)**, cu accent pe **interoperabilitate și securitate**, inspirat de abordarea **EBSI** (registre on-chain + servicii off-chain + IAM).

Repo-ul este împărțit pe componente:
- `app/` — aplicație (UI / client) (TypeScript)  
- `blockchain_network/` — rețea & smart contracts (Solidity) pentru registre (ex. DID/Issuer/Schema/Revocation)  
- `keycloak/` — Identity & Access Management (Keycloak) (config/realm/extensii)  
- `walt.id_apis/` — servicii SSI/VC (walt.id) (API-uri de emitere/verificare, integrare cu registre)  

> Structura de mai sus și limbajele repo-ului sunt vizibile în pagina principală a repository-ului.  
> (TypeScript ~ dominant, plus Solidity și Java) :contentReference[oaicite:1]{index=1}

---

## Scop & context

Proiectul urmărește:
- emiterea de **VC** (Issuer),
- prezentarea de **VP** (Holder),
- verificarea **VP/VC** (Verifier),
- ancorarea în **registre on-chain** a metadatelor necesare (ex. chei/DID, scheme, status/revocare),
- integrare cu un **IAM** (Keycloak) pentru autentificare, politici și management identitate.

---

## Arhitectură (high level)

```text
+---------+        +-------------------+        +------------------+
|  Holder |<------>|  app (UI / client)|<------>|  Keycloak (IAM)  |
+---------+        +-------------------+        +------------------+
     |                         |
     | VP/VC                   | API calls
     v                         v
+--------------+        +------------------+        +----------------------+
|  Verifier    |<------>|  walt.id_apis    |<------>| blockchain_network    |
+--------------+        | (issue/verify)   |        | (registries/contracts)|
                        +------------------+        +----------------------+
