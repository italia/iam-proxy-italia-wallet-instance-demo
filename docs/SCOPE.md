# Scope

`iam-proxy-italia-wallet-instance-demo` is a **developer inspection wallet**, not a production or certified wallet.

It exists so developers can drive and observe OpenID4VCI issuance and OpenID4VP presentation against Credential Issuers and Relying Parties in the IAM Proxy Italia stack (IT-Wallet 1.4.7). Held attestations live in process memory. A restart clears them. Do not use it in production.

## Features

| Area | What the demo does |
|---|---|
| **Access** | Password-gated demo UI (`WALLET_INSTANCE_PASSWORD`). |
| **Issuance (Emissione)** | Point at a Credential Issuer URL, choose discovery (`openid` or `openid-federation`; EUDIW LOTL is listed but not implemented), load the catalog, obtain PID/mDL and other configured attestations. |
| **Holding (Attestati)** | Keep issued credentials in memory. Show metadata, user attributes, decoded attestation, and revocation state. Delete one attestation or reset the whole demo. |
| **Presentation (Presentazione)** | Scan an RP QR, show which claims will be shared, complete OpenID4VP remote presentation (`direct_post.jwt` / `vp_token`). |
| **Presentations Dashboard** | Local history of RP interactions: outcome, RP metadata, requested vs presented attestations, JSON export. |
| **HTTP diagnostics (Diagnosi)** | In-memory log of outbound HTTP exchanges toward issuers, verifiers, and federation peers. |
| **Wallet Provider endpoints** | Publishes federation Entity Configuration, nonce, instance initialization, and wallet attestation for the demo identity. |
| **Formats** | SD-JWT VC (`dc+sd-jwt` / `vc+sd-jwt`) and mdoc CBOR (`mso_mdoc`). |

## Checks

Protocol and product checks the demo runs:

### Trust and discovery

- Resolves Trust Anchor / OpenID Federation entity configurations.
- Verifies Entity Statement / Entity Configuration JWTs.
- Confirms the configured wallet provider appears under the trust anchor when federation is required.

### Issuance

- Validates issuer and authorization-server metadata.
- Runs PKCE, PAR / JAR when required, wallet attestation + PoP, DPoP token binding (`token_type` must be `DPoP`).
- Verifies access token claims and issued credential signatures (SD-JWT or mdoc) against issuer JWKs.
- Rejects duplicate hold of the same attestation.

### Presentation

- Accepts `openid_federation` and `x509_hash` client id schemes.
- Fetches and verifies the Relying Party request object JWT.
- Matches held credentials to DCQL / requested types (`vct` / `doctype`).
- Before send, evaluates expiry and Status List revocation/suspension; warns and still allows present-or-reissue.
- Surfaces Relying Party refusal causes (expired, revoked, suspended, missing claims).

### Revocation

- Reads only the Status List referenced in the credential (`status.status_list.uri` + `idx`).
- Verifies the status-list JWT, checks `sub` against the URI, decodes bits, maps `0/1/2` → valid / revoked / suspended.
- Does **not** call a status-assertion endpoint.

### Out of scope as checks

- Not a certified wallet security evaluation.
- Not a substitute for production key storage or user authentication strength.
- Not an authorization decision engine for Relying Parties beyond what presentation flow requires.

## Transparency over HTTP objects

The demo is built so developers can **see the wire objects**, not only the happy-path UI.

### Storico Azioni HTTP (`/wallet/diagnostics`)

- Records up to 100 outbound exchanges (method, URL, status, peer role, time).
- Peer tags: Credential Issuer, Verifier, Federation.
- Purpose grouping from the URL path (entity configuration, issuer metadata, PAR, token, nonces, wallet attestation, credential, request/response URI, Status List, and others).
- For each exchange shows:
  - raw **HTTP request** and **HTTP response** (start line, headers, body);
  - embedded **JWTs** decoded into Header / Payload tabs (encrypted JWT payload marked as ciphertext);
  - **X.509** material from `x5c` / COSE `x5chain` as readable certificate text.
- Private-key material is redacted; oversized bodies are truncated.
- Export as text or JSON; selective delete of logged exchanges.

### Held credentials

- Cleartext Header / Payload (and Disclosures for SD-JWT; CBOR diagnostic notation for mdoc).
- Status List JWT Header / Payload after “Verifica revoca”.

### Presentation UI / Dashboard

- Shows authorization-request payload and which attributes will be shared.
- Keeps Relying Party-facing outcome and metadata for later inspection.

### Persistence disclaimer

The same instance shares held attestations across logins until delete, reset, or process restart. That is intentional for demo inspection, not isolation.
