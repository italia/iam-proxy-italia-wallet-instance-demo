# Configuration Guide

This document describes the YAML configuration files used by the application and how to manage them.

---

## 1. Structure

All deployment-specific and runtime configuration lives in the **`config/` YAML files**.

The single source of truth for runtime configuration is **`config/app_config.yaml`**. All sections that drive runtime behavior live there, either directly or via `!INCLUDE` directives that pull in separate files.

The `!INCLUDE` mechanism is used intentionally to separate two logically independent concerns:

```
app_config.yaml
│
│   (runtime settings: Flask, logging, wallet instance, trust, metadata flows)
│
├── !INCLUDE wallet_provider.yaml
│       └── everything related to the Wallet Provider's identity in the federation:
│           JWKs, Entity Configuration parameters, advertised wallet metadata
│
└── !INCLUDE credentials_config.yaml
        └── everything related to credential management:
            supported credential types, document formats, attribute mappings
                └── !INCLUDE credentials/pid.yaml
                        └── cross-format attribute mapping for the PID credential
```

When the application starts, the loader resolves all `!INCLUDE` tags and produces a single in-memory configuration tree. From the application's point of view there is only one config object — the file split is purely for developer clarity.

The loader also supports a second custom tag:

- `!ENV <VAR_NAME>` — injects the value of an environment variable at load time. If the variable is not set the field resolves to `None`.

**Rule of thumb for edits:**
- Change something about the app itself (host, port, logging, trust anchors, flow parameters) → edit `app_config.yaml`.
- Change something about how the wallet identifies itself in the federation → edit `wallet_provider.yaml`.
- Add or modify a credential type or its attribute layout → edit `credentials_config.yaml` (and optionally a file under `credentials/`).

---

## 2. Environment Variables

All `!ENV` references across the YAML files. These must be set before the application starts:

| Variable | File | Description |
|---|---|---|
| `CONFIG_DIR` | _(bootstrap)_ | Directory containing the YAML config files (default: `config`) |
| `FLASK_RUN_HOST` | `app_config.yaml` | Host the Flask server binds to (e.g. `0.0.0.0`) |
| `FLASK_RUN_PORT` | `app_config.yaml` | Port the Flask server listens on (e.g. `8080`) |
| `SECRET_KEY` | `app_config.yaml` | Flask session secret — **required in any non-local environment** |
| `TRUST_ANCHOR_URL` | `app_config.yaml`, `wallet_provider.yaml` | Federation Entity ID of the Trust Anchor |
| `WALLET_PROVIDER_URL` | `wallet_provider.yaml` | Public base URL of the Wallet Provider |
| `OPENID_CIE_PROVIDER_URL` | `app_config.yaml` | URL of the CIE Level 2 Identity Provider |
| `WALLET_INITIALIZE_REDIRECT_URI` | `app_config.yaml` | Redirect URI for the PID Issuance (initialization) flow |
| `WALLET_CREDENTIAL_REDIRECT_URI` | `app_config.yaml` | Redirect URI for the EAA Credential Issuance flow |

---

## 3. `app_config.yaml`

Main entrypoint. The first two keys delegate entirely to the included files — edit those files directly.

```yaml
provider_config:    !INCLUDE wallet_provider.yaml
credentials_config: !INCLUDE credentials_config.yaml
```

### `app`

Flask and application-level settings.

| Key | Value | Description |
|---|---|---|
| `host` | `!ENV FLASK_RUN_HOST` | Bind address |
| `port` | `!ENV FLASK_RUN_PORT` | Bind port |
| `debug_mode` | `false` | Enable Flask debug mode — **keep `false` in any non-local environment** |
| `favicon_subpath` | `images/wallet_logo.svg` | Subpath (relative to `static/`) for the favicon |
| `static_folder` | `static` | Flask static files folder name |
| `secret_key` | `!ENV SECRET_KEY` | Flask session secret — **must be set via env in any non-local environment** |

### `app.logging`

Controls application-level log output.

| Key | Default | Description |
|---|---|---|
| `filepath` | _(empty)_ | Optional directory for log file output |
| `filename` | _(empty)_ | Optional log file name |
| `level` | `DEBUG` | Log level for the `app` logger |
| `libs_enabled` | `true` | Whether to enable logging from third-party libraries |
| `libs_level` | `INFO` | Log level for third-party libraries |

### `wallet_instance`

Security capabilities declared in the wallet attestation.

| Key | Example | Description |
|---|---|---|
| `key_storage` | `[iso_18045_basic]` | Supported key storage mechanisms |
| `user_authentication` | `[iso_18045_basic]` | Supported user authentication mechanisms |
| `certification` | URL | Registry URL for certification verification |
| `oauth_authorization_server` | URL | Authorization server URL for OpenID4VP |

### `ms_trust_configuration`

Root section defining trust configurations for EU countries. Each key is an ISO 3166-1 alpha-2 country code (e.g. `IT`).

```yaml
ms_trust_configuration:
  IT:
    trust_root: !ENV TRUST_ANCHOR_URL   # Federation Entity ID of the Trust Anchor
    trust_framework: oid-fed            # Only supported value: oid-fed
```

| Key | Type | Description |
|---|---|---|
| `<ISO_country_code>` | Object | Trust configuration for a specific EU country (e.g. `IT`) |
| `<ISO_country_code>.trust_root` | String | Federation Entity ID of the Trust Anchor |
| `<ISO_country_code>.trust_framework` | String | Trust framework name (e.g. `oid-fed`) |

To add support for another country, add a new block with the appropriate country code.

### `metadata`

Metadata configuration used by the application, including network, flow, and wallet parameters.

#### Proxy

| Key | Description |
|---|---|
| `use_proxy` | Set `true` to route outbound HTTP requests through a proxy |
| `http_proxy` | HTTP proxy address (`host:port`) |
| `https_proxy` | HTTPS proxy address (`host:port`) |
| `no_proxy` | Comma-separated list of hosts/domains that bypass the proxy |

#### `initialize_flow` — PID Issuance

Defines the configuration of the Initialization flow (PID Issuance flow) implemented by the application.

| Key | Type | Description |
|---|---|---|
| `idphints` | Object | Identity Providers (IdPs) to be used for each supported identification method: CIE Level 3, CIE Level 2, SPID Level 2 |
| `idphints.CIE3` | String | URL of the Identity Provider for CIE Level 3 (empty string = disabled) |
| `idphints.CIE2` | String | URL of the Identity Provider for CIE Level 2 (`!ENV OPENID_CIE_PROVIDER_URL`) |
| `idphints.SPID2` | String | URL of the Identity Provider for SPID Level 2 |
| `credential_configuration_id` | String | Credential configuration identifier used during initialization (e.g. `mso_mdoc_pid`) |
| `response_mode` | String | ⚠ Spec-fixed: only `query` is accepted. Validated at startup against `AUTH_RESPONSE_MODE_QUERY` in `constants.py`. |
| `response_type` | String | ⚠ Spec-fixed: only `code` is accepted. Validated at startup against `AUTH_RESPONSE_TYPE_CODE` in `constants.py`. |
| `redirect_uri` | String | Redirect URI where the authorization response is sent (`!ENV WALLET_INITIALIZE_REDIRECT_URI`) |

#### `credential_flow` — EAA Issuance

Defines the configuration of the Credential Issuance flow (EAA Issuance flow) implemented by the application.

| Key | Type | Description |
|---|---|---|
| `response_mode` | String | Authorization response mode — `query` or `form_post.jwt`. Validated at startup; current value is `form_post.jwt`. |
| `response_type` | String | ⚠ Spec-fixed: only `code` is accepted. Validated at startup against `AUTH_RESPONSE_TYPE_CODE` in `constants.py`. |
| `redirect_uri` | String | Redirect URI where the authorization response is sent (`!ENV WALLET_CREDENTIAL_REDIRECT_URI`) |
| `credential_configurations_supported` | Array | List of supported credential configuration identifiers the wallet can request |
| `_response_mode` | String | _(unused — internal note field, do not remove)_ |

#### `presentation_flow` — Remote Presentation

Defines the configuration of the Presentation Remote flow implemented by the application.

| Key | Type | Description |
|---|---|---|
| `response_mode` | String | ⚠ Spec-fixed: only `direct_post.jwt` is accepted. Validated at startup against `PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT` in `constants.py`. |
| `response_type` | String | ⚠ Spec-fixed: only `vp_token` is accepted. Validated at startup against `PRESENTATION_RESPONSE_TYPE_VP_TOKEN` in `constants.py`. |
| `status_assertion_supported` | Boolean | Indicates if status assertion is supported in the Presentation Remote flow |

---

## 4. `wallet_provider.yaml`

Defines the federation identity of the Wallet Provider. **The JWKs shipped in this file are demo keys — replace them before any non-local deployment.**

| Key | Description |
|---|---|
| `wallet_link` | URL of the wallet solution homepage |
| `ec_duration_seconds` | Validity of the Entity Configuration JWT in seconds (`1980` ≈ 33 min) |
| `nbf_attestation` | `not-before` offset in seconds for wallet attestations |
| `spec_version` | Version of the IT Wallet specification supported by this implementation (e.g. `1.3.3`) |
| `public_url` | Federation Entity ID of the Wallet Provider — public base URL (`!ENV WALLET_PROVIDER_URL`) |
| `federation_jwks` | EC private key in JWK format used for federation-level signing — **replace in production** |
| `core_jwks` | EC private key in JWK format used for core wallet operations — **replace in production** |
| `authority_hints` | List of Trust Anchor Entity IDs (`!ENV TRUST_ANCHOR_URL`) |

### `metadata_group`

#### `federation_entity`

Human-readable metadata published in the Entity Configuration:

| Key | Description |
|---|---|
| `organization_name` | Display name of the organization |
| `homepage_uri` | Homepage URL |
| `policy_uri` | Privacy policy URL |
| `tos_uri` | Terms of service URL |
| `logo_uri` | Logo URL |

#### `wallet_solution`

Wallet solution capabilities advertised to the federation:

| Key | Description |
|---|---|
| `logo_uri` | Compact logo URL |
| `wallet_metadata.wallet_name` | Display name of the wallet |
| `wallet_metadata.credential_offer_endpoint` | Credential offer callback URL |
| `wallet_metadata.authorization_endpoint` | Authorization endpoint URL |
| `wallet_metadata.vp_formats_supported` | VP formats and supported signing algorithms |
| `wallet_metadata.client_id_prefixes_supported` | Supported client ID schemes (e.g. `openid_federation`, `x509_hash`) |
| `wallet_metadata.response_types_supported` | Supported response types (e.g. `vp_token`) |
| `wallet_metadata.response_modes_supported` | Supported response modes (e.g. `query`) |
| `wallet_metadata.request_object_signing_alg_values_supported` | Supported signing algorithms for request objects |

---

## 5. `credentials_config.yaml`

Defines the credential types the wallet supports and how their attributes are mapped across formats.

### `supported_credentials`

Each entry key is a credential configuration identifier (e.g. `dc_sd_jwt_pid`, `mso_mdoc_mDL`).

| Key | Description |
|---|---|
| `proto_version` | Spec version — informational, currently unused |
| `valid_for_wallet_activation` | Whether this credential can be used for wallet activation — currently unused |
| `internal_mapping_ref` | Key that links this credential to an entry in `internal_attributes_mappings` |
| `document_identifier.type` | `vct` for SD-JWT VC, `doctype` for mdoc |
| `document_identifier.value` | The credential type URI or doctype string |
| `document_format.id` | `sd-jwt-vc` or `mdoc-cbor` |
| `document_format.specs` | Format-specific parameters (mdoc: `namespaces`, `version`) |

**To add a new credential type**, add a new entry under `supported_credentials` and, if it requires a new attribute layout, add a corresponding entry under `internal_attributes_mappings`.

### `internal_attributes_mappings`

Maps each `internal_mapping_ref` to a YAML file that describes how credential attributes translate across formats.

```yaml
internal_attributes_mappings:
  pid: !INCLUDE credentials/pid.yaml
```

---

## 6. `credentials/pid.yaml`

Defines the cross-format attribute mapping for the PID credential. Each top-level key is the **internal attribute name** used in Jinja2 rendering templates. Dot-notation keys (e.g. `metadata.iat`) are expanded into nested objects.

Each attribute entry can have two format blocks:

```yaml
<attribute_name>:
  sd-jwt-vc:
    subgroup: <optional logical group>
    element_identifier: <claim name in the SD-JWT VC>
  mdoc-cbor:
    namespace: <mdoc namespace>
    subgroup: <optional logical group>
    element_identifier: <element identifier in the mdoc>
```

**Fields:**

| Field | Description |
|---|---|
| `subgroup` | Optional logical group within the credential (e.g. `verification`, `validityInfo`) |
| `namespace` | mdoc-cbor only — the namespace that contains this attribute (e.g. `eu.europa.ec.eudi.pid.1`) |
| `element_identifier` | The actual attribute/claim name as it appears in the issued credential |

**To add a new attribute to the PID mapping**, append a new entry following the same structure. Ensure the `element_identifier` values match the spec definitions for each format.

---

