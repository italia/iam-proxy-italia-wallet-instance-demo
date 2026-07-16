"""
Application-wide constants.

These are protocol/spec-defined values (OID-Fed, OAuth 2.0, OIDC, IT Wallet spec)
that must not vary per deployment. They are NOT configuration — do not add
deployment-specific or environment-specific values here.

Exception: CONFIG_DIR is resolved from the CONFIG_DIR env var at startup since it
is required before any config file can be loaded.
"""

import os

# Bootstrap
CONFIG_DIR: str = os.environ.get("CONFIG_DIR", "config")
APP_SETTINGS_KEY = "SETTINGS"

# Correlation ID
CORRELATION_ID_FALLBACK: str = "N/A"
DEFAULT_CORRELATION_ID: str = "default-id"

# Flask static / favicon
FAVICON_MIMETYPE: str = "image/svg+xml"

# OIDC / OID-Fed well-known paths
OID_FED_LIST_PATH: str = "/list"
OID_FED_WELL_KNOWN_PATH: str = "/.well-known/openid-federation"
CHROME_DEVTOOLS_PATH: str = "/.well-known/appspecific/com.chrome.devtools.json"

# Wallet attestation claim names (IT Wallet spec)
WALLET_ATTESTATION_NAME: str = "WalletInstanceAttestation"
WALLET_UNIT_ATTESTATION_NAME: str = "WalletUnitAttestation"

# AAL (Authenticator Assurance Level) URIs — EU Trust List
AAL_VALUE_BASIC: str = "https://trust-list.eu/aal/basic"
AAL_VALUE_MEDIUM: str = "https://trust-list.eu/aal/medium"
AAL_VALUE_HIGH: str = "https://trust-list.eu/aal/high"

# OAuth 2.0 / OIDC response types and modes
AUTH_RESPONSE_TYPE_CODE: str = "code"
AUTH_RESPONSE_MODE_QUERY: str = "query"
AUTH_RESPONSE_MODE_FORM_POST_JWT: str = "form_post.jwt"
PRESENTATION_RESPONSE_TYPE_VP_TOKEN: str = "vp_token"
PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT: str = "direct_post.jwt"

# OID-Fed / OIDC metadata type identifiers
METADATA_TYPE_FEDERATION_ENTITY: str = "federation_entity"
METADATA_TYPE_AUTHORIZATION_SERVER: str = "oauth_authorization_server"
METADATA_TYPE_CREDENTIAL_ISSUER: str = "openid_credential_issuer"
METADATA_TYPE_CREDENTIAL_VERIFIER: str = "openid_credential_verifier"
METADATA_TYPE_WALLET_PROVIDER: str = "wallet_solution"

# EU member state ISO-3166-1 alpha-2 codes
EU_COUNTRIES: set[str] = {
    "AT", "BE", "BG", "CZ", "CY", "DK", "DE", "EE", "ES", "FR",
    "FI", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "SE",
}

# Valid IdP hint identifiers
IDP_VALID: set[str] = {"CIE3", "CIE2", "SPID2"}

# Credential status byte values (IT Wallet spec)
CREDENTIAL_VALID: str = "0x00"
CREDENTIAL_INVALID: str = "0x01"
CREDENTIAL_SUSPENDED: str = "0x02"

# Credential / document format prefixes
CONTENT_PDF_BASE_64_PREFIX: str = "data:application/pdf;base64,"
JWT_PREFIX: str = "jwt"
SD_JWT_PREFIX: str = "dc_sd_jwt"
MSO_MDOC_PREFIX: str = "mso_mdoc"

