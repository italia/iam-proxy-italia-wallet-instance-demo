"""
Centralized settings for the IT Wallet instance demo.

All values are overridable via environment variables (use UPPER_SNAKE_CASE,
e.g. SECRET_KEY, OID_FED_LIST_PATH). Also loads from config.json "app" section.
"""
from settings_utils import (
    CONFIG_DIR,  # noqa: F401
    DEFAULTS,
    _get,
    _get_int,
    _get_set,
)

# App / Flask
OID_FED_LIST_PATH = _get("oid_fed_list_path")
OID_FED_WELL_KNOWN_PATH = _get("oid_fed_well_known_path")
CHROME_DEVTOOLS_PATH = _get("chrome_devtools_path")
FAVICON_SUBPATH = _get("favicon_subpath")
FAVICON_MIMETYPE = _get("favicon_mimetype")
STATIC_FOLDER = _get("static_folder")
DEFAULT_HOST = _get("default_host")
DEFAULT_PORT = _get_int("default_port", 8080)
SECRET_KEY = _get("secret_key")
CORRELATION_ID_FALLBACK = _get("correlation_id_fallback")
DEFAULT_CORRELATION_ID = _get("default_correlation_id")

# Domain / OAuth / OIDC / metadata
WALLET_ATTESTATION_NAME = _get("wallet_attestation_name")
AAL_VALUE_BASIC = _get("aal_value_basic")
AAL_VALUE_MEDIUM = _get("aal_value_medium")
AAL_VALUE_HIGH = _get("aal_value_high")
AUTH_RESPONSE_TYPE_CODE = _get("auth_response_type_code")
AUTH_RESPONSE_MODE_QUERY = _get("auth_response_mode_query")
AUTH_RESPONSE_MODE_FORM_POST_JWT = _get("auth_response_mode_form_post_jwt")
PRESENTATION_RESPONSE_TYPE_VP_TOKEN = _get("presentation_response_type_vp_token")
PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT = _get("presentation_response_mode_direct_post_jwt")
METADATA_TYPE_FEDERATION_ENTITY = _get("metadata_type_federation_entity")
METADATA_TYPE_AUTHORIZATION_SERVER = _get("metadata_type_authorization_server")
METADATA_TYPE_CREDENTIAL_ISSUER = _get("metadata_type_credential_issuer")
METADATA_TYPE_CREDENTIAL_VERIFIER = _get("metadata_type_credential_verifier")

# Sets (comma-separated in env)
EU_COUNTRIES = _get_set("eu_countries", DEFAULTS["eu_countries"])
IDP_VALID = _get_set("idp_valid", DEFAULTS["idp_valid"])

# Credential status / format
CREDENTIAL_VALID = _get("credential_valid")
CREDENTIAL_INVALID = _get("credential_invalid")
CREDENTIAL_SUSPENDED = _get("credential_suspended")
CONTENT_PDF_BASE_64_PREFIX = _get("content_pdf_base_64_prefix")
JWT_PREFIX = _get("jwt_prefix")
SD_JWT_PREFIX = _get("sd_jwt_prefix")
MSO_MDOC_PREFIX = _get("mso_mdoc_prefix")
ISO_18013_5_VERSION = _get("iso_18013_5_version")
ISO_18013_5_NAME = _get("iso_18013_5_name")
HASH_ALGORITHM = _get("hash_algorithm")
