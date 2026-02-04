# constants.py
CONFIG_DIR = "config"
WALLET_ATTESTATION_NAME = "WalletAttestation"
AAL_VALUE_BASIC = "https://trust-list.eu/aal/basic"
AAL_VALUE_MEDIUM = "https://trust-list.eu/aal/medium"
AAL_VALUE_HIGH = "https://trust-list.eu/aal/high"
AUTH_RESPONSE_TYPE_CODE = "code"
AUTH_RESPONSE_MODE_QUERY = "query"
AUTH_RESPONSE_MODE_FORM_POST_JWT = "form_post.jwt"
PRESENTATION_RESPONSE_TYPE_VP_TOKEN = "vp_token"
PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt"
METADATA_TYPE_FEDERATION_ENTITY = "federation_entity"
METADATA_TYPE_AUTHORIZATION_SERVER = "oauth_authorization_server"
METADATA_TYPE_CREDENTIAL_ISSUER = "openid_credential_issuer"
METADATA_TYPE_CREDENTIAL_VERIFIER = "openid_credential_verifier"
# Lista ISO alpha‑2 dei 27 Stati membri EU
EU_COUNTRIES = {
    "AT","BE","BG","CZ","CY","DK","DE","EE","ES","FR",
    "FI","GR","HU","IE","IT","LV","LT","LU","MT","NL",
    "PL","PT","RO","SK","SI","SE"
}
IDP_VALID = {
    "CIE3","CIE2","SPID2"
}
CREDENTIAL_VALID = "0x00"
CREDENTIAL_INVALID = "0x01"
CREDENTIAL_SUSPENDED = "0x02"
CONTENT_PDF_BASE_64_PREFIX = "data:application/pdf;base64,"
JWT_PREFIX = "jwt"
SD_JWT_PREFIX = "dc_sd_jwt"
MSO_MDOC_PREFIX = "mso_mdoc"
ISO_18013_5_VERSION = "1.0"
ISO_18013_5_NAME = "org.iso.18013.5.1"
HASH_ALGORITHM = "SHA-256"