"""
Helper functions for loading and resolving settings from env, config.json, and defaults.
"""

import json
import os

# Bootstrap: CONFIG_DIR must be resolvable before loading config
DEFAULT_CONFIG_DIR = "config"
CONFIG_DIR = os.environ.get("CONFIG_DIR", DEFAULT_CONFIG_DIR)

# Default values (overridden by config.json "app" section or env)
DEFAULTS = {
    # App / Flask
    "secret_key": "s3cr3t",
    "oid_fed_list_path": "/list",
    "oid_fed_well_known_path": "/.well-known/openid-federation",
    "chrome_devtools_path": "/.well-known/appspecific/com.chrome.devtools.json",
    "favicon_subpath": "images/wallet_logo.svg",
    "favicon_mimetype": "image/svg+xml",
    "static_folder": "static",
    "default_host": "0.0.0.0",
    "default_port": 8080,
    "correlation_id_fallback": "N/A",
    "default_correlation_id": "default-id",
    # Domain / OAuth / OIDC
    "wallet_attestation_name": "WalletAttestation",
    "aal_value_basic": "https://trust-list.eu/aal/basic",
    "aal_value_medium": "https://trust-list.eu/aal/medium",
    "aal_value_high": "https://trust-list.eu/aal/high",
    "auth_response_type_code": "code",
    "auth_response_mode_query": "query",
    "auth_response_mode_form_post_jwt": "form_post.jwt",
    "presentation_response_type_vp_token": "vp_token",
    "presentation_response_mode_direct_post_jwt": "direct_post.jwt",
    "metadata_type_federation_entity": "federation_entity",
    "metadata_type_authorization_server": "oauth_authorization_server",
    "metadata_type_credential_issuer": "openid_credential_issuer",
    "metadata_type_credential_verifier": "openid_credential_verifier",
    "metadata_type_wallet_solution": "wallet_solution",
    "eu_countries": "AT,BE,BG,CZ,CY,DK,DE,EE,ES,FR,FI,GR,HU,IE,IT,LV,LT,LU,MT,NL,PL,PT,RO,SK,SI,SE",
    "idp_valid": "CIE3,CIE2,SPID2",
    "credential_valid": "0x00",
    "credential_invalid": "0x01",
    "credential_suspended": "0x02",
    "content_pdf_base_64_prefix": "data:application/pdf;base64,",
    "jwt_prefix": "jwt",
    "sd_jwt_prefix": "dc_sd_jwt",
    "mso_mdoc_prefix": "mso_mdoc",
    "iso_18013_5_version": "1.0",
    "iso_18013_5_name": "org.iso.18013.5.1",
    "hash_algorithm": "SHA-256",
}

_config: dict = {}


def _load_config() -> dict:
    global _config
    if _config:
        return _config
    config_path = os.path.join(os.getcwd(), CONFIG_DIR, "config.json")
    try:
        with open(config_path) as f:
            data = json.load(f)
        app_section = data.get("app", {})
        _config = {**DEFAULTS, **app_section}
    except (FileNotFoundError, json.JSONDecodeError):
        _config = dict(DEFAULTS)
    return _config


def _get(key: str, default: str = None) -> str:
    """Get setting: env (UPPER_SNAKE) > config > default. Returns str."""
    env_key = key.upper()
    val = os.environ.get(env_key)
    if val is not None:
        return val
    cfg = _load_config()
    return cfg.get(key, default or DEFAULTS.get(key))


def _get_int(key: str, default: int = 0) -> int:
    return int(_get(key, str(default)) or default)


def _get_set(key: str, default: str = "") -> set:
    """Get setting as set (comma-separated string)."""
    raw = _get(key, default)
    if not raw:
        return set()
    return {x.strip() for x in raw.split(",") if x.strip()}


def get(key: str, default=None):
    """Get a setting value. Use for lazy access."""
    return _get(key, default)
