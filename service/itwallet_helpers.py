"""
Helper functions to reduce cyclomatic complexity in itwallet_service.
"""

import logging
from typing import Any

from flask import current_app

from state import app_state
from utils.utils import extract_claim

logger = logging.getLogger(__name__)


def get_proxies_from_config() -> tuple[dict | None, list[str]]:
    """Extract proxy config. Returns (proxies, no_proxy_domains)."""
    use_proxy = extract_claim(current_app.config, "metadata.use_proxy")
    if not use_proxy:
        logger.info("🚨  Proxy disabilitati")
        return None, []
    proxies = {
        "http": extract_claim(current_app.config, "metadata.http_proxy"),
        "https": extract_claim(current_app.config, "metadata.https_proxy"),
    }
    no_proxy_raw = extract_claim(current_app.config, "metadata.no_proxy") or ""
    no_proxy_domains = [d.strip() for d in no_proxy_raw.split(",") if d.strip()]
    logger.info("🚨  Configuring proxy...")
    logger.info("🚨  Proxy abilitati: HTTP=%s, HTTPS=%s", proxies["http"], proxies["https"])
    logger.info("🚨  No proxy domains: %s", no_proxy_domains)
    return proxies, no_proxy_domains


def validate_response_mode(response_mode: Any, supported: list, flow_name: str) -> None:
    """Validate response_mode is in supported list. Raises ValueError if not."""
    if response_mode not in supported:
        raise ValueError(
            f"Il response_mode '{response_mode}' configurato per {flow_name} non è supportato, "
            f"valori ammessi: {supported}"
        )


def validate_response_type(response_type: Any, supported: list, flow_name: str) -> None:
    """Validate response_type is in supported list. Raises ValueError if not."""
    if response_type not in supported:
        raise ValueError(
            f"Il response_type '{response_type}' configurato per {flow_name} non è supportato, "
            f"valori ammessi: {supported}"
        )


def get_trust_root_and_eaa_provider_ec(
    credential_configuration_id: str,
) -> tuple[str, str, dict]:
    """Get trust_root_url, eaa_provider_url, eaa_provider_ec for given credential_configuration_id. Raises ValueError if not found."""
    from constants import METADATA_TYPE_CREDENTIAL_ISSUER

    country = app_state.selected_country
    trust_root_url = extract_claim(current_app.config, f"ms_trust_configuration.{country}.trust_root")
    if not trust_root_url:
        raise ValueError(f"Nessun Trust root per il paese {country}")
    query = (
        f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_configurations_supported.{credential_configuration_id}"
    )
    ec_list = app_state.ec_store.all_values(query)
    if not ec_list:
        raise ValueError(
            f"Nessun {METADATA_TYPE_CREDENTIAL_ISSUER} trovato che supporti credenziali di tipo {credential_configuration_id}"
        )
    ec = ec_list[0]
    eaa_url = extract_claim(ec, "iss")
    if not eaa_url:
        raise ValueError(f"EC dell'entità che rilascia {credential_configuration_id} non presenta il claim 'iss'")
    return trust_root_url, eaa_url, ec


def validate_credential_and_presentation_flow() -> None:
    """Validate credential_flow and presentation_flow response_mode/response_type from config."""
    from constants import (
        AUTH_RESPONSE_MODE_FORM_POST_JWT,
        AUTH_RESPONSE_MODE_QUERY,
        AUTH_RESPONSE_TYPE_CODE,
        PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT,
        PRESENTATION_RESPONSE_TYPE_VP_TOKEN,
    )

    cred_mode = extract_claim(current_app.config, "metadata.credential_flow.response_mode")
    validate_response_mode(cred_mode, [AUTH_RESPONSE_MODE_QUERY, AUTH_RESPONSE_MODE_FORM_POST_JWT], "wallet")
    cred_type = extract_claim(current_app.config, "metadata.credential_flow.response_type")
    validate_response_type(cred_type, [AUTH_RESPONSE_TYPE_CODE], "wallet")
    pres_mode = extract_claim(current_app.config, "metadata.presentation_flow.response_mode")
    validate_response_mode(pres_mode, [PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT], "presentazione credenziali")
    pres_type = extract_claim(current_app.config, "metadata.presentation_flow.response_type")
    validate_response_type(pres_type, [PRESENTATION_RESPONSE_TYPE_VP_TOKEN], "presentazione credenziali")


def apply_credential_issuer_overrides(entity_id: str, config_prefix: str) -> None:
    """Apply EC overrides from config (initialize_flow or credential_flow) for credential issuer."""
    base = f"metadata.{config_prefix}.override_entity_configuration.openid_credential_issuer"
    path_map = {
        "credential_issuer": "metadata.openid_credential_issuer.credential_issuer",
        "credential_endpoint": "metadata.openid_credential_issuer.credential_endpoint",
        "nonce_endpoint": "metadata.openid_credential_issuer.nonce_endpoint",
        "status_assertion_endpoint": "metadata.openid_credential_issuer.status_assertion_endpoint",
        "status_attestation_endpoint": "metadata.openid_credential_issuer.status_attestation_endpoint",
    }
    for key, ec_path in path_map.items():
        value = extract_claim(current_app.config, f"{base}.{key}")
        if value:
            app_state.ec_store.update_claim_by_path(entity_id, ec_path, value)
            logger.info(
                "✅ Aggiornato EC entità %s: %s = %s",
                entity_id,
                ec_path.split(".")[-1],
                value[:50] + "..." if len(str(value)) > 50 else value,
            )


def require_session_key(session: dict, key: str, msg: str = "") -> Any:
    """Get key from session. Raise ValueError if missing or empty."""
    val = session.get(key)
    if val is None or val == "":
        raise ValueError(msg or f"Session key '{key}' mancante")
    return val


def require_jwt_claim(payload: dict, key: str, expected: Any = None, msg: str = "") -> Any:
    """Get claim from payload. Raise ValueError if missing or (if expected given) mismatch."""
    val = payload.get(key)
    if val is None or val == "":
        raise ValueError(msg or f"Claim '{key}' mancante")
    if expected is not None and val != expected:
        raise ValueError(msg or f"Claim '{key}' non valido: atteso '{expected}', trovato '{val}'")
    return val


def apply_replace_values(entity_id: str, config_prefix: str) -> int:
    """Apply replace_values from config. Returns number of replacements."""
    old_val = extract_claim(current_app.config, f"metadata.{config_prefix}.replace_values.old_value")
    new_val = extract_claim(current_app.config, f"metadata.{config_prefix}.replace_values.new_value")
    if old_val is None or new_val is None:
        return 0
    count = app_state.ec_store.replace_in_all_value_fields(old_val, new_val)
    if count:
        logger.info("✅ Sostituite %d occorrenze in EC %s", count, entity_id)
    return count
