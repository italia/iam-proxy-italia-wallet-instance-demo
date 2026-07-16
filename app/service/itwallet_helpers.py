"""
Helper functions to reduce cyclomatic complexity in itwallet_service.

Validation and check logic for Entity Configuration, access tokens, and RP authorization
requests are centralized here to keep the main service file maintainable.
"""

import logging
from typing import Any

from flask import current_app

from app.constants import METADATA_TYPE_CREDENTIAL_ISSUER
from app.store import app_state
from app.utils.utils import extract_claim, sanitize_for_logging

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
    # codeql[py/log-injection]
    logger.info(
        "🚨  Proxy abilitati: HTTP=%s, HTTPS=%s",
        sanitize_for_logging(proxies["http"]),
        sanitize_for_logging(proxies["https"]),
    )
    # codeql[py/log-injection]
    logger.info("🚨  No proxy domains: %s", sanitize_for_logging(no_proxy_domains))
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
    logger.info(
        f"Entering method: get_trust_root_and_eaa_provider_ec. Params: [credential_configuration_id: {credential_configuration_id}]"
    )
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
    logger.info("Entering method: validate_credential_and_presentation_flow. ")
    from app.constants import (
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
    logger.info(f"Entering method: require_session_key. Params [ session: {session}, key: {key}]")
    val = session.get(key)
    if val is None or val == "":
        raise ValueError(msg or f"Session key '{key}' not present in session")
    return val


def require_jwt_claim(payload: dict, key: str, expected: Any = None, msg: str = "") -> Any:
    """Get claim from payload. Raise ValueError if missing or (if expected given) mismatch."""
    logger.info(f"Entering method: require_jwt_claim. Params [ payload: {payload}, key: {key}, expected:{expected}]")

    val = payload.get(key)

    if val is None or val == "":
        raise ValueError(msg or f"Claim '{key}' not found")

    if expected is not None and val != expected:
        raise ValueError(msg or f"Claim '{key}' not valid: expected '{expected}', found '{val}'")

    return val


def apply_replace_values(entity_id: str, config_prefix: str) -> int:
    """Apply replace_values from config. Returns number of replacements."""
    old_val = extract_claim(current_app.config, f"metadata.{config_prefix}.replace_values.old_value")
    new_val = extract_claim(current_app.config, f"metadata.{config_prefix}.replace_values.new_value")
    if old_val is None or new_val is None:
        return 0
    count = app_state.ec_store.replace_in_all_value_fields(old_val, new_val)
    if count:
        # codeql[py/log-injection]
        logger.info("✅ Sostituite %d occorrenze in EC %s", count, sanitize_for_logging(entity_id))
    return count


def _validate_ec_iss_sub(ec_payload: dict, expected: str) -> None:
    """Validate EC iss and sub match expected. Raises ValueError."""
    logger.debug(f"Entering method: _validate_ec_iss_sub. Params [ec_payload: {ec_payload}, expected: {expected}]")
    if not ec_payload:
        raise ValueError("Entity Configuration is empty")
    # Split the iss to check if it has a scheme (http/https). If it does, we can compare directly. If not, we need to prepend the scheme from the expected value.
    iss_split = ec_payload.get("iss", "").split(":")
    if iss_split[0] not in ["http", "https"]:
        ec_payload["iss"] = f"{iss_split[1]}:{iss_split[2]}"
        ec_payload["sub"] = f"{iss_split[1]}:{iss_split[2]}"

    if ec_payload.get("iss") != expected or ec_payload.get("sub") != expected:
        raise ValueError(f"EC iss/sub non valido: atteso '{expected}'")


def _validate_ec_authority_hints(ec_payload: dict, expected_hint: Any) -> None:
    """Validate EC authority_hints contains expected_hint. Raises ValueError."""
    logger.debug(f"Entering method: _validate_ec_authority_hints. Params [ec_payload: {ec_payload}, expected_hint: {expected_hint}]", ec_payload, expected_hint)
    hints = ec_payload.get("authority_hints", [])
    if not isinstance(hints, list) or not hints or expected_hint not in hints:
        raise ValueError(f"EC 'authority_hints' non valido o mancante hint '{expected_hint}'")


def _validate_ec_metadata_and_jwks(ec_payload: dict, expected_metadata_types: list) -> None:
    """Validate EC has required metadata types and jwks. Raises ValueError."""
    from app.constants import METADATA_TYPE_FEDERATION_ENTITY
    logger.debug(f"Entering method: _validate_ec_metadata_and_jwks. Params [ec_payload: {ec_payload}, expected_metadata_types: {expected_metadata_types}]")
    actual = ec_payload.get("metadata", {})
    missing = [t for t in expected_metadata_types if t not in actual]
    if missing:
        raise ValueError(f"EC metadata mancanti: {missing}")
    for mtype in expected_metadata_types:
        if mtype == METADATA_TYPE_FEDERATION_ENTITY:
            continue
        try:
            _ = ec_payload["metadata"][mtype]["jwks"]
        except KeyError:
            raise ValueError(f"metadata.{mtype}.jwks mancante")


def validate_ec(
    ec_payload: dict, expected_issuer_url: str, expected_metadata_types: list, expected_hint: Any = None
) -> None:
    """Validate Entity Configuration: iss/sub, authority_hints, metadata types, jwks. Raises ValueError."""
    logger.info(f"Entering method: validate_ec. Params [ec_payload: {ec_payload}, expected_issuer_url: {expected_issuer_url}, expected_metadata_types: {expected_metadata_types}, expected_hint: {expected_hint}]")
    if not ec_payload:
        raise ValueError("Entity Configuration non specificato")
    _validate_ec_iss_sub(ec_payload, expected_issuer_url)
    if expected_hint is not None:
        _validate_ec_authority_hints(ec_payload, expected_hint)
    _validate_ec_metadata_and_jwks(ec_payload, expected_metadata_types)


def validate_access_token(
    json_content: dict, expected_issuer_url: str, expected_client_id: str, expected_cnf_jkt_value: str
) -> None:
    """Validate DPoP access token claims (iss, client_id, sub, cnf.jkt). Raises ValueError."""
    logger.info(
        f"Entering method: validate_access_token. Params [json_content: {json_content}, expected_issuer_url: {expected_issuer_url}, expected_client_id:{expected_client_id}, expected_cnf_jkt_value: {expected_cnf_jkt_value}]"
    )

    if not json_content:
        raise ValueError("Access Token unspecified")

    if json_content.get("iss") != expected_issuer_url:
        raise ValueError(f"iss not valid: expected_issuer_url '{expected_issuer_url}', found {json_content.get('iss')}")

    if json_content.get("client_id") != expected_client_id:
        raise ValueError(
            f"Iclient id not vlaid: expected_client_id '{expected_client_id}', found {json_content.get('client_id')}"
        )

    if json_content.get("sub") is None:
        raise ValueError("Sub not found")

    cnf = json_content.get("cnf")

    if not cnf or not isinstance(cnf, dict):
        raise ValueError("cnf empty or not found into json_content")

    jkt = cnf.get("jkt")

    if jkt != expected_cnf_jkt_value:
        raise ValueError(f"cnf.jkt not valid: expected '{expected_cnf_jkt_value}', found {jkt}")


def parse_rp_authorization_request(json_content: dict, client_id: str) -> tuple[list, str, str, str]:
    """Validate RP Authorization Request JWT. Returns (credentials_requested, state, nonce, response_uri)."""
    if not json_content:
        raise ValueError("JWT nel Request_uri response non specificato")
    pres_rt = extract_claim(current_app.config, "metadata.presentation_flow.response_type")
    pres_rm = extract_claim(current_app.config, "metadata.presentation_flow.response_mode")
    require_jwt_claim(json_content, "client_id", expected=client_id, msg=f"client_id atteso '{client_id}'")
    require_jwt_claim(json_content, "iss", expected=client_id, msg=f"iss atteso '{client_id}'")
    state = require_jwt_claim(json_content, "state", msg="Claim 'state' mancante")
    nonce = require_jwt_claim(json_content, "nonce", msg="Claim 'nonce' mancante")
    response_uri = require_jwt_claim(json_content, "response_uri", msg="Claim 'response_uri' mancante")
    require_jwt_claim(json_content, "response_type", expected=pres_rt, msg=f"response_type atteso '{pres_rt}'")
    require_jwt_claim(json_content, "response_mode", expected=pres_rm, msg=f"response_mode atteso '{pres_rm}'")
    dcql = json_content.get("dcql_query")
    if not dcql:
        raise ValueError("Claim 'dcql_query' non presente nel JWT")
    credentials = dcql.get("credentials", [])
    if not isinstance(credentials, list) or not all(isinstance(c, dict) for c in credentials):
        credentials = []
    logger.info(
        "ℹ️  dcql_query.credentials: %d tipologie",
        len(credentials),
    )
    return credentials, state, nonce, response_uri
