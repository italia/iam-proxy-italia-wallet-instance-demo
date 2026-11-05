import json
import logging
from urllib.parse import urlparse

from flask import Blueprint, current_app, g, jsonify, request, session, url_for
from flask_babel import gettext as _

from app.constants import (
    APP_SETTINGS_KEY,
    DEFAULT_CORRELATION_ID,
    METADATA_TYPE_CREDENTIAL_ISSUER,
    OID_FED_WELL_KNOWN_PATH,
)
from app.i18n import get_locale
from app.service.itwallet_service import ItWalletService
from app.store import app_state
from app.utils.diagnostic_log import list_entries, peer_role, remove_entries
from app.utils.utils import (
    estrai_parametro_query_string,
    guess_credential_configuration_icon,
    sanitize_for_logging,
)

logger = logging.getLogger(__name__)

wallet_api_bp = Blueprint("wallet_api_bp", __name__, url_prefix="/itwallet")


def _with_credential_view_url(result: dict) -> dict:
    data = result.get("data") if isinstance(result, dict) else None
    credential_id = data.get("credential_id") if isinstance(data, dict) else None
    if not result.get("success") or not credential_id:
        return result
    from app.routes.wallet_routes import _held_credential_views

    for index, item in enumerate(_held_credential_views()):
        if item.get("id") == credential_id:
            data["view_url"] = url_for("wallet_routes.wallet_credentials", _anchor=f"credential-{index}")
            break
    return result


@wallet_api_bp.before_request
def log_request_info():
    method = request.method
    path = request.path
    logger.info(f"Ricevuta richiesta: {method} {path}")


@wallet_api_bp.before_request
def set_correlation_id():
    g.correlation_id = request.headers.get("X-Correlation-ID", DEFAULT_CORRELATION_ID)


@wallet_api_bp.after_request
def add_charset_to_json(response):
    if response.content_type.startswith("application/json"):
        response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response


@wallet_api_bp.route("/reset", methods=["GET"])
def wallet_reset():
    """Endpoint for reset the Wallet."""
    _clear_session()
    try:
        # Svuota la memoria del wallet ma non la sessione
        app_state.credential_store.clear()
        app_state.selected_country = ""
        app_state.wallet_initialized = False

        logger.info("Il Wallet è stato resettato correttamente")
        return jsonify({"success": True}), 200
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


def _ensure_member_state() -> None:
    """Issuance still reads the trust root for a member state. The page no longer asks for one."""
    if app_state.selected_country:
        return
    trust = current_app.config.get("ms_trust_configuration") or {}
    if isinstance(trust, dict) and trust:
        app_state.selected_country = next(iter(trust))


def configured_issuer_urls() -> list[str]:
    raw = current_app.config[APP_SETTINGS_KEY].credential_issuers
    if isinstance(raw, list):
        parts = raw
    else:
        parts = str(raw or "").split(",")
    return [part.strip() for part in parts if str(part).strip()]


def _localized_display(displays, lang: str) -> dict:
    if isinstance(displays, dict):
        displays = [displays]
    if not isinstance(displays, list):
        return {}
    prefix = (lang or "it").lower()
    chosen = next(
        (
            item
            for item in displays
            if isinstance(item, dict) and str(item.get("locale", "")).lower().startswith(prefix)
        ),
        None,
    )
    if isinstance(chosen, dict):
        return chosen
    first = displays[0] if displays else {}
    return first if isinstance(first, dict) else {}


def _italian_display(displays) -> dict:
    return _localized_display(displays, "it")


def _claim_labels(config: dict) -> list[str]:
    claims = (config.get("credential_metadata") or {}).get("claims") or []
    labels = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        chosen = _italian_display(claim.get("display") or [])
        label = chosen.get("name") or chosen.get("label") or ""
        if label and label not in labels:
            labels.append(label)
    return labels


def load_configured_issuers() -> str | None:
    """Fetch each configured issuer into ec_store. Returns an Italian error, or None."""
    urls = configured_issuer_urls()
    if not urls:
        return "Nessun credential issuer è configurato."
    known = set()
    for key in app_state.ec_store.keys():
        payload = app_state.ec_store.get(key)
        if isinstance(payload, dict):
            known.add(payload.get("iss") or key)
    service = ItWalletService(session)
    for url in urls:
        if url in known:
            continue
        try:
            ec_payload = service._entity_configuration_management(url, [METADATA_TYPE_CREDENTIAL_ISSUER])
            if not _attestations_from_ec(ec_payload):
                return "Questo indirizzo non pubblica attestazioni ottenibili."
            app_state.ec_store.add(ec_payload.get("iss") or url, ec_payload)
        except Exception as exc:
            logger.error("❌ %s", sanitize_for_logging(str(exc)))
            return "Impossibile leggere i metadata di questo issuer."
    return None


def display_index() -> dict[str, dict]:
    index = {}
    for section in _catalog_sections():
        for item in section["attestations"]:
            index[item["id"]] = item
    return index


def lookup_attestation(credential_key: str, index: dict | None = None) -> dict:
    catalog = index if index is not None else display_index()
    if not catalog or not credential_key:
        return {}
    if credential_key in catalog:
        return catalog[credential_key]
    key_lower = str(credential_key).lower()
    for config_id, item in catalog.items():
        cid = str(config_id).lower()
        if key_lower.startswith(cid) or cid.startswith(key_lower):
            return item
    return {}


def _held_credential_ids() -> set[str]:
    held = set()
    store = app_state.credential_store.get_store() or {}
    for credentials in store.values():
        if isinstance(credentials, dict):
            held.update(str(key) for key in credentials.keys())
    return held


_FORMAT_LABELS = {
    "dc+sd-jwt": "SD-JWT",
    "vc+sd-jwt": "SD-JWT",
    "mso_mdoc": "mdoc CBOR",
    "jwt_vc_json": "JWT",
}


def _format_label(value: str) -> str:
    return _FORMAT_LABELS.get(value, value)


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def _chosen_display(config: dict) -> dict:
    metadata = _as_dict(config.get("credential_metadata"))
    metadata_display = _italian_display(_as_list(metadata.get("display")))
    top_display = _italian_display(_as_list(config.get("display")))
    return metadata_display or top_display


def _attestation_name(chosen: dict, config_id: str) -> str:
    return chosen.get("name") or chosen.get("description") or config_id


def _attestation_record(config_id, config: dict) -> dict:
    chosen = _chosen_display(config)
    name = _attestation_name(chosen, config_id)
    description = chosen.get("description") or ""
    if description == name:
        description = ""
    credential_format = config.get("format") or ""
    return {
        "id": config_id,
        "name": name,
        "description": description,
        "claims": _claim_labels(config),
        "format": credential_format,
        "format_label": _format_label(credential_format),
        "obtained": bool(app_state.credential_store.find_by_prefix_with_key(str(config_id))),
    }


def _mark_ambiguous(attestations: list[dict]) -> None:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for item in attestations:
        grouped.setdefault((item["name"], item["format_label"]), []).append(item)
    for group in grouped.values():
        if len(group) < 2:
            continue
        for item in group:
            item["disambiguator"] = item["id"]


def _supported_configurations(ec_payload: dict):
    supported = (
        ec_payload.get("metadata", {})
        .get(METADATA_TYPE_CREDENTIAL_ISSUER, {})
        .get("credential_configurations_supported")
        or {}
    )
    return supported if isinstance(supported, dict) else {}


def _attestations_from_ec(ec_payload: dict) -> list[dict]:
    attestations = []
    for config_id, config in _supported_configurations(ec_payload).items():
        if isinstance(config, dict):
            attestations.append(_attestation_record(config_id, config))
    _mark_ambiguous(attestations)
    return attestations


def _federation_source(entity_id: str) -> str:
    base = (entity_id or "").strip().rstrip("/")
    if base.endswith(OID_FED_WELL_KNOWN_PATH):
        return base
    return f"{base}{OID_FED_WELL_KNOWN_PATH}"


def _credential_issuer_metadata(ec_payload: dict | None) -> dict:
    if not isinstance(ec_payload, dict):
        return {}
    metadata = (ec_payload.get("metadata") or {}).get(METADATA_TYPE_CREDENTIAL_ISSUER) or {}
    return metadata if isinstance(metadata, dict) else {}


def _catalog_section(issuer: str, attestations: list[dict], ec_payload: dict | None = None) -> dict:
    metadata = _credential_issuer_metadata(ec_payload)
    uri = str(metadata.get("credential_issuer") or issuer or "").strip()
    name = str(_localized_display(metadata.get("display") or [], get_locale()).get("name") or "").strip()
    return {
        "issuer": issuer,
        "name": name,
        "uri": uri,
        "source": _federation_source(issuer),
        "attestations": attestations,
    }


def _catalog_sections() -> list[dict]:
    sections = []
    for key in app_state.ec_store.keys():
        payload = app_state.ec_store.get(key)
        if not isinstance(payload, dict):
            continue
        attestations = _attestations_from_ec(payload)
        if not attestations:
            continue
        sections.append(_catalog_section(payload.get("iss") or key, attestations, payload))
    return sections


@wallet_api_bp.route("/diagnostics", methods=["GET", "DELETE"])
def diagnostics():
    """Return the recent outbound request and response log, or remove selected exchanges."""
    if request.method == "DELETE":
        body = request.get_json(silent=True) or {}
        ids = body.get("ids")
        if not isinstance(ids, list):
            return jsonify({"success": False, "message": _("Seleziona gli scambi da rimuovere.")}), 400
        remove_entries([str(item) for item in ids])
    return jsonify({"success": True, "data": list_entries()}), 200


@wallet_api_bp.route("/issuerCatalog", methods=["GET", "POST"])
def issuer_catalog():
    """List attestations from credential issuer metadata, or load another issuer URL."""
    if request.method == "GET":
        return jsonify({"success": True, "data": _catalog_sections()}), 200

    body = request.get_json(silent=True) or {}
    issuer_url = (body.get("issuerUrl") or "").strip()
    parsed = urlparse(issuer_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return jsonify({"success": False, "field": "issuerUrl", "message": _("Inserisci un URL http o https.")}), 400

    peer = peer_role.set("credential_issuer")
    try:
        service = ItWalletService(session)
        ec_payload = service._entity_configuration_management(issuer_url, [METADATA_TYPE_CREDENTIAL_ISSUER])
        attestations = _attestations_from_ec(ec_payload)
        if not attestations:
            return jsonify(
                {
                    "success": False,
                    "field": "issuerUrl",
                    "message": _("Questo indirizzo non pubblica attestazioni ottenibili."),
                }
            ), 400
        stored_as = ec_payload.get("iss") or issuer_url
        app_state.ec_store.add(stored_as, ec_payload)
        return jsonify({"success": True, "data": _catalog_section(stored_as, attestations, ec_payload)}), 200
    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify(
            {"success": False, "field": "issuerUrl", "message": _("Impossibile leggere i metadata di questo issuer.")}
        ), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify(
            {"success": False, "field": "issuerUrl", "message": _("Impossibile leggere i metadata di questo issuer.")}
        ), 500
    finally:
        peer_role.reset(peer)


@wallet_api_bp.route("/credentialSupported", methods=["GET"])
def credentialSupported():
    """Endpoint to fetch supported Wallet credential types."""
    logger.debug("Entering method: credentialSupported.")
    try:
        held = _held_credential_ids()
        output = [
            {"id": item["id"], "label": item["name"], "icon": guess_credential_configuration_icon(item["id"])}
            for section in _catalog_sections()
            for item in section["attestations"]
            if item["id"] not in held
        ]
        return jsonify({"success": True, "data": output}), 200
    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/objectTypesInMemory", methods=["GET"])
def objectTypesInMemory():
    """Endpoint to fetch all object types currently in memory."""
    try:
        objectTypesInMemory = app_state.get_store_types()
        logger.info(
            "✅ Tipologie di oggetti presenti nella memoria del Wallet:  %s", sanitize_for_logging(objectTypesInMemory)
        )
        return jsonify({"success": True, "data": objectTypesInMemory}), 200

    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/viewObjectTypeInMemory", methods=["POST"])
def viewObjectTypeInMemory():
    """Route to display a specific object type from the Wallet memory."""
    _clear_session()

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        object_type_value = data.get("objectType")  # Check if objectType key is present
        if not object_type_value:
            return jsonify({"success": False, "data": {"error": _("Indica il tipo di elemento da mostrare.")}}), 400

        logger.info("Recuperato oggetto di tipo %s dalla memoria del Wallet", sanitize_for_logging(object_type_value))

        result = app_state.get_store(object_type_value)
        logger.debug("%s", sanitize_for_logging(json.dumps(result, indent=2, ensure_ascii=False)))

        return jsonify({"success": True, "data": result}), 200

    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


#
# @wallet_api_bp.route("/onboardedRelyingParties", methods=["GET"])
# def onboardedRelyingParties():
#     """Endpoint to fetch the list of onboarded Relying Parties."""
#     try:
#         service = ItWalletService(session)
#         result = service.getOnboardedRelyingParties()
#
#         if not result.get("success"):
#             return jsonify(result), 500
#
#         logger.info("Onboarded Relying Parties:")
#         data = []
#         for rp in list(result["data"]):
#             logger.info(" - %s", sanitize_for_logging(rp))
#             data.append({"id": rp, "label": rp, "icon": "🏛️"})
#
#         return jsonify({"success": True, "data": data}), 200
#
#     except ValueError as ve:
#         logger.error("❌ %s", sanitize_for_logging(str(ve)))
#         return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
#     except Exception as e:
#         logger.error("❌ %s", sanitize_for_logging(str(e)))
#         return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/deleteCredential", methods=["POST"])
def deleteCredentialItWallet():
    """Route to add a credential to the Wallet."""

    _clear_session()
    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credential_id = data.get("credentialId")
        if not credential_id:
            return jsonify({"success": False, "data": {"error": _("Seleziona l'attestazione da ottenere.")}}), 400

        service = ItWalletService(session)
        result = service.delete_credential_wallet(credential_id)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/addCredential", methods=["POST"])
def addCredentialItWallet():
    """Route to add a credential to the Wallet."""
    _clear_session()

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credential_id = data.get("credentialId")
        if not credential_id:
            return jsonify({"success": False, "data": {"error": _("Seleziona l'attestazione da ottenere.")}}), 400

        _ensure_member_state()
        service = ItWalletService(session)
        result = service.add_credential_wallet(credential_id)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/addCredential/complete", methods=["POST"])
def completedAddCredentialItWallet():
    """Route to complete adding a credential to the Wallet."""

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credentials_presenting = data.get("credentialsPresenting") if data else None
        service = ItWalletService(session)
        if not credentials_presenting:
            result = _with_credential_view_url(service.complete_add_credential_from_browser())
            status_code = 200 if result["success"] else 500
            return jsonify(result), status_code

        if not isinstance(credentials_presenting, list):
            raise ValueError(_("I dati da condividere con l'issuer non sono nel formato atteso."))

        _ensure_member_state()
        service = ItWalletService(session)
        result = _with_credential_view_url(service.complete_add_credential_wallet(credentials_presenting))

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/loginToRelyingParty", methods=["POST"])
def loginToRelyingParty():
    """Route to authenticate with a Relying Party."""
    _clear_session()
    try:
        data = request.get_json()
        client_id, request_uri, request_uri_method, state = _validate_login_to_rp_request(data)

        logger.info("Body richiesta: %s", sanitize_for_logging(data))
        logger.info(
            "L'ID del Relying Party selezionato è un URL valido %s", sanitize_for_logging(data.get("relyingPartyId"))
        )
        logger.info("Il contenuto del QR Code è un URL valido: %s", sanitize_for_logging(data.get("qrCodeContent")))

        service = ItWalletService(session)
        result = service.loginToVerifier(client_id, request_uri, request_uri_method, state)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code
    except ValueError as ve:
        logger.error("Errore: %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("Errore: %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


@wallet_api_bp.route("/loginToVerifier/complete", methods=["POST"])
def completedLoginToVerifier():
    """Route to complete authentication with a verifier."""
    try:
        data = request.get_json()
        logger.info("Corpo della richiesta: %s", sanitize_for_logging(data))

        credentials_presenting = data.get("credentialsPresenting")
        if not credentials_presenting:
            raise ValueError(_("Manca l'elenco dei dati da presentare al verificatore."))

        if not isinstance(credentials_presenting, list):
            raise ValueError(_("I dati da presentare al verificatore non sono nel formato atteso."))

        service = ItWalletService(session)
        result = service.complete_loginToVerifier(credentials_presenting)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("Errore: %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("Errore: %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": _(str(e))}}), 500


def _require_param(value: str | None, msg: str) -> str:
    """Return value or raise ValueError with msg."""
    if not value:
        raise ValueError(msg)
    return value


def _validate_login_to_rp_request(data: dict) -> tuple[str, str, str, str]:
    """Validate request data and extract clientId, requestUri, requestUriMethod, state. Raises ValueError on error."""
    rp_id = data.get("relyingPartyId") or ""
    qr_content = data.get("qrCodeContent") or ""
    rp_parsed = urlparse(rp_id)
    if not (rp_parsed.scheme and rp_parsed.netloc):
        raise ValueError(_("Il verificatore indicato nel QR non è un URL valido."))
    qr_parsed = urlparse(qr_content)
    if not (qr_parsed.scheme and qr_parsed.netloc):
        raise ValueError(_("Il contenuto del QR non è un URL valido."))
    client_id = _require_param(
        estrai_parametro_query_string(qr_content, "client_id"),
        _("Il QR non contiene il parametro client_id."),
    )
    if client_id != rp_id:
        raise ValueError(_("Il client indicato nel QR non corrisponde al verificatore."))
    request_uri = _require_param(
        estrai_parametro_query_string(qr_content, "request_uri"),
        _("Il QR non contiene il parametro request_uri."),
    )
    request_uri_method = estrai_parametro_query_string(qr_content, "request_uri_method") or "get"
    state = _require_param(
        estrai_parametro_query_string(qr_content, "state"),
        _("Il QR non contiene il parametro state."),
    )
    return client_id, request_uri, request_uri_method, state


def _clear_session():
    # Salva le chiavi da preservare
    preserved = {"session_id": session.get("session_id"), "authenticated": session.get("authenticated")}

    # Pulisce la sessione
    session.clear()

    # Ripristina le chiavi
    session.update({k: v for k, v in preserved.items() if v is not None})
