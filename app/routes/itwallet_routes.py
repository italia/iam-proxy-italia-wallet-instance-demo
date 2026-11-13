import io
import json
import logging
from app.service.credential_status import presentation_error_message
from urllib.parse import quote, urlparse

import pyqrcode
from flask import Blueprint, Response, current_app, g, jsonify, redirect, request, session, url_for
from flask_babel import gettext as _

from app.constants import (
    APP_SETTINGS_KEY,
    DEFAULT_CORRELATION_ID,
    METADATA_TYPE_CREDENTIAL_ISSUER,
    OID_FED_WELL_KNOWN_PATH,
)
from app.i18n import get_locale
from app.service.catalog import (
    _as_dict,
    _as_list,
    _attach_offer_uris,
    _attestation_name,
    _attestation_record,
    _attestations_from_ec,
    _catalog_section,
    _catalog_sections,
    _chosen_display,
    _claim_labels,
    _credential_issuer_metadata,
    _credential_offer_uri,
    _direct_issuer_payload,
    _discovery_rejection,
    _ensure_member_state,
    _federation_source,
    _fetch_issuer_payload,
    _format_label,
    _held_credential_ids,
    _issuer_catalog_post,
    _italian_display,
    _localized_display,
    _mark_ambiguous,
    _metadata_source,
    _offer_authorization_server,
    _offer_qr_svg,
    _parse_direct_metadata,
    _require_param,
    _store_discovered_issuer,
    _stored_discovery,
    _supported_configurations,
    _validate_login_to_rp_request,
    _with_credential_view_url,
    configured_eudiw_lotl,
    configured_issuer_urls,
    configured_trust_anchor,
    display_index,
    load_configured_issuers,
    lookup_attestation,
)
from app.service.itwallet_service import ItWalletService
from app.store import app_state, transaction_log
from app.utils.diagnostic_log import list_entries, peer_role, remove_entries
from app.utils.http_utils import http_request_with_retry
from app.utils.utils import (
    estrai_parametro_query_string,
    guess_credential_configuration_icon,
    sanitize_for_logging,
)

logger = logging.getLogger(__name__)

wallet_api_bp = Blueprint("wallet_api_bp", __name__, url_prefix="/itwallet")

_DISCOVERY_DIRECT = "openid"
_DISCOVERY_FEDERATION = "openid-federation"
_DISCOVERY_LOTL = "eudiw-lotl"
_DIRECT_WELL_KNOWN = "/.well-known/openid-credential-issuer"


@wallet_api_bp.before_request
def require_wallet_session():
    if session.get("authenticated"):
        return None
    return redirect(url_for("wallet_routes.wallet_access"))


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


@wallet_api_bp.route("/credential-offer.svg", methods=["GET"])
def credential_offer_qr():
    try:
        svg = _offer_qr_svg(request.args.get("offer") or "")
    except ValueError:
        return jsonify({"success": False, "message": _("Credential offer non valida.")}), 400
    return Response(svg, mimetype="image/svg+xml")


@wallet_api_bp.route("/issuerCatalog", methods=["GET", "POST"])
def issuer_catalog():
    """List attestations from credential issuer metadata, or load another issuer URL."""
    if request.method == "GET":
        return jsonify({"success": True, "data": _catalog_sections()}), 200
    return _issuer_catalog_post()


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
def stored_object_types():
    """Endpoint to fetch all object types currently in memory."""
    try:
        stored_types = app_state.get_store_types()
        logger.info(
            "✅ Tipologie di oggetti presenti nella memoria del Wallet:  %s", sanitize_for_logging(stored_types)
        )
        return jsonify({"success": True, "data": stored_types}), 200

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


@wallet_api_bp.route("/deleteCredential", methods=["POST"])
def deleteCredentialItWallet():
    """Route to add a credential to the Wallet."""

    _clear_session()
    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credential_id = data.get("credentialId")
        if not credential_id:
            return jsonify({"success": False, "data": {"error": _("Seleziona l'attestato da ottenere.")}}), 400

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
            return jsonify({"success": False, "data": {"error": _("Seleziona l'attestato da ottenere.")}}), 400

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


def _issuance_state_from(data):
    issuance_state = data.get("issuanceState") if isinstance(data, dict) else None
    if isinstance(issuance_state, str) and issuance_state:
        return issuance_state
    return None


def _json_result(result):
    status_code = 200 if result["success"] else 500
    return jsonify(result), status_code


def _complete_from_browser(data):
    service = ItWalletService(session)
    result = _with_credential_view_url(service.complete_add_credential_from_browser(_issuance_state_from(data)))
    return _json_result(result)


def _complete_with_shared_data(credentials_presenting):
    if not isinstance(credentials_presenting, list):
        raise ValueError(_("I dati da condividere con l'issuer non sono nel formato atteso."))
    _ensure_member_state()
    service = ItWalletService(session)
    result = _with_credential_view_url(service.complete_add_credential_wallet(credentials_presenting))
    return _json_result(result)


@wallet_api_bp.route("/addCredential/complete", methods=["POST"])
def completedAddCredentialItWallet():
    """Route to complete adding a credential to the Wallet."""

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))
        credentials_presenting = data.get("credentialsPresenting") if data else None
        if credentials_presenting:
            return _complete_with_shared_data(credentials_presenting)
        return _complete_from_browser(data)

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
        result = service.present_to_verifier(client_id, request_uri, request_uri_method, state)

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
        result = service.complete_presentation(credentials_presenting)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("Errore: %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": _(str(ve))}}), 400
    except Exception as e:
        logger.error("Errore: %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": presentation_error_message(e)}}), 500


def _clear_session():
    transaction_log.abandon_open_presentation(session)
    # Salva le chiavi da preservare
    preserved = {
        "session_id": session.get("session_id"),
        "authenticated": session.get("authenticated"),
        "issuance_requests": session.get("issuance_requests"),
    }

    # Pulisce la sessione
    session.clear()

    # Ripristina le chiavi
    session.update({k: v for k, v in preserved.items() if v is not None})
