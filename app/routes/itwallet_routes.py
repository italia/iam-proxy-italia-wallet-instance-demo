import json
import logging
from urllib.parse import urlparse

from flask import Blueprint, current_app, g, jsonify, request, session

from app.service.itwallet_service import ItWalletService
from app.store import app_state
from app.utils.utils import (
    estrai_parametro_query_string,
    extract_claim,
    guess_credential_configuration_icon,
    sanitize_for_logging,
)
from settings import (
    DEFAULT_CORRELATION_ID,
    EU_COUNTRIES,
    IDP_VALID,
)

logger = logging.getLogger(__name__)

wallet_api_bp = Blueprint("wallet_api_bp", __name__, url_prefix="/itwallet")


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
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/init", methods=["GET"])
def init_wallet():
    """Endpoint for Wallet initialization via required query parameters (e.g., country, idp)."""
    logger.info("Entering method: init_wallet.")
    _clear_session()
    try:
        country = request.args.get("country")
        if not country:
            raise ValueError("Parametro 'country' mancante")

        country = country.upper()
        if country not in EU_COUNTRIES:
            raise ValueError(
                f"Parametro 'country' valorizzato con il paese '{country}' non riconosciuto come membro UE"
            )

        idp = request.args.get("idp")
        if not idp:
            raise ValueError("Parametro 'idp' mancante")

        idp = idp.upper()
        if idp not in IDP_VALID:
            raise ValueError(f"Parametro 'idp' valorizzato con il valore '{idp}' non riconosciuto")

        # Salvataggio in memoria del country e dell'idp selezionato
        app_state.selected_country = country
        app_state.selected_idp = idp

        service = ItWalletService(session)
        result = service.initialize_wallet(idp=idp, country=country)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/init/complete", methods=["GET"])
def completedInitItWallet():
    """Endpoint to complete the Wallet initialization process."""
    try:
        service = ItWalletService(session)
        result = service.complete_initialize_wallet()

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/credentialSupported", methods=["GET"])
def credentialSupported():
    """Endpoint to fetch supported Wallet credential types."""
    try:
        supported_creds = extract_claim(
            current_app.config, "metadata.credential_flow.credential_configurations_supported"
        )
        if not supported_creds:
            raise ValueError("Nessuna tipologia credenziale configurata")

        logger.info("Tipologie di credenziali supportate dal wallet:")
        result = []
        for c in list(supported_creds):
            logger.info(" - %s", sanitize_for_logging(c))
            cred = dict(id=c, label=c, icon=guess_credential_configuration_icon(c))
            result.append(cred)

        logger.info(
            "ℹ️  Nel wallet hai al momento: %s", sanitize_for_logging(app_state.credential_store.keys_with_vct())
        )
        return jsonify({"success": True, "data": result}), 200

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


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
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/viewObjectTypeInMemory", methods=["POST"])
def viewObjectTypeInMemory():
    """Route to display a specific object type from the Wallet memory."""
    _clear_session()

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        object_type_value = data.get("objectType")  # Check if objectType key is present
        if not object_type_value:
            return jsonify({"success": False, "data": {"error": "Missing request parameter 'objectType'"}}), 400

        logger.info("Recuperato oggetto di tipo %s dalla memoria del Wallet", sanitize_for_logging(object_type_value))

        result = app_state.get_store(object_type_value)
        logger.debug("%s", sanitize_for_logging(json.dumps(result, indent=2, ensure_ascii=False)))

        return jsonify({"success": True, "data": result}), 200

    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/onboardedRelyingParties", methods=["GET"])
def onboardedRelyingParties():
    """Endpoint to fetch the list of onboarded Relying Parties."""
    try:
        service = ItWalletService(session)
        result = service.getOnboardedRelyingParties()

        if not result.get("success"):
            return jsonify(result), 500

        logger.info("Onboarded Relying Parties:")
        data = []
        for rp in list(result["data"]):
            logger.info(" - %s", sanitize_for_logging(rp))
            data.append({"id": rp, "label": rp, "icon": "🏛️"})

        return jsonify({"success": True, "data": data}), 200

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/deleteCredential", methods=["POST"])
def deleteCredentialItWallet():
    """Route to add a credential to the Wallet."""

    _clear_session()
    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credential_id = data.get("credentialId")
        if not credential_id:
            return jsonify({"success": False, "data": {"error": "Missing request parameter 'credentialId'"}}), 400

        service = ItWalletService(session)
        result = service.delete_credential_wallet(credential_id)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/addCredential", methods=["POST"])
def addCredentialItWallet():
    """Route to add a credential to the Wallet."""
    _clear_session()

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credential_id = data.get("credentialId")
        if not credential_id:
            return jsonify({"success": False, "data": {"error": "Missing request parameter 'credentialId'"}}), 400

        service = ItWalletService(session)
        result = service.add_credential_wallet(credential_id)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/addCredential/complete", methods=["POST"])
def completedAddCredentialItWallet():
    """Route to complete adding a credential to the Wallet."""

    try:
        data = request.get_json()
        logger.info("%s", sanitize_for_logging(data))

        credentials_presenting = data.get("credentialsPresenting")
        if not credentials_presenting:
            raise ValueError("La richiesta non presenta il parametro 'credentialsPresenting'")

        if not isinstance(credentials_presenting, list):
            raise ValueError("Il parametro 'credentialsPresenting' ha un formato non valido")

        service = ItWalletService(session)
        result = service.complete_add_credential_wallet(credentials_presenting)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("❌ %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("❌ %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


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
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("Errore: %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


@wallet_api_bp.route("/loginToVerifier/complete", methods=["POST"])
def completedLoginToVerifier():
    """Route to complete authentication with a verifier."""
    try:
        data = request.get_json()
        logger.info("Corpo della richiesta: %s", sanitize_for_logging(data))

        credentials_presenting = data.get("credentialsPresenting")
        if not credentials_presenting:
            raise ValueError("Il parametro 'credentialsPresenting' non è presente nel corpo della richiesta")

        if not isinstance(credentials_presenting, list):
            raise ValueError("Il parametro 'credentialsPresenting' ha un formato non valido.")

        service = ItWalletService(session)
        result = service.complete_loginToVerifier(credentials_presenting)

        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("Errore: %s", sanitize_for_logging(str(ve)))
        return jsonify({"success": False, "data": {"error": str(ve)}}), 400
    except Exception as e:
        logger.error("Errore: %s", sanitize_for_logging(str(e)))
        return jsonify({"success": False, "data": {"error": str(e)}}), 500


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
        raise ValueError(f"L'ID del Relying Party selezionato non è un URL valido: {rp_id}")
    qr_parsed = urlparse(qr_content)
    if not (qr_parsed.scheme and qr_parsed.netloc):
        raise ValueError(f"Il contenuto del QR Code non è un URL valido: {qr_content}")
    client_id = _require_param(
        estrai_parametro_query_string(qr_content, "client_id"),
        "L'URL specificata nel QR Code non presenta il parametro 'client_id' in query string",
    )
    if client_id != rp_id:
        raise ValueError("client_id nel QR Code non corrisponde al Relying Party")
    request_uri = _require_param(
        estrai_parametro_query_string(qr_content, "request_uri"),
        "L'URL specificata nel QR Code non presenta il parametro 'request_uri' in query string",
    )
    request_uri_method = estrai_parametro_query_string(qr_content, "request_uri_method") or "get"
    state = _require_param(
        estrai_parametro_query_string(qr_content, "state"),
        "L'URL specificata nel QR Code non presenta il parametro 'state' in query string",
    )
    return client_id, request_uri, request_uri_method, state


def _clear_session():
    # Salva le chiavi da preservare
    preserved = {"session_id": session.get("session_id"), "pin_authenticated": session.get("pin_authenticated")}

    # Pulisce la sessione
    session.clear()

    # Ripristina le chiavi
    session.update({k: v for k, v in preserved.items() if v is not None})
