import logging
from datetime import datetime

import bcrypt
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from settings import CONTENT_PDF_BASE_64_PREFIX, ISO_18013_5_NAME, MSO_MDOC_PREFIX, SD_JWT_PREFIX
from store import app_state
from utils.itwalletUtils import get_status_description
from utils.utils import (
    extract_claim,
    extract_text_from_base64_pdf,
    generate_nonce,
    sanitize_for_logging,
    unescape_json,
    unix_ts_to_str_datetime,
)

logger = logging.getLogger(__name__)
wallet_routes = Blueprint("wallet_routes", __name__, url_prefix='/wallet')


@wallet_routes.route("/activate", methods=["GET"])
def show_activation():
    return render_template("wallet_activation.html")


@wallet_routes.route("/activate", methods=["POST"])
def activate_wallet():
    pin = request.form.get("pin")
    confirm = request.form.get("confirm_pin")
    if pin != confirm or not pin.isdigit() or not (4 <= len(pin) <= 8):
        flash("PIN non valido o non corrispondente", "error")
        return redirect(url_for("wallet_routes.show_activation"))

    app_state.stored_hashed_pin = bcrypt.hashpw(pin.encode(), bcrypt.gensalt())  # Hash the PIN and save it to memory
    flash("Wallet attivato correttamente!", "success")

    return redirect(url_for("wallet_routes.wallet_access"))


@wallet_routes.route("/access", methods=["GET", "POST"])
def wallet_access():
    if request.method == "POST":
        if not (pin_attempt := request.form.get("pin_attempt", "")):
            return render_template("wallet_access.html")

        if app_state.stored_hashed_pin and bcrypt.checkpw(pin_attempt.encode(), app_state.stored_hashed_pin):
            session["pin_authenticated"] = True

            #Create new session ID and set as correlation ID for log tracking.
            session_id = generate_nonce()
            session["session_id"] = session_id

            # codeql[py/log-injection]
            logger.info("✅ Effettuato login (sessione inizializzata id=%s).", sanitize_for_logging(session_id))
            return redirect(url_for("wallet_routes.wallet_home", session_id=session_id))
        else:
            logger.error("❌ Login fallito: PIN errato")
            flash("PIN errato. Riprova.", "error")

    return render_template("wallet_access.html")


@wallet_routes.route("/home", methods=["GET"])
def wallet_home():
    if not session.get("pin_authenticated"):
        return redirect(url_for("wallet_routes.wallet_access"))

    session_id = request.args.get("session_id", "")
    selected_country = app_state.selected_country
    wallet_initialized = app_state.wallet_initialized
    credential_store = app_state.credential_store
    credential_keys = credential_store.keys() # Retrieve all credential keys

    return render_template(
        "wallet_home.html",
        session_id=session_id,
        selected_country=selected_country,
        wallet_initialized=wallet_initialized,
        credential_keys=credential_keys,
    )


@wallet_routes.route("/logout", methods=["GET"])
def logout():
    session_id = session.get("session_id", "")
    # codeql[py/log-injection]
    logger.info("✅ Effettuato logout (sessione cancellata id=%s).", sanitize_for_logging(session_id))
    session.clear()
    return redirect(url_for("wallet_routes.wallet_access"))


@wallet_routes.route("/cb", methods=["GET"])
def wallet_callback():
    params_list = list(request.args.items()) # Convert query parameters into a list of tuples
    current_path = request.path

    if params_list:
        logger.info("Ricevuta request GET %s con query string:", sanitize_for_logging(current_path))
        for k, v in params_list:
            logger.info("   %s = %s", sanitize_for_logging(k), sanitize_for_logging(v))
    else:
        logger.info("Ricevuta request GET %s senza query string", sanitize_for_logging(current_path))

    session["query_params"] = dict(params_list) #store params in session
    return render_template("wallet_cb.html")


@wallet_routes.route("/template/<credential_type>", methods=["GET"])
def credentialTypeTemplate(credential_type):

    _clear_session() #todo can remove it?

    if not (result := app_state.credential_store.find_by_prefix_with_key(credential_type)):
        logger.error("Nessuna credenziale di tipo %s trovata nella memoria", sanitize_for_logging(credential_type))
        return "Nessuna credenziale di tipo richiesto trovata nel wallet", 400

    key, value = result
    logger.info("Recuperata dalla memoria credenziale con chiave %s", sanitize_for_logging(key))

    vct = value.get("vct", "")
    logger.info("Il vct della credenziale %s è: %s", sanitize_for_logging(key), sanitize_for_logging(vct))

    status = value.get("status", "")
    status_descr = get_status_description(status)
    logger.info(
        "La credenziale %s è in stato: %s %s",
        sanitize_for_logging(key),
        sanitize_for_logging(status),
        sanitize_for_logging(status_descr),
    )

    claims = value.get("claims", {})
    claims = unescape_json(claims)

    data_row = value.get("data_row", {})
    content = claims.get("content")

    content_list = []
    if content and content.startswith(CONTENT_PDF_BASE_64_PREFIX):
        logger.debug("La credenziale presenta un claim 'content' contenente dati pdf_base64")
        content_list = extract_text_from_base64_pdf(content)

        if content_list and len(content_list) > 0:
            logger.debug("Il PDF contiene almeno una pagina con contenuto.")
            for i, pagina in enumerate(content_list, start=1):
                logger.debug("Pagina %d:\n%s\n%s", i, sanitize_for_logging(pagina), "-" * 40)

    metadata = _create_credential_metadata(key, claims)
    logger.info("Il metadata della credenziale %s è: %s", sanitize_for_logging(key), sanitize_for_logging(metadata))

    template_name = _get_template_name_for_credential_key(key)
    if not template_name:
        logger.error("Nessun template configurato per la credenziale con chiave %s", sanitize_for_logging(key))
        return "Nessun template trovato per la credenziale nel wallet", 500

    try:
        return render_template(
            template_name + ".html",
            data_row=data_row,
            claims=claims,
            metadata=metadata,
            status=status,
            statusDecr=status_descr,
            contentList=content_list,
        )
    except Exception as e:
        logger.error("%s", sanitize_for_logging(str(e)))
        return "Nessun template trovato per la credenziale nel wallet", 500


def _create_credential_metadata(credential_key, claims):
    parsed_claims = _parse_credential_claims_by_key(credential_key, claims)

    dt_iat_local_formatted = parsed_claims["dt_iat_local_formatted"]
    dt_exp_local_formatted = parsed_claims["dt_exp_local_formatted"]
    issuing_authority = parsed_claims["issuing_authority"]
    issuing_country = parsed_claims["issuing_country"]

    if dt_iat_local_formatted and dt_exp_local_formatted:
        metadata = f"Credenziale emessa da {issuing_authority} ({issuing_country}) il {dt_iat_local_formatted}, scade il {dt_exp_local_formatted}."
    else:
        logger.error(
            "Non è stato possibile leggere l'intervallo di validità della credenziale %s",
            sanitize_for_logging(credential_key),
        )
        metadata = f"Credenziale emessa da {issuing_authority} ({issuing_country})"
    return metadata


def _parse_credential_claims_by_key(credential_key, claims):
    issuing_country = ""
    issuing_authority = ""
    dt_iat_local_formatted, dt_exp_local_formatted = None, None

    if credential_key.startswith(MSO_MDOC_PREFIX):
        name_space = claims.get("nameSpaces", {}).get(ISO_18013_5_NAME, {})
        issuing_country = name_space.get("issuing_country")
        issuing_authority = name_space.get("issuing_authority")

        validity_info = claims.get("mso", {}).get("validityInfo", {})
        iat = validity_info.get("validFrom")  # ISO 8601 formatted string with UTC timezone
        exp = validity_info.get("validUntil")  # ISO 8601 formatted string with UTC timezone

        dt_iat_local_formatted = unix_ts_to_str_datetime(int(datetime.fromisoformat(iat).timestamp()),
                                                         fmt="%d-%m-%Y %H:%M:%S")
        dt_exp_local_formatted = unix_ts_to_str_datetime(int(datetime.fromisoformat(exp).timestamp()),
                                                         fmt="%d-%m-%Y %H:%M:%S")

    elif credential_key.startswith(SD_JWT_PREFIX):
        issuing_country = claims.get("issuing_country")
        issuing_authority = claims.get("issuing_authority")
        iat = claims.get("iat")  # Unix timestamp in UTC
        exp = claims.get("exp")  # Unix timestamp in UTC
        dt_iat_local_formatted = unix_ts_to_str_datetime(iat, fmt="%d-%m-%Y %H:%M:%S")
        dt_exp_local_formatted = unix_ts_to_str_datetime(exp, fmt="%d-%m-%Y %H:%M:%S")

    return dict(
        issuing_country=issuing_country,
        issuing_authority=issuing_authority,
        dt_iat_local_formatted=dt_iat_local_formatted,
        dt_exp_local_formatted=dt_exp_local_formatted,
    )


def _get_template_name_for_credential_key(key: str) -> str | None:
    """
    Resolve a trusted credential store key to a whitelisted template name.
    Prevents XSS/template injection by using only config-validated names.
    Template names follow the pattern: config_id or config_id + "-credid".
    """
    wallet_credential_supported = extract_claim(
        current_app.config, "metadata.credential_flow.credential_configurations_supported"
    )
    if not wallet_credential_supported:
        return None
    supported_list = list(wallet_credential_supported)

    id_credential = extract_claim(current_app.config, "metadata.initialize_flow.credential_configuration_id")
    if id_credential:
        supported_list.append(id_credential)

    key_lower = key.lower()
    # Find the config id that matches the key (longest prefix match first)
    for config_id in sorted(supported_list, key=len, reverse=True):
        if not key_lower.startswith(config_id.lower()):
            continue
        # Try config_id + "-credid" first (common template pattern), then config_id
        for candidate in (config_id + "-credid", config_id):
            if all(c.isalnum() or c in "_-" for c in candidate):
                return candidate
    return None


def _clear_session():
    preserved = {"session_id": session.get("session_id"), "pin_authenticated": session.get("pin_authenticated")}
    session.clear()
    session.update({k: v for k, v in preserved.items() if v is not None})
