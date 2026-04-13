import json
import logging
from datetime import datetime

import bcrypt
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for, jsonify

from app.store import app_state
from app.service.v1.service import Service
from app.utils.itwalletUtils import get_status_description
from app.utils.utils import (
    extract_claim,
    extract_text_from_base64_pdf,
    generate_nonce,
    remove_str_prefix,
    sanitize_for_logging,
    unescape_json,
    unix_ts_to_str_datetime,
)
from app.service.itwallet_service import ItWalletService
from settings import CONTENT_PDF_BASE_64_PREFIX, ISO_18013_5_NAME, JWT_PREFIX, MSO_MDOC_PREFIX, SD_JWT_PREFIX

logger = logging.getLogger(__name__)
wallet_routes = Blueprint("wallet_routes", __name__, url_prefix="/wallet")


@wallet_routes.app_template_filter("from_json")
def convert_to_list(value):
    """
    Converts input to a Python list.

    Returns the list if already provided, decodes it if it's a valid JSON string,
    or returns an empty list if an error occurs or the input is None.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as e:
        # codeql[py/log-injection]
        logging.getLogger(__name__).error(
            "JSON parsing error in filter: %s, value: %s",
            sanitize_for_logging(str(e)),
            sanitize_for_logging(value),
        )
        return []


@wallet_routes.app_template_filter("split")
def split_string(value, delimiter):
    """Splits a string into a list based on a delimiter."""
    if value is None:
        return []
    return str(value).split(delimiter)


@wallet_routes.app_template_filter("format_credenziale")
def format_credential(value):
    """
    Identifies the credential format based on the credential_id prefix.
    Returns the lowercased format name or 'unknown' if no match is found.
    """
    if not value:
        return "sconosciuto"

    val_lower = value.lower()
    prefixes = [JWT_PREFIX, SD_JWT_PREFIX, MSO_MDOC_PREFIX]
    for prefix in prefixes:
        if val_lower.startswith(prefix.lower()):
            return prefix.lower()
    return "sconosciuto"


@wallet_routes.app_template_filter("tag_credenziale")
def credential_tag(value):
    """
    Generates a 3-4 character uppercase tag from a credential ID.
    Removes prefixes and special characters, prioritizes existing uppercase chars,
    or formats based on underscores.
    """
    if not value:
        return "N/A"

    # 1. Clean prefix and leading special chars
    prefixes = [JWT_PREFIX, SD_JWT_PREFIX, MSO_MDOC_PREFIX]
    val = remove_str_prefix(value, prefixes)

    if val and not val[0].isalnum():
        val = val[1:]

    # 2. Strategy A: Use existing uppercase if enough (min 3)
    upper_chars = "".join(c for c in val if c.isupper())
    if len(upper_chars) >= 3:
        return upper_chars[:3]

    # 3. Strategy B: Handle underscores (e.g., "name_id" -> "NAM-I")
    if "_" in val[1:]:
        parts = val.split("_", 1)
        if len(parts) > 1 and parts[1]:
            return f"{parts[0][:3].upper()}-{parts[1][0].upper()}"

    # 4. Strategy C: Fallback to first 3 chars
    return val[:3].upper()


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
    logger.info("Entering method: wallet_access. Params []")
    if request.method == "POST":
        if not (pin_attempt := request.form.get("pin_attempt", "")):
            return render_template("wallet_access.html")

        if app_state.stored_hashed_pin and bcrypt.checkpw(pin_attempt.encode(), app_state.stored_hashed_pin):
            session["pin_authenticated"] = True

            session_id = generate_nonce()

            session["session_id"] = session_id

            logger.info(f"session_id: {session_id} authenticated successfully.")

            oauth_authorization_server = extract_claim(current_app.config, "wallet_instance.oauth_authorization_server")

            wallet_initialized = app_state.wallet_initialized

            if oauth_authorization_server and not wallet_initialized:
                app_state.selected_country = "IT"
                app_state.selected_idp = None
                service = ItWalletService(session, external_discovery=True)
                try:
                    result = service.initialize_wallet(idp = None, country="IT")
                    return redirect(result.get("data", {}).get("redirect_url"))
                except ValueError as ve:
                    logger.error(f"Error, message: {ve}")
                    error_message = str(ve)
                except Exception as e:
                    logger.error(f"Error, message: {e}")
                    error_message = "Exception when call discovery page. Contact administrator."
                flash(error_message, "error")
            else:
                return redirect(url_for("wallet_routes.wallet_home", session_id=session_id))
        else:
            logger.error("Error: Wrong PIN attempt for wallet access.")
            flash("PIN errato. Riprova.", "error")

    return render_template("wallet_access.html")


@wallet_routes.route("/home", methods=["GET"])
def wallet_home():
    if not session.get("pin_authenticated"):
        return redirect(url_for("wallet_routes.wallet_access"))

    session_id = request.args.get("session_id", "")
    init_error_message = request.args.get("init_error_message", "")
    success_message = request.args.get("init_success_message", "")

    if init_error_message:
        flash(error_message, "init_error_message")
    elif success_message:
        flash(success_message, "init_success_message")

    selected_country = app_state.selected_country
    wallet_initialized = app_state.wallet_initialized
    credential_store = app_state.credential_store
    credential_keys = credential_store.get_store()

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
    params_list = list(request.args.items())  # Convert query parameters into a list of tuples
    current_path = request.path

    if params_list:
        logger.info("Ricevuta request GET %s con query string:", sanitize_for_logging(current_path))
        for k, v in params_list:
            logger.info("   %s = %s", sanitize_for_logging(k), sanitize_for_logging(v))
    else:
        logger.info("Ricevuta request GET %s senza query string", sanitize_for_logging(current_path))

    session["query_params"] = dict(params_list)
    oauth_authorization_server = extract_claim(current_app.config, "wallet_instance.oauth_authorization_server")
    wallet_initialized = app_state.wallet_initialized

    if oauth_authorization_server and not wallet_initialized:
        logger.info("init wallet process")
        service = ItWalletService(session)
        init_success_message = ""
        init_error_message = ""
        try:
            service.complete_initialize_wallet()
            init_success_message = "Wallet inizializzato con successo!"
        except ValueError as value_error:
            logger.error(f"Error, message: {value_error}")
            init_error_message = str(value_error)
        except Exception as exception:
            logger.error(f"Error, message: {exception}")
            init_error_message = "Exception when call discovery page. Contact administrator."
        session_id = request.args.get("session_id", "")
        return redirect(url_for("wallet_routes.wallet_home", session_id=session_id, init_success_message= init_success_message, init_error_message = init_error_message))

    return render_template("wallet_cb.html")


@wallet_routes.route("/v1/search", methods=["POST"])
def search():
    logger.info(f"Entering method: search. Params [search_type: {request.form.get('search_type')}, search_element: {request.form.get('search_element')}]")
    result = {}
    error_message = None
    success_message = None
    status_code = 200
    try:
        service = Service(session)
        result = service.search(request.form.get("search_type"), request.form.get("search_element"))
    except ValueError as ve:
        logger.error(f"Error, message: {ve}")
        error_message = str(ve)
        credential_store = app_state.credential_store
        result =  credential_store.get_store()
        status_code = 400
    except Exception as e:
        logger.error(f"Error, message: {e}")
        error_message = "Si è verificato un errore interno durante la ricerca."
        status_code = 500

    session_id = request.args.get("session_id", "")
    selected_country = app_state.selected_country
    wallet_initialized = app_state.wallet_initialized
    credential_keys = result
    return render_template(
        "wallet_home.html",
        session_id=session_id,
        selected_country=selected_country,
        wallet_initialized=wallet_initialized,
        credential_keys=credential_keys,
        success_message = success_message,
        error_message = error_message
    ), status_code

@wallet_routes.route("/template/<credential_type>", methods=["GET"])
def credentialTypeTemplate(credential_type):

    _clear_session()  # todo can remove it?

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

        dt_iat_local_formatted = unix_ts_to_str_datetime(
            int(datetime.fromisoformat(iat).timestamp()), fmt="%d-%m-%Y %H:%M:%S"
        )
        dt_exp_local_formatted = unix_ts_to_str_datetime(
            int(datetime.fromisoformat(exp).timestamp()), fmt="%d-%m-%Y %H:%M:%S"
        )

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
