import base64
import hmac
import json
import logging
import zlib
from datetime import date, datetime
from urllib.parse import urlparse

import cbor2
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_babel import gettext as _

from app.constants import (
    APP_SETTINGS_KEY,
    JWT_PREFIX,
    METADATA_TYPE_CREDENTIAL_ISSUER,
    MSO_MDOC_PREFIX,
    SD_JWT_PREFIX,
)
from app.routes.itwallet_routes import (
    _catalog_sections,
    _ensure_member_state,
    _format_label,
    configured_eudiw_lotl,
    configured_issuer_urls,
    configured_trust_anchor,
    display_index,
    load_configured_issuers,
    lookup_attestation,
)
from app.service.itwallet_service import ItWalletService
from app.store import app_state
from app.utils.diagnostic_log import peer_role
from app.utils.itwalletUtils import request_status_list
from app.utils.jwtUtils import decode_and_verify_jwt
from app.utils.parsers import parser_credential_format_to_internal
from app.utils.utils import (
    extract_claim,
    generate_nonce,
    parse_url_to_dict,
    remove_str_prefix,
    sanitize_for_logging,
    unescape_json,
)

from ..utils.type_utils import get_type_from_key

from app.service.credential_view import (
    _b64url,
    _json_text,
    _jwt_part_json,
    _jwt_cleartext,
    _sd_jwt_cleartext,
    _jsonable_tag,
    _jsonable_items,
    _jsonable,
    _cose_key,
    _cbor_diag_items,
    _cbor_diag,
    _decoded_cbor,
    _cose_headers_text,
    _cose_sign1,
    _mdoc_cleartext,
    _credential_cleartext,
    _or_text,
    _held_entries,
    _is_held_entry,
    _held_view,
    _held_credential_views,
    _find_held_credential,
)

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


@wallet_routes.app_template_filter("format_date")
def format_date(value, fmt="%d-%m-%Y %H:%M:%S"):
    """
    Formats a date value for display.
    Accepts:
      - int/float  → Unix timestamp (UTC) → formatted date string
      - str        → ISO 8601 date or datetime string → formatted date string
    Returns str(value) if unparseable, empty string if None.
    """
    from datetime import timezone

    if value is None:
        return ""
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime(fmt)
        if isinstance(value, str):
            normalized = value.strip().replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).strftime(fmt)
    except (ValueError, OSError, OverflowError, TypeError):
        pass
    return str(value)


@wallet_routes.app_template_filter("format_credential")
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


def safe_next_path(raw: str | None) -> str | None:
    """Accept only a same-app relative path. Reject external and protocol-relative URLs."""
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate.startswith("/") or candidate.startswith("//") or "\\" in candidate or "://" in candidate:
        return None
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    if parsed.path in ("/wallet/access", "/wallet/activate"):
        return None
    return candidate


def redirect_to_login(target: str):
    from urllib.parse import urlencode

    return redirect(f"{url_for('wallet_routes.wallet_access')}?{urlencode({'next': target})}")


@wallet_routes.route("/lang/<lang_code>", methods=["GET"])
def set_language(lang_code: str):
    if lang_code not in ("it", "en"):
        lang_code = "it"
    session["lang"] = lang_code
    destination = (request.args.get("next") or "").strip()
    parsed = urlparse(destination)
    if destination.startswith("/") and not destination.startswith("//") and not parsed.scheme and not parsed.netloc:
        return redirect(destination)
    return redirect(url_for("wallet_routes.wallet_access"))


@wallet_routes.route("/activate", methods=["GET", "POST"])
def show_activation():
    return redirect(url_for("wallet_routes.wallet_access"))


@wallet_routes.route("/access", methods=["GET", "POST"])
def wallet_access():
    logger.info("Entering method: wallet_access. Params []")
    if request.method == "POST":
        password_attempt = request.form.get("password", "")
        configured = current_app.config[APP_SETTINGS_KEY].app.password
        if password_attempt and hmac.compare_digest(password_attempt, configured):
            session["authenticated"] = True

            if not request.args.get("session_id"):
                logger.info("No session_id in request, generating new one.")
                session_id = generate_nonce()
                session["session_id"] = session_id
            else:
                session_id = request.args.get("session_id")
                session["session_id"] = session_id

            logger.info(f"session_id: {session_id} authenticated successfully.")
            destination = safe_next_path(request.form.get("next") or request.args.get("next"))
            if destination:
                return redirect(destination)
            return redirect(url_for("wallet_routes.wallet_home", session_id=session_id))
        else:
            logger.error("Error: Wrong password attempt for wallet access.")
            flash(_("Password non corretta."), "error")

    return render_template("wallet_access.html", next_path=safe_next_path(request.args.get("next")) or "")


@wallet_routes.route("/home", methods=["GET"])
def wallet_home():
    logger.info(f"Entering method: wallet_home. Params [session_id: {request.args.get('session_id', '')}]")

    if not session.get("authenticated"):
        target = request.path
        if request.query_string:
            target = f"{request.path}?{request.query_string.decode()}"
        return redirect_to_login(target)

    _ensure_member_state()
    catalog_error = load_configured_issuers()
    attestations = display_index()

    session_id = request.args.get("session_id", "")
    init_error_message = request.args.get("init_error_message", "")
    init_success_message = request.args.get("init_success_message", "")

    if init_error_message:
        flash(init_error_message, "init_error_message")
    elif init_success_message:
        flash(init_success_message, "init_success_message")

    selected_country = app_state.selected_country
    credential_store = app_state.credential_store
    credential_keys = credential_store.get_store()

    return render_template(
        "wallet_home.html",
        session_id=session_id,
        selected_country=selected_country,
        wallet_initialized=app_state.wallet_initialized,
        credential_keys=credential_keys,
        catalog_sections=_catalog_sections(),
        display_index=attestations,
        catalog_error=catalog_error,
        default_issuer_url=(configured_issuer_urls() or [""])[0],
        default_trust_anchor=configured_trust_anchor(),
        eudiw_lotl_url=configured_eudiw_lotl(),
        init_error_message=init_error_message,
        init_success_message=init_success_message,
    )


_STATUS_LIST_CODES = {0: "valid", 1: "revoked", 2: "suspended"}














































def _require_session():
    if session.get("authenticated"):
        return None
    target = request.path
    if request.query_string:
        target = f"{request.path}?{request.query_string.decode()}"
    return redirect_to_login(target)


@wallet_routes.route("/credentials", methods=["GET"])
def wallet_credentials():
    denied = _require_session()
    if denied:
        return denied
    _ensure_member_state()
    load_configured_issuers()
    return render_template("wallet_credentials.html", credentials=_held_credential_views())


def _status_list_ref(token: str) -> tuple[str, int] | None:
    compact = token.split("~", 1)[0]
    parts = compact.split(".")
    if len(parts) < 2 or not parts[1]:
        return None
    payload = _jwt_part_json(parts[1])
    status = payload.get("status") if isinstance(payload, dict) else None
    listed = status.get("status_list") if isinstance(status, dict) else None
    if not isinstance(listed, dict) or not isinstance(listed.get("uri"), str):
        return None
    try:
        index = int(listed.get("idx"))
    except (TypeError, ValueError):
        return None
    return listed["uri"], index


def _status_list_code(lst: str, bits: int, index: int) -> int:
    if bits not in (1, 2, 4, 8) or index < 0:
        raise ValueError("Indice di status list non valido")
    padded = lst + "=" * (-len(lst) % 4)
    raw = zlib.decompress(base64.urlsafe_b64decode(padded))
    total = (len(raw) * 8) // bits
    if index >= total:
        raise ValueError("Indice di status list fuori dall'elenco")
    jump = bits * index
    return (raw[jump // 8] >> (jump % 8)) & ((1 << bits) - 1)


def _credentials_page():
    return redirect(url_for("wallet_routes.wallet_credentials"))


def _issuer_status_jwks(stored_issuer):
    ec = app_state.ec_store.get(stored_issuer)
    if not isinstance(ec, dict):
        return None
    return extract_claim(ec, f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks")


def _require_status_list(claims, status_uri):
    if not isinstance(claims, dict):
        raise ValueError("La status list non contiene l'elenco degli stati")
    if claims.get("sub") != status_uri:
        raise ValueError("Il subject della status list non coincide con l'URI dell'attestazione")
    status_list = claims.get("status_list")
    if isinstance(status_list, dict) and isinstance(status_list.get("lst"), str):
        return status_list
    raise ValueError("La status list non contiene l'elenco degli stati")


def _store_status_list(credential_id, status_uri, status_idx, jwks, service):
    token = request_status_list(status_uri, proxies=service.proxies, no_proxy_domains=service.no_proxy_domains)
    status_list = _require_status_list(decode_and_verify_jwt(token, jwks), status_uri)
    code = _status_list_code(status_list["lst"], int(status_list.get("bits") or 1), status_idx)
    app_state.credential_store.update_status(credential_id, token, _STATUS_LIST_CODES.get(code, str(code)))
    return code


def _flash_status_result(code: int) -> None:
    if code == 0:
        flash(_("La credenziale è valida e non risulta essere stata revocata."), "success")
        return
    if code == 1:
        flash(_("La credenziale risulta revocata."), "error")
        return
    if code == 2:
        flash(_("La credenziale risulta sospesa."), "error")
        return
    flash(_("Lo stato della credenziale non è riconosciuto."), "error")


def _flash_status_failure(exc):
    logger.error("❌ %s", sanitize_for_logging(str(exc)))
    reason = " ".join(str(exc).split())
    if len(reason) > 500:
        reason = reason[:500] + "…"
    if reason:
        flash(_("Impossibile verificare lo stato di revoca. %(reason)s") % {"reason": reason}, "error")
        return
    flash(_("Impossibile verificare lo stato di revoca."), "error")


@wallet_routes.route("/credentials/status", methods=["POST"])
def credential_status():
    denied = _require_session()
    if denied:
        return denied
    credential_id = (request.form.get("credential_id") or "").strip()
    issuer = (request.form.get("issuer") or "").strip()
    _ensure_member_state()
    load_configured_issuers()
    stored_issuer, entry = _find_held_credential(issuer, credential_id)
    token = entry.get("data_row") if isinstance(entry, dict) else None
    if not isinstance(token, str):
        flash(_("Attestazione non trovata."), "error")
        return _credentials_page()
    listed = _status_list_ref(token)
    if not listed:
        flash(_("Questa attestazione non contiene una status list."), "error")
        return _credentials_page()
    jwks = _issuer_status_jwks(stored_issuer)
    if not isinstance(jwks, dict):
        flash(_("Questo issuer non pubblica l'endpoint di stato."), "error")
        return _credentials_page()
    service = ItWalletService(session)
    peer = peer_role.set("credential_issuer")
    try:
        _flash_status_result(_store_status_list(credential_id, listed[0], listed[1], jwks, service))
    except Exception as exc:
        _flash_status_failure(exc)
    finally:
        peer_role.reset(peer)
    return _credentials_page()


@wallet_routes.route("/credentials/delete", methods=["POST"])
def credential_delete():
    denied = _require_session()
    if denied:
        return denied
    credential_id = (request.form.get("credential_id") or "").strip()
    issuer = (request.form.get("issuer") or "").strip()
    _ensure_member_state()
    load_configured_issuers()
    stored_issuer, entry = _find_held_credential(issuer, credential_id)
    if not entry:
        flash(_("Attestazione non trovata."), "error")
        return redirect(url_for("wallet_routes.wallet_credentials"))
    if not app_state.credential_store.remove_held(stored_issuer or issuer, credential_id):
        flash(_("Impossibile rimuovere l'attestazione."), "error")
        return redirect(url_for("wallet_routes.wallet_credentials"))
    flash(_("Attestazione rimossa."), "success")
    return redirect(url_for("wallet_routes.wallet_credentials"))


@wallet_routes.route("/present", methods=["GET"])
def wallet_present():
    denied = _require_session()
    if denied:
        return denied
    return render_template("wallet_present.html")


@wallet_routes.route("/diagnostics", methods=["GET"])
def wallet_diagnostics():
    denied = _require_session()
    if denied:
        return denied
    return render_template("wallet_diagnostics.html")


@wallet_routes.route("/logout", methods=["GET"])
def logout():
    session_id = session.get("session_id", "")
    lang = session.get("lang")
    # codeql[py/log-injection]
    logger.info("✅ Effettuato logout (sessione cancellata id=%s).", sanitize_for_logging(session_id))
    session.clear()
    if lang:
        session["lang"] = lang
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
    return render_template("wallet_cb.html")


@wallet_routes.route("/detail", methods=["POST"], strict_slashes=False)
def credential_detail():
    denied = _require_session()
    if denied:
        return denied

    logger.debug("Entering method: credential_detail.")
    body = request.get_json()
    issuer = body["issuer"]
    key = body["key"]
    _clear_session()  # todo can remove it?
    # if not (result := app_state.credential_store.find_by_prefix_with_key(credential_type)):

    if not (response := app_state.credential_store._get_credential_into_store(issuer, key)):
        logger.error(f"CredentialTypeTemplate: issuer or key not found in credentialStore for key: {key}")
        return (
            "Nessuna credenziale di tipo richiesto trovata nel wallet",
            400,
        )  # i18n? @Todo Talking with Giuseppe for i18n implementation

    logger.info(f"credential_detail: result: {response}")

    # key, value = result
    # logger.info("Recuperata dalla memoria credenziale con chiave %s", sanitize_for_logging(key))

    # vct = value.get("vct", "")
    # logger.info("Il vct della credenziale %s è: %s", sanitize_for_logging(key), sanitize_for_logging(vct))

    # @TODO Talking with Giuseppe for Status list

    # status = value.get("status", "")
    # status_descr = get_status_description(status)
    # logger.info(
    #     "La credenziale %s è in stato: %s %s",
    #     sanitize_for_logging(key),
    #     sanitize_for_logging(status),
    #     sanitize_for_logging(status_descr),
    # )

    claims = response.get("claims", {})
    claims = unescape_json(claims)

    status = "0x01"
    status_descr = "VALIDO"

    data_row = response.get("data_row", {})
    internal_claims = parser_credential_format_to_internal(
        current_app.config[APP_SETTINGS_KEY].credentials_config, key.rsplit("_", 1)[0], claims
    )

    # @TODO Decprecated
    content_list = []
    # if content and content.startswith(CONTENT_PDF_BASE_64_PREFIX):
    #     logger.debug("La credenziale presenta un claim 'content' contenente dati pdf_base64")
    #     content_list = extract_text_from_base64_pdf(content)
    #
    #     if content_list and len(content_list) > 0:
    #         logger.debug("Il PDF contiene almeno una pagina con contenuto.")
    #         for i, pagina in enumerate(content_list, start=1):
    #             logger.debug("Pagina %d:\n%s\n%s", i, sanitize_for_logging(pagina), "-" * 40)

    try:
        return render_template(
            "template_detail.html",
            data_row=data_row,
            internal_claims=internal_claims,
            claims=claims,
            metadata=internal_claims.get("metadata"),
            status=status,
            statusDecr=status_descr,
            contentList=content_list,
            type=get_type_from_key(key),
        )
    except Exception as e:
        logger.error("%s", sanitize_for_logging(str(e)))
        return "Nessun template trovato per la credenziale nel wallet", 500


@wallet_routes.route("/presentation", methods=["POST"], strict_slashes=False)
def presentation_phase():
    denied = _require_session()
    if denied:
        return denied
    logger.debug("Entering method: presentation.")
    body = request.get_json()
    qrcode_data = body["qrcode_data"]
    _clear_session()  # todo can remove it?
    print(f"qrcode_data: {qrcode_data}")

    it_wallet_service = ItWalletService(session, external_discovery=True)
    try:
        params = parse_url_to_dict(qrcode_data)
        credentials = it_wallet_service.present_to_verifier(
            params.get("client_id"), params.get("request_uri"), params.get("request_uri_method"), params.get("state")
        )
    except Exception as e:
        logger.error(f"Error, message: {e}")
        # @Todo insert this into Util
        return jsonify({"success": False, "error_message": f"Exception :{e}."}), 400
    return jsonify({"success": True, "success_message": "Login success.", "data": credentials}), 200


@wallet_routes.route("/authorization", methods=["POST"], strict_slashes=False)
def authorization_phase():
    denied = _require_session()
    if denied:
        return denied
    logger.debug("Entering method: authorization.")
    body = request.get_json()
    credentials_presenting = body["credentialsPresenting"]
    it_wallet_service = ItWalletService(session, external_discovery=True)
    try:
        result = it_wallet_service.complete_presentation(credentials_presenting)
        status_code = 200 if result["success"] else 500
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error, message: {e}")
        # @Todo insert this into Util
        return jsonify({"success": False, "error_message": f"Exception :{e}."}), 400


def _clear_session():
    preserved = {"session_id": session.get("session_id"), "authenticated": session.get("authenticated")}
    session.clear()
    session.update({k: v for k, v in preserved.items() if v is not None})
