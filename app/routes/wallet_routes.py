import base64
import hmac
import json
import logging
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
    display_index,
    load_configured_issuers,
    lookup_attestation,
)
from app.service.itwallet_service import ItWalletService
from app.service.v1.service import Service
from app.store import app_state
from app.utils.parsers import parser_credential_format_to_internal
from app.utils.diagnostic_log import peer_role
from app.utils.utils import (
    extract_claim,
    generate_nonce,
    parse_url_to_dict,
    remove_str_prefix,
    sanitize_for_logging,
    unescape_json,
)

from ..utils.type_utils import get_type_from_key

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
        init_error_message=init_error_message,
        init_success_message=init_success_message,
    )


_STATUS_LABELS = {
    "valid": "Valida",
    "revoked": "Revocata",
    "suspended": "Sospesa",
}


_SD_JWT_FORMATS = {"dc+sd-jwt", "vc+sd-jwt"}
_MDOC_FORMATS = {"mso_mdoc"}
_COSE_ALGS = {-7: "ES256", -35: "ES384", -36: "ES512", -8: "EdDSA", -257: "RS256"}


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_text(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


def _jwt_part_json(part: str):
    raw = _b64url(part)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode("utf-8", errors="replace")


def _jwt_cleartext(token) -> dict | None:
    if not isinstance(token, str):
        return None
    compact = token.split("~", 1)[0].strip()
    parts = compact.split(".")
    if len(parts) < 3 or not parts[0] or not parts[1]:
        return None
    try:
        return {"header": _json_text(_jwt_part_json(parts[0])), "payload": _json_text(_jwt_part_json(parts[1]))}
    except Exception:
        return None


def _sd_jwt_cleartext(token: str) -> dict | None:
    view = _jwt_cleartext(token)
    if not view:
        return None
    disclosures = []
    for piece in token.strip().split("~")[1:]:
        if not piece or piece.count(".") >= 2:
            continue
        try:
            disclosures.append(json.loads(_b64url(piece)))
        except Exception:
            disclosures.append(piece)
    view["disclosures"] = _json_text(disclosures)
    return view


def _jsonable(value):
    if isinstance(value, cbor2.CBORTag):
        if value.tag == 24 and isinstance(value.value, (bytes, bytearray)):
            try:
                return _jsonable(cbor2.loads(value.value))
            except Exception:
                return base64.b64encode(value.value).decode("ascii")
        return {"tag": value.tag, "value": _jsonable(value.value)}
    if isinstance(value, dict):
        return {_cose_key(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _cose_key(key):
    names = {1: "alg", 4: "kid"}
    if key in names:
        return names[key]
    return str(key) if isinstance(key, int) else key


def _cose_sign1(value):
    if isinstance(value, cbor2.CBORTag):
        value = value.value
    if not isinstance(value, (list, tuple)) or len(value) < 3:
        return None
    protected, _unprotected, payload = value[0], value[1], value[2]
    header = cbor2.loads(protected) if isinstance(protected, (bytes, bytearray)) else protected
    if isinstance(header, dict) and header.get(1) in _COSE_ALGS:
        header = dict(header)
        header[1] = _COSE_ALGS[header[1]]
    body = cbor2.loads(payload) if isinstance(payload, (bytes, bytearray)) else payload
    return {"header": _json_text(_jsonable(header)), "payload": _json_text(_jsonable(body))}


def _mdoc_cleartext(token: str) -> dict | None:
    if not isinstance(token, str) or not token.strip():
        return None
    try:
        issuer_signed = cbor2.loads(_b64url(token.strip()))
    except Exception:
        return None
    if not isinstance(issuer_signed, dict):
        return None
    signed = _cose_sign1(issuer_signed.get("issuerAuth"))
    if not signed:
        return None
    namespaces = issuer_signed.get("nameSpaces") or {}
    signed["disclosures"] = _json_text(_jsonable(namespaces))
    return signed


def _credential_cleartext(token, credential_format: str, credential_id: str) -> dict | None:
    fmt = (credential_format or "").lower()
    key = str(credential_id or "")
    if fmt in _SD_JWT_FORMATS or key.startswith(SD_JWT_PREFIX):
        return _sd_jwt_cleartext(token) if isinstance(token, str) else None
    if fmt in _MDOC_FORMATS or key.startswith(MSO_MDOC_PREFIX):
        return _mdoc_cleartext(token) if isinstance(token, str) else None
    return _jwt_cleartext(token)


def _held_credential_views() -> list[dict]:
    views = []
    store = app_state.credential_store.get_store() or {}
    index = display_index()
    for issuer, group in store.items():
        if not isinstance(group, dict):
            continue
        entries = {issuer: group} if "data_row" in group else group
        for credential_id, entry in entries.items():
            if not isinstance(entry, dict) or "data_row" not in entry:
                continue
            meta = lookup_attestation(str(credential_id), index)
            status = str(entry.get("status") or "").strip()
            views.append(
                {
                    "issuer": "" if "data_row" in group else issuer,
                    "id": credential_id,
                    "name": meta.get("name") or credential_id,
                    "description": meta.get("description") or "",
                    "format": meta.get("format") or "",
                    "format_label": meta.get("format_label") or _format_label(meta.get("format") or ""),
                    "claims": meta.get("claims") or [],
                    "config_id": meta.get("id") or credential_id,
                    "credential": _credential_cleartext(entry.get("data_row"), meta.get("format") or "", credential_id),
                    "status_label": _STATUS_LABELS.get(status.lower(), status or "Non verificata"),
                    "assertion": _jwt_cleartext(entry.get("status_assertion")),
                }
            )
    return views


def _find_held_credential(issuer: str, credential_id: str):
    store = app_state.credential_store.get_store() or {}
    group = store.get(issuer)
    if isinstance(group, dict):
        if "data_row" in group and credential_id == issuer:
            return issuer, group
        entry = group.get(credential_id)
        if isinstance(entry, dict):
            return issuer, entry
    for stored_issuer, stored_group in store.items():
        if isinstance(stored_group, dict) and isinstance(stored_group.get(credential_id), dict):
            return stored_issuer, stored_group[credential_id]
    return None, None


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
    if not entry or not isinstance(entry.get("data_row"), str):
        flash(_("Attestazione non trovata."), "error")
        return redirect(url_for("wallet_routes.wallet_credentials"))
    if "~" not in entry["data_row"] and not entry["data_row"].startswith("eyJ"):
        flash(_("Lo stato di revoca si può verificare solo per le attestazioni SD-JWT."), "error")
        return redirect(url_for("wallet_routes.wallet_credentials"))
    ec = app_state.ec_store.get(stored_issuer)
    status_url = extract_claim(ec, f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.status_assertion_endpoint") if isinstance(ec, dict) else None
    jwks = extract_claim(ec, f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks") if isinstance(ec, dict) else None
    if not status_url or not isinstance(jwks, dict):
        flash(_("Questo issuer non pubblica l'endpoint di stato."), "error")
        return redirect(url_for("wallet_routes.wallet_credentials"))
    peer = peer_role.set("credential_issuer")
    try:
        ItWalletService(session)._status_assertion_management(status_url, jwks, credential_id, entry["data_row"])
        flash(_("Stato di revoca aggiornato."), "success")
    except Exception as exc:
        logger.error("❌ %s", sanitize_for_logging(str(exc)))
        reason = " ".join(str(exc).split())
        if len(reason) > 500:
            reason = reason[:500] + "…"
        if reason:
            flash(_("Impossibile verificare lo stato di revoca. %(reason)s") % {"reason": reason}, "error")
        else:
            flash(_("Impossibile verificare lo stato di revoca."), "error")
    finally:
        peer_role.reset(peer)
    return redirect(url_for("wallet_routes.wallet_credentials"))


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


@wallet_routes.route("/v1/search", methods=["POST"])
def search():
    search_type = (request.form.get("search_type") or "").strip()
    search_element = (request.form.get("search_element") or "").strip()
    logger.info(
        f"Entering method: search. Params [search_type: {search_type}, search_element: {search_element}]"
    )
    result = app_state.credential_store.get_store()
    search_type_error = None
    search_element_error = None
    status_code = 200
    allowed_types = {"scope", "credential_issuer", "attribute"}
    if not search_type:
        search_type_error = _("Scegli il tipo di ricerca.")
    elif search_type not in allowed_types:
        search_type_error = _("Questo tipo di ricerca non è disponibile.")
    if not search_element:
        search_element_error = _("Scrivi cosa cercare.")
    if search_type_error or search_element_error:
        status_code = 400
    else:
        try:
            service = Service(session)
            result = service.search(search_type, search_element)
        except ValueError as ve:
            logger.error(f"Error, message: {ve}")
            search_element_error = _(str(ve))
            status_code = 400
        except Exception as e:
            logger.error(f"Error, message: {e}")
            search_element_error = _("Si è verificato un errore interno durante la ricerca.")
            status_code = 500

    session_id = request.args.get("session_id", "")
    selected_country = app_state.selected_country
    wallet_initialized = app_state.wallet_initialized
    _ensure_member_state()
    catalog_error = load_configured_issuers()
    return render_template(
        "wallet_home.html",
        session_id=session_id,
        selected_country=selected_country,
        wallet_initialized=wallet_initialized,
        credential_keys=result,
        catalog_sections=_catalog_sections(),
        display_index=display_index(),
        catalog_error=catalog_error,
        search_type=search_type,
        search_element=search_element,
        search_type_error=search_type_error,
        search_element_error=search_element_error,
    ), status_code


@wallet_routes.route("/detail", methods=["POST"], strict_slashes=False)
def credentialTypeTemplate():

    logger.debug("Entering method: credentialTypeTemplate.")
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

    logger.info(f"credentialTypeTemplate: result: {response}")

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
    logger.debug("Entering method: presentation.")
    body = request.get_json()
    qrcode_data = body["qrcode_data"]
    _clear_session()  # todo can remove it?
    print(f"qrcode_data: {qrcode_data}")

    it_wallet_service = ItWalletService(session, external_discovery=True)
    try:
        params = parse_url_to_dict(qrcode_data)
        credentials = it_wallet_service.loginToVerifier(
            params.get("client_id"), params.get("request_uri"), params.get("request_uri_method"), params.get("state")
        )
    except Exception as e:
        logger.error(f"Error, message: {e}")
        # @Todo insert this into Util
        return jsonify({"success": False, "error_message": f"Exception :{e}."}), 400
    return jsonify({"success": True, "success_message": "Login success.", "data": credentials}), 200


@wallet_routes.route("/authorization", methods=["POST"], strict_slashes=False)
def authorization_phase():
    logger.debug("Entering method: authorization.")
    body = request.get_json()
    credentials_presenting = body["credentialsPresenting"]
    it_wallet_service = ItWalletService(session, external_discovery=True)
    try:
        result = it_wallet_service.complete_loginToVerifier(credentials_presenting)
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
