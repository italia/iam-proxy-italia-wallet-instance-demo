import io
import json
import logging
from urllib.parse import quote, urlparse

import pyqrcode
from flask import Blueprint, Response, current_app, g, jsonify, request, session, url_for
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
from app.utils.http_utils import http_request_with_retry
from app.utils.utils import (
    estrai_parametro_query_string,
    guess_credential_configuration_icon,
    sanitize_for_logging,
)

logger = logging.getLogger(__name__)

_DISCOVERY_DIRECT = "openid"
_DISCOVERY_FEDERATION = "openid-federation"
_DISCOVERY_LOTL = "eudiw-lotl"
_DIRECT_WELL_KNOWN = "/.well-known/openid-credential-issuer"


def _with_credential_view_url(result: dict) -> dict:
    data = result.get("data") if isinstance(result, dict) else None
    credential_id = data.get("credential_id") if isinstance(data, dict) else None
    if not result.get("success") or not credential_id:
        return result
    from app.service.credential_view import _held_credential_views

    for index, item in enumerate(_held_credential_views()):
        if item.get("id") == credential_id:
            data["credential_name"] = item.get("name") or credential_id
            data["view_url"] = url_for("wallet_routes.wallet_credentials", _anchor=f"credential-{index}")
            break
    return result


def _ensure_member_state() -> None:
    """Issuance still reads the trust root for a member state. The page no longer asks for one."""
    if app_state.selected_country:
        return
    trust = current_app.config.get("ms_trust_configuration") or {}
    if isinstance(trust, dict) and trust:
        app_state.selected_country = next(iter(trust))


def configured_trust_anchor() -> str:
    trust = current_app.config.get("ms_trust_configuration") or {}
    italy = trust.get("IT") if isinstance(trust, dict) else None
    if not isinstance(italy, dict):
        return ""
    return str(italy.get("trust_root") or "").strip()


def configured_eudiw_lotl() -> str:
    return str(current_app.config[APP_SETTINGS_KEY].eudiw_lotl or "").strip()


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
    return [item["label"] for item in _claim_entries(config)]


def _claim_path(claim):
    if not isinstance(claim, dict):
        return None
    path = claim.get("path")
    if not isinstance(path, list) or not path:
        return None
    return path


def _claim_label(claim: dict, path: list) -> str:
    chosen = _italian_display(claim.get("display") or [])
    return str(chosen.get("name") or chosen.get("label") or path[-1]).strip()


def _claim_entries(config: dict) -> list[dict]:
    claims = (config.get("credential_metadata") or {}).get("claims") or []
    entries = []
    seen = set()
    for claim in claims:
        path = _claim_path(claim)
        if path is None:
            continue
        label = _claim_label(claim, path)
        key = tuple(str(step) for step in path)
        if not label or key in seen:
            continue
        seen.add(key)
        entries.append({"label": label, "path": [str(step) for step in path]})
    return entries


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
    return catalog.get(credential_key) or {}


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
        "claim_paths": _claim_entries(config),
        "format": credential_format,
        "format_label": _format_label(credential_format),
        "obtained": bool(app_state.credential_store.find_by_configuration_id(str(config_id))),
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


def _metadata_source(entity_id: str, discovery: str) -> str:
    if discovery != _DISCOVERY_DIRECT:
        return _federation_source(entity_id)
    base = (entity_id or "").strip().rstrip("/")
    if base.endswith(_DIRECT_WELL_KNOWN):
        return base
    return f"{base}{_DIRECT_WELL_KNOWN}"


def _stored_discovery(ec_payload) -> str:
    if not isinstance(ec_payload, dict):
        return ""
    return str(ec_payload.get("_wallet_discovery") or "")


def _credential_issuer_metadata(ec_payload: dict | None) -> dict:
    if not isinstance(ec_payload, dict):
        return {}
    metadata = (ec_payload.get("metadata") or {}).get(METADATA_TYPE_CREDENTIAL_ISSUER) or {}
    return metadata if isinstance(metadata, dict) else {}


def _offer_authorization_server(metadata: dict) -> str:
    servers = metadata.get("authorization_servers")
    if not isinstance(servers, list) or len(servers) < 2 or not isinstance(servers[0], str):
        return ""
    return servers[0].strip()


def _credential_offer_uri(issuer_uri: str, configuration_id: str, authorization_server: str = "") -> str:
    grant = {"authorization_server": authorization_server} if authorization_server else {}
    payload = {
        "credential_issuer": issuer_uri,
        "credential_configuration_ids": [configuration_id],
        "grants": {"authorization_code": grant},
    }
    encoded = quote(json.dumps(payload, separators=(",", ":")), safe="")
    return f"openid-credential-offer://?credential_offer={encoded}"


def _attach_offer_uris(uri: str, attestations: list[dict], authorization_server: str) -> None:
    for item in attestations:
        item["offer_uri"] = _credential_offer_uri(uri, str(item.get("id") or ""), authorization_server)


def _catalog_section(issuer: str, attestations: list[dict], ec_payload: dict | None = None) -> dict:
    metadata = _credential_issuer_metadata(ec_payload)
    uri = str(metadata.get("credential_issuer") or issuer or "").strip()
    name = str(_localized_display(metadata.get("display") or [], get_locale()).get("name") or "").strip()
    _attach_offer_uris(uri, attestations, _offer_authorization_server(metadata))
    return {
        "issuer": issuer,
        "name": name,
        "uri": uri,
        "source": _metadata_source(issuer, _stored_discovery(ec_payload)),
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


def _offer_qr_svg(offer: str) -> str:
    prefix = "openid-credential-offer://?credential_offer="
    if not offer.startswith(prefix) or len(offer) > 4096:
        raise ValueError("invalid credential offer")
    buffer = io.BytesIO()
    pyqrcode.create(offer, error="M").svg(buffer, scale=4, quiet_zone=2)
    return buffer.getvalue().decode("utf-8")


def _parse_direct_metadata(response) -> dict:
    metadata = response.json()
    if not isinstance(metadata, dict):
        raise ValueError("credential issuer metadata is not an object")
    return metadata


def _direct_issuer_payload(service: ItWalletService, issuer_url: str) -> dict:
    metadata = http_request_with_retry(
        "GET",
        f"{issuer_url.rstrip('/')}{_DIRECT_WELL_KNOWN}",
        headers={"Accept": "application/json"},
        proxies=service.proxies,
        no_proxy_domains=service.no_proxy_domains,
        parse_response=_parse_direct_metadata,
    )
    issuer = str(metadata.get("credential_issuer") or issuer_url).strip()
    return {
        "iss": issuer,
        "metadata": {METADATA_TYPE_CREDENTIAL_ISSUER: metadata},
        "_wallet_discovery": _DISCOVERY_DIRECT,
    }


def _fetch_issuer_payload(service: ItWalletService, issuer_url: str, discovery: str) -> dict:
    if discovery == _DISCOVERY_DIRECT:
        return _direct_issuer_payload(service, issuer_url)
    payload = service._entity_configuration_management(issuer_url, [METADATA_TYPE_CREDENTIAL_ISSUER])
    payload["_wallet_discovery"] = _DISCOVERY_FEDERATION
    return payload


def _discovery_rejection(discovery: str) -> str:
    if discovery == _DISCOVERY_LOTL:
        return _("eudiw lotl non è ancora implementato.")
    if discovery not in (_DISCOVERY_DIRECT, _DISCOVERY_FEDERATION):
        return _("Seleziona una modalità di discovery.")
    return ""


def _store_discovered_issuer(issuer_url: str, discovery: str):
    peer = peer_role.set("credential_issuer")
    try:
        service = ItWalletService(session)
        ec_payload = _fetch_issuer_payload(service, issuer_url, discovery)
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


def _issuer_catalog_post():
    body = request.get_json(silent=True) or {}
    issuer_url = (body.get("issuerUrl") or "").strip()
    parsed = urlparse(issuer_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return jsonify({"success": False, "field": "issuerUrl", "message": _("Inserisci un URL http o https.")}), 400
    discovery = (body.get("discovery") or _DISCOVERY_FEDERATION).strip()
    rejected = _discovery_rejection(discovery)
    if rejected:
        return jsonify({"success": False, "field": "discovery", "message": rejected}), 400
    return _store_discovered_issuer(issuer_url, discovery)


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
