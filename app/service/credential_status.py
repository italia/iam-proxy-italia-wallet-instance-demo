"""Status List read and the presentation check for expiry and revocation."""

import base64
import logging
import time
import zlib
from datetime import datetime, timezone

from flask import session
from flask_babel import gettext as _

from app.constants import METADATA_TYPE_CREDENTIAL_ISSUER
from app.service.credential_view import _jwt_part_json
from app.store import app_state
from app.utils.diagnostic_log import peer_role
from app.utils.itwalletUtils import request_status_list
from app.utils.jwtUtils import decode_and_verify_jwt
from app.utils.utils import extract_claim, sanitize_for_logging

logger = logging.getLogger(__name__)


def status_list_ref(token: str) -> tuple[str, int] | None:
    compact = token.split("~", 1)[0]
    parts = compact.split(".")
    if len(parts) < 2 or not parts[1]:
        return None
    payload = _jwt_part_json(parts[1])
    return _listed_status(payload if isinstance(payload, dict) else None)


def _listed_status(payload) -> tuple[str, int] | None:
    status = payload.get("status") if isinstance(payload, dict) else None
    listed = status.get("status_list") if isinstance(status, dict) else None
    if not isinstance(listed, dict) or not isinstance(listed.get("uri"), str):
        return None
    try:
        index = int(listed.get("idx"))
    except (TypeError, ValueError):
        return None
    return listed["uri"], index


def status_list_code(lst: str, bits: int, index: int) -> int:
    if bits not in (1, 2, 4, 8) or index < 0:
        raise ValueError("Indice di status list non valido")
    padded = lst + "=" * (-len(lst) % 4)
    raw = zlib.decompress(base64.urlsafe_b64decode(padded))
    total = (len(raw) * 8) // bits
    if index >= total:
        raise ValueError("Indice di status list fuori dall'elenco")
    jump = bits * index
    return (raw[jump // 8] >> (jump % 8)) & ((1 << bits) - 1)


def issuer_status_jwks(stored_issuer):
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


def store_status_list(credential_id, status_uri, status_idx, jwks, service):
    token = request_status_list(status_uri, proxies=service.proxies, no_proxy_domains=service.no_proxy_domains)
    claims = decode_and_verify_jwt(token, jwks)
    status_list = _require_status_list(claims, status_uri)
    code = status_list_code(status_list["lst"], int(status_list.get("bits") or 1), status_idx)
    app_state.credential_store.update_status(credential_id, token, {0: "valid", 1: "revoked", 2: "suspended"}.get(code, str(code)))
    return code, claims


def _moment(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value > 0:
        return int(value)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    return None


def _expiry_moment(entry: dict) -> int | None:
    token = entry.get("data_row")
    if isinstance(token, str):
        parts = token.split("~", 1)[0].split(".")
        if len(parts) >= 2 and parts[1]:
            payload = _jwt_part_json(parts[1])
            moment = _moment(payload.get("exp") if isinstance(payload, dict) else None)
            if moment is not None:
                return moment
    claims = entry.get("claims") if isinstance(entry.get("claims"), dict) else {}
    moment = _moment(claims.get("exp"))
    if moment is not None:
        return moment
    mobile = claims.get("mso") if isinstance(claims.get("mso"), dict) else {}
    validity = mobile.get("validityInfo") if isinstance(mobile.get("validityInfo"), dict) else {}
    return _moment(validity.get("validUntil"))


def _is_expired(entry: dict) -> bool:
    moment = _expiry_moment(entry)
    return moment is not None and moment <= int(time.time())


def _issuer_for(credential_key: str) -> str:
    store = app_state.credential_store.get_store() or {}
    for issuer, group in store.items():
        if not isinstance(group, dict):
            continue
        if "data_row" in group and credential_key == issuer:
            return str(issuer)
        if isinstance(group.get(credential_key), dict):
            return str(issuer)
    return ""


def _credential_name(key: str, entry: dict) -> str:
    configuration_id = str(entry.get("configuration_id") or "").strip()
    meta = {}
    if configuration_id:
        from app.service.catalog import lookup_attestation

        try:
            found = lookup_attestation(configuration_id)
        except Exception:
            found = {}
        if isinstance(found, dict):
            meta = found
    name = str(meta.get("name") or "").strip()
    if name:
        return name
    vct = entry.get("vct")
    if isinstance(vct, str) and vct:
        return vct
    return key


def _revocation(entry: dict, issuer: str, credential_key: str, service) -> str:
    token = entry.get("data_row")
    listed = status_list_ref(token) if isinstance(token, str) else None
    if not listed:
        claims = entry.get("claims") if isinstance(entry.get("claims"), dict) else None
        listed = _listed_status(claims)
    if not listed:
        return "absent"
    jwks = issuer_status_jwks(issuer)
    if not isinstance(jwks, dict):
        return "unknown"
    peer = peer_role.set("credential_issuer")
    try:
        code, _claims = store_status_list(credential_key, listed[0], listed[1], jwks, service)
    except Exception as exc:
        logger.error("❌ %s", sanitize_for_logging(str(exc)))
        return "unknown"
    finally:
        peer_role.reset(peer)
    if code == 0:
        return "valid"
    if code == 2:
        return "suspended"
    return "revoked"


def _matching_hold(item: dict):
    from app.service.presentation_flow import _held_by_doctype, _held_by_vct

    meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
    if item.get("format") == "mso_mdoc":
        found = _held_by_doctype(meta)
    else:
        found = _held_by_vct(meta)
    if not found:
        return None
    key, entry = found
    if not isinstance(entry, dict):
        return None
    return _issuer_for(str(key)), str(key), entry


def collect_presentation_issues(items, service) -> list[dict]:
    if not isinstance(items, list):
        return []
    issues = []
    for item in items:
        if not isinstance(item, dict):
            continue
        located = _matching_hold(item)
        if not located:
            continue
        issuer, key, entry = located
        expired = _is_expired(entry)
        revocation = _revocation(entry, issuer, key, service)
        if not expired and revocation in ("valid", "absent"):
            continue
        issues.append(
            {
                "name": _credential_name(key, entry),
                "expired": expired,
                "revoked": revocation == "revoked",
                "suspended": revocation == "suspended",
                "status_unknown": revocation == "unknown",
            }
        )
    return issues


def _choice(count: int) -> str:
    if count == 1:
        return _("Puoi presentarla comunque oppure richiedere una nuova emissione.")
    return _("Puoi presentarle comunque oppure richiedere una nuova emissione.")


def _reissue(names: list[str]) -> str:
    if len(names) == 1:
        return _("Richiedi una nuova emissione della credenziale %(name)s.") % {"name": names[0]}
    return _("Richiedi una nuova emissione delle credenziali %(names)s.") % {"names": ", ".join(names)}


def _issue_sentences(issue: dict) -> tuple[list[str], str]:
    name = issue["name"]
    expired = _("La credenziale %(name)s è scaduta.") % {"name": name}
    revoked = _("La credenziale %(name)s risulta revocata.") % {"name": name}
    suspended = _("La credenziale %(name)s risulta sospesa.") % {"name": name}
    sentences = []
    failure = ""
    if issue["expired"] and issue["revoked"]:
        sentences.extend((expired, revoked))
        failure = _("Il verificatore ha rifiutato la presentazione perché la credenziale %(name)s è scaduta e risulta revocata.") % {"name": name}
    elif issue["expired"] and issue["suspended"]:
        sentences.extend((expired, suspended))
        failure = _("Il verificatore ha rifiutato la presentazione perché la credenziale %(name)s è scaduta e risulta sospesa.") % {"name": name}
    elif issue["expired"]:
        sentences.append(expired)
        failure = _("Il verificatore ha rifiutato la presentazione perché la credenziale %(name)s è scaduta.") % {"name": name}
    elif issue["revoked"]:
        sentences.append(revoked)
        failure = _("Il verificatore ha rifiutato la presentazione perché la credenziale %(name)s risulta revocata.") % {"name": name}
    elif issue["suspended"]:
        sentences.append(suspended)
        failure = _("Il verificatore ha rifiutato la presentazione perché la credenziale %(name)s risulta sospesa.") % {"name": name}
    if issue["status_unknown"]:
        sentences.append(_("Impossibile verificare lo stato di revoca della credenziale %(name)s.") % {"name": name})
    return sentences, failure


def presentation_dialog(issues: list[dict]) -> dict:
    if not issues:
        return {}
    sentences = []
    failures = []
    names = []
    for issue in issues:
        names.append(issue["name"])
        said, failure = _issue_sentences(issue)
        sentences.extend(said)
        if failure:
            failures.append(failure)
    sentences.append(_choice(len(issues)))
    return {"message": " ".join(sentences), "reissue": _reissue(names), "failure": " ".join(failures)}


def remember_presentation_dialog(items, service) -> dict:
    dialog = presentation_dialog(collect_presentation_issues(items, service))
    session["presentation_dialog"] = dialog
    session["presentation_failure"] = dialog.get("failure") or ""
    return dialog


def eloquent_presentation_error(message: str, failure: str) -> str:
    if failure and "invalid DCQL response" in message:
        return failure
    return message


def presentation_error_message(exc: BaseException) -> str:
    failure = session.get("presentation_failure") or ""
    if not isinstance(failure, str):
        failure = ""
    return eloquent_presentation_error(str(exc), failure)
