import base64
import json
import logging
import zlib
from datetime import date, datetime

import cbor2

from app.routes.itwallet_routes import (
    _format_label,
    display_index,
    lookup_attestation,
)
from app.store import app_state

logger = logging.getLogger(__name__)

_STATUS_LABELS = {
    "valid": "Valida",
    "revoked": "Revocata",
    "suspended": "Sospesa",
}
_SD_JWT_FORMATS = {"dc+sd-jwt", "vc+sd-jwt"}
_MDOC_FORMATS = {"mso_mdoc"}

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

def _jsonable_tag(value):
    embedded = value.tag == 24 and isinstance(value.value, (bytes, bytearray))
    if not embedded:
        return {"tag": value.tag, "value": _jsonable(value.value)}
    try:
        return _jsonable(cbor2.loads(value.value))
    except Exception:
        return base64.b64encode(value.value).decode("ascii")

def _jsonable_items(value):
    if isinstance(value, dict):
        return {_cose_key(key): _jsonable(item) for key, item in value.items()}
    return [_jsonable(item) for item in value]

def _jsonable(value):
    if isinstance(value, cbor2.CBORTag):
        return _jsonable_tag(value)
    if isinstance(value, (dict, list, tuple)):
        return _jsonable_items(value)
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

def _cbor_diag_items(value):
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_cbor_diag(key)}: {_cbor_diag(item)}" for key, item in value.items()) + "}"
    return "[" + ", ".join(_cbor_diag(item) for item in value) + "]"

def _cbor_diag(value) -> str:
    if isinstance(value, cbor2.CBORTag):
        return f"{value.tag}({_cbor_diag(value.value)})"
    if isinstance(value, (dict, list, tuple)):
        return _cbor_diag_items(value)
    if isinstance(value, (bytes, bytearray)):
        return "h'" + value.hex() + "'"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (datetime, date)):
        return json.dumps(value.isoformat(), ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    return json.dumps(value, ensure_ascii=False, default=str)

def _decoded_cbor(value):
    if not isinstance(value, (bytes, bytearray)) or not value:
        return value
    try:
        return cbor2.loads(value)
    except Exception:
        return value

def _preserve_cbor_tag(decoder, tag, shareable_index=None):
    return tag

def _load_preserved(data: bytes):
    return cbor2.loads(data, tag_hook=_preserve_cbor_tag)

def _iso_pad(indent: int) -> str:
    return "  " * indent

def _iso_bytes(value: bytes) -> str:
    return "h'" + value.hex().upper() + "'"

def _indent_block(text: str, indent: int) -> str:
    pad = _iso_pad(indent)
    return "\n".join(pad + line for line in text.split("\n"))

def _iso_embedded(data: bytes, indent: int) -> str:
    try:
        decoded = _load_preserved(data)
    except Exception:
        return _iso_bytes(data)
    body = _indent_block(_iso_diag(decoded), indent + 1)
    return f"<<\n{body}\n{_iso_pad(indent)}>>"

def _iso_tag(value: cbor2.CBORTag, indent: int) -> str:
    if value.tag == 24 and isinstance(value.value, (bytes, bytearray)):
        return f"24({_iso_embedded(bytes(value.value), indent)})"
    return f"{value.tag}({_iso_diag(value.value, indent)})"

def _iso_issuer_auth(value, indent: int) -> str:
    if isinstance(value, cbor2.CBORTag) and value.tag == 18:
        return f"18({_iso_issuer_auth(value.value, indent)})"
    if isinstance(value, (list, tuple)) and len(value) >= 4:
        return _iso_array(value, indent, embedded_indexes={0, 2})
    return _iso_diag(value, indent)

def _iso_map(value: dict, indent: int) -> str:
    if not value:
        return "{}"
    lines = ["{"]
    items = list(value.items())
    inner = _iso_pad(indent + 1)
    for index, (key, item) in enumerate(items):
        comma = "," if index < len(items) - 1 else ""
        rendered = _iso_issuer_auth(item, indent + 1) if key == "issuerAuth" else _iso_diag(item, indent + 1)
        lines.append(f"{inner}{_iso_diag(key, indent + 1)}: {rendered}{comma}")
    lines.append(_iso_pad(indent) + "}")
    return "\n".join(lines)

def _iso_array(value, indent: int, embedded_indexes=()) -> str:
    if not value:
        return "[]"
    lines = ["["]
    inner = _iso_pad(indent + 1)
    last = len(value) - 1
    for index, item in enumerate(value):
        comma = "," if index < last else ""
        if index in embedded_indexes and isinstance(item, (bytes, bytearray)):
            rendered = _iso_embedded(bytes(item), indent + 1)
        else:
            rendered = _iso_diag(item, indent + 1)
        lines.append(f"{inner}{rendered}{comma}")
    lines.append(_iso_pad(indent) + "]")
    return "\n".join(lines)

def _iso_diag(value, indent: int = 0) -> str:
    if isinstance(value, cbor2.CBORTag):
        return _iso_tag(value, indent)
    if isinstance(value, dict):
        return _iso_map(value, indent)
    if isinstance(value, (list, tuple)):
        return _iso_array(value, indent)
    if isinstance(value, (bytes, bytearray)):
        return _iso_bytes(bytes(value))
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, datetime):
        text = value.isoformat()
        if text.endswith("+00:00"):
            text = text[:-6] + "Z"
        return f'0("{text}")'
    if isinstance(value, date):
        return f'1004("{value.isoformat()}")'
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return json.dumps(value)
    return json.dumps(value, ensure_ascii=False, default=str)

def _iso_mdoc_diag(raw: bytes) -> str:
    return _iso_diag(_load_preserved(raw))

def _cose_headers_text(protected, unprotected) -> str:
    unprotected_map = {} if unprotected is None else unprotected
    return _cbor_diag(_decoded_cbor(protected)) + "\n" + _cbor_diag(unprotected_map)

def _cose_sign1(value):
    if isinstance(value, cbor2.CBORTag):
        value = value.value
    if not isinstance(value, (list, tuple)) or len(value) < 3:
        return None
    protected, unprotected, payload = value[0], value[1], value[2]
    body = cbor2.loads(payload) if isinstance(payload, (bytes, bytearray)) else payload
    return {"header": _cose_headers_text(protected, unprotected), "payload": _json_text(_jsonable(body))}

def _mdoc_cleartext(token: str) -> dict | None:
    if not isinstance(token, str) or not token.strip():
        return None
    try:
        raw = _b64url(token.strip())
        issuer_signed = cbor2.loads(raw)
    except Exception:
        return None
    if not isinstance(issuer_signed, dict):
        return None
    signed = _cose_sign1(issuer_signed.get("issuerAuth"))
    if not signed:
        return None
    namespaces = issuer_signed.get("nameSpaces") or {}
    signed["disclosures"] = _json_text(_jsonable(namespaces))
    try:
        signed["diagnostic"] = _iso_mdoc_diag(raw)
    except Exception:
        logger.debug("Notazione diagnostica mdoc non disponibile", exc_info=True)
    return signed

def _credential_cleartext(token, credential_format: str) -> dict | None:
    fmt = (credential_format or "").lower()
    if fmt in _SD_JWT_FORMATS:
        return _sd_jwt_cleartext(token) if isinstance(token, str) else None
    if fmt in _MDOC_FORMATS:
        return _mdoc_cleartext(token) if isinstance(token, str) else None
    return _jwt_cleartext(token)

def _or_text(value, fallback=""):
    return value or fallback

def _held_entries(issuer, group):
    if "data_row" in group:
        return {issuer: group}
    return group

def _is_held_entry(entry) -> bool:
    return isinstance(entry, dict) and "data_row" in entry

def _held_view(issuer, group, credential_id, entry, index) -> dict:
    meta = lookup_attestation(str(entry.get("configuration_id") or ""), index)
    status = str(_or_text(entry.get("status"))).strip()
    credential_format = _or_text(meta.get("format"))
    return {
        "issuer": "" if "data_row" in group else issuer,
        "id": credential_id,
        "name": _or_text(meta.get("name"), credential_id),
        "description": _or_text(meta.get("description")),
        "format": credential_format,
        "format_label": _or_text(meta.get("format_label"), _format_label(credential_format)),
        "claims": meta.get("claims") or [],
        "config_id": _or_text(meta.get("id"), credential_id),
        "credential": _credential_cleartext(entry.get("data_row"), credential_format),
        "status_label": _STATUS_LABELS.get(status.lower(), _or_text(status, "Non verificata")),
        "assertion": _jwt_cleartext(entry.get("status_assertion")),
    }

def _held_credential_views() -> list[dict]:
    views = []
    store = app_state.credential_store.get_store() or {}
    index = display_index()
    for issuer, group in store.items():
        if not isinstance(group, dict):
            continue
        entries = _held_entries(issuer, group)
        for credential_id, entry in entries.items():
            if _is_held_entry(entry):
                views.append(_held_view(issuer, group, credential_id, entry, index))
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

