"""Decode X.509 certificates carried in JWT x5c and COSE x5chain (header 33)."""

from __future__ import annotations

import base64
import json
import re
from datetime import timezone

import cbor2

_COSE_X5CHAIN = 33
_JWT_TOKEN = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def der_from_x5c_member(value) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        return data if len(data) >= 16 else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    for decoder in (base64.b64decode, _b64url):
        try:
            data = decoder(text)
        except Exception:
            continue
        if len(data) >= 16:
            return data
    return None


def certificate_subject(data: bytes) -> str | None:
    certificate = _load_certificate(data)
    if certificate is None:
        return None
    return certificate.subject.rfc4514_string()


def certificate_text(data: bytes) -> str | None:
    certificate = _load_certificate(data)
    if certificate is None:
        return None
    from cryptography.hazmat.primitives.serialization import Encoding

    not_before = certificate.not_valid_before_utc.astimezone(timezone.utc).isoformat()
    not_after = certificate.not_valid_after_utc.astimezone(timezone.utc).isoformat()
    pem = certificate.public_bytes(Encoding.PEM).decode("ascii").strip()
    return "\n".join(
        [
            f"Subject: {certificate.subject.rfc4514_string()}",
            f"Issuer: {certificate.issuer.rfc4514_string()}",
            f"Serial Number: {certificate.serial_number}",
            f"Not Before: {not_before}",
            f"Not After: {not_after}",
            "",
            pem,
        ]
    )


def _load_certificate(data: bytes):
    if len(data) < 16:
        return None
    from cryptography import x509

    try:
        return x509.load_der_x509_certificate(bytes(data))
    except Exception:
        pass
    try:
        return x509.load_pem_x509_certificate(bytes(data))
    except Exception:
        return None


def _chain_members(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _append_decoded_chain(found: list[dict], *, side: str, locator: str, members) -> None:
    texts = []
    for member in _chain_members(members):
        der = der_from_x5c_member(member)
        text = certificate_text(der) if der else None
        if text:
            texts.append(text)
    total = len(texts)
    for index, text in enumerate(texts, start=1):
        suffix = f"[{index}]" if total > 1 else ""
        found.append({"side": side, "locator": f"{locator}{suffix}", "text": text})


def _header_map(value) -> dict:
    decoded = value
    if isinstance(value, (bytes, bytearray)):
        try:
            decoded = cbor2.loads(bytes(value))
        except Exception:
            return {}
    if isinstance(decoded, cbor2.CBORTag):
        decoded = decoded.value
    return decoded if isinstance(decoded, dict) else {}


def _x5chain_from_cose_headers(protected, unprotected):
    members = []
    for header in (_header_map(protected), _header_map(unprotected)):
        if _COSE_X5CHAIN in header:
            members.extend(_chain_members(header.get(_COSE_X5CHAIN)))
    return members


def _looks_like_cose_sign1(value) -> bool:
    if isinstance(value, cbor2.CBORTag):
        if value.tag not in (18, 98):
            return False
        value = value.value
    return isinstance(value, (list, tuple)) and len(value) >= 3 and isinstance(value[1], dict)


def _collect_from_cbor(value, side: str, locator: str, found: list[dict], seen: set) -> None:
    key = (side, locator, id(value))
    if key in seen:
        return
    seen.add(key)

    if isinstance(value, cbor2.CBORTag):
        if value.tag in (18, 98) and _looks_like_cose_sign1(value):
            body = value.value
            chain = _x5chain_from_cose_headers(body[0], body[1])
            if chain:
                _append_decoded_chain(found, side=side, locator=f"{locator}.x5chain", members=chain)
            _collect_from_cbor(body[2], side, f"{locator}.payload", found, seen)
            return
        _collect_from_cbor(value.value, side, locator, found, seen)
        return

    if _looks_like_cose_sign1(value):
        chain = _x5chain_from_cose_headers(value[0], value[1])
        if chain:
            _append_decoded_chain(found, side=side, locator=f"{locator}.x5chain", members=chain)
        _collect_from_cbor(value[2], side, f"{locator}.payload", found, seen)
        return

    if isinstance(value, dict):
        if "issuerAuth" in value:
            _collect_from_cbor(value.get("issuerAuth"), side, f"{locator}.issuerAuth", found, seen)
        if _COSE_X5CHAIN in value:
            _append_decoded_chain(found, side=side, locator=f"{locator}.x5chain", members=value.get(_COSE_X5CHAIN))
        for key_name, item in value.items():
            if key_name in ("issuerAuth", _COSE_X5CHAIN):
                continue
            child = f"{locator}.{key_name}" if locator else str(key_name)
            _collect_from_cbor(item, side, child, found, seen)
        return

    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _collect_from_cbor(item, side, f"{locator}[{index}]", found, seen)


def _try_cbor_string(text: str, side: str, locator: str, found: list[dict], seen: set) -> None:
    if len(text) < 24 or "." in text[:80]:
        return
    for decoder in (_b64url, base64.b64decode):
        try:
            raw = decoder(text.strip())
            decoded = cbor2.loads(raw)
        except Exception:
            continue
        _collect_from_cbor(decoded, side, locator, found, seen)
        return


def _jwt_header(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
    except Exception:
        return None
    return header if isinstance(header, dict) else None


def _jwt_candidates(text: str) -> list[str]:
    tokens = [match.group(0) for match in _JWT_TOKEN.finditer(text)]
    compact = text.split("~", 1)[0].strip()
    parts = compact.split(".")
    if len(parts) >= 3 and parts[0] and parts[1] and compact not in tokens:
        tokens.insert(0, compact)
    return tokens


def _collect_from_value(value, side: str, locator: str, found: list[dict], seen: set) -> None:
    if isinstance(value, dict):
        if "x5c" in value:
            path = f"{locator}.x5c" if locator else "x5c"
            _append_decoded_chain(found, side=side, locator=path, members=value.get("x5c"))
        if _COSE_X5CHAIN in value or "x5chain" in value:
            path = f"{locator}.x5chain" if locator else "x5chain"
            members = value.get(_COSE_X5CHAIN, value.get("x5chain"))
            _append_decoded_chain(found, side=side, locator=path, members=members)
        for key, item in value.items():
            if key in ("x5c", "x5chain", _COSE_X5CHAIN):
                continue
            child = f"{locator}.{key}" if locator else str(key)
            _collect_from_value(item, side, child, found, seen)
        return

    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            child = f"{locator}[{index}]" if locator else f"[{index}]"
            _collect_from_value(item, side, child, found, seen)
        return

    if isinstance(value, (bytes, bytearray)):
        try:
            decoded = cbor2.loads(bytes(value))
        except Exception:
            text = certificate_text(bytes(value))
            if text and locator:
                found.append({"side": side, "locator": locator, "text": text})
            return
        _collect_from_cbor(decoded, side, locator or "cbor", found, seen)
        return

    if not isinstance(value, str):
        return

    text = value.strip()
    if not text:
        return

    jwt_found = False
    for token in _jwt_candidates(text):
        header = _jwt_header(token)
        if not header:
            continue
        if not (header.get("alg") or header.get("typ") or header.get("kid") or header.get("x5c")):
            continue
        jwt_found = True
        token_locator = locator or "JWT"
        if header.get("x5c"):
            _append_decoded_chain(found, side=side, locator=f"{token_locator}.x5c", members=header.get("x5c"))
    if jwt_found:
        return
    _try_cbor_string(text, side, locator or "cbor", found, seen)


def certificates_from_exchange(entry: dict) -> list[dict]:
    """Return decoded X.509 certificates found in one diagnostic HTTP exchange."""
    found: list[dict] = []
    seen: set = set()
    request = entry.get("request")
    response = entry.get("response")
    if request is not None:
        _collect_from_value(request, "request", "", found, seen)
    if response is not None:
        _collect_from_value(response, "response", "", found, seen)
    return found
