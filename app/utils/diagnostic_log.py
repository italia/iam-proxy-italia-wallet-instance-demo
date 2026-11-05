"""In-memory log of outbound HTTP exchanges used by the wallet demo."""

import contextvars
import json
import logging
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from functools import wraps

logger = logging.getLogger(__name__)

peer_role: contextvars.ContextVar[str | None] = contextvars.ContextVar("diagnostic_peer", default=None)
_entries: deque[dict] = deque(maxlen=100)
_lock = threading.Lock()
_MAX_TEXT = 100_000


def diagnostic_peer(role: str):
    """Tag outbound calls made while the wrapped method runs."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = peer_role.set(role)
            try:
                return fn(*args, **kwargs)
            finally:
                peer_role.reset(token)

        return wrapper

    return decorator


def peer_for(url: str) -> str:
    explicit = peer_role.get()
    if explicit:
        return explicit
    lowered = (url or "").lower()
    if "openid4vp" in lowered:
        return "relying_party"
    if "openid4vci" in lowered:
        return "credential_issuer"
    return "federation"


def _redact(value):
    if isinstance(value, str):
        if "PRIVATE KEY" in value.upper():
            return "[omesso]"
        if len(value) > _MAX_TEXT:
            return value[:_MAX_TEXT] + "…[troncato]"
        return value
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            name = str(key)
            redacted[name] = "[omesso]" if "private" in name.lower() else _redact(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def _as_object(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return _redact(value)
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return _redact(json.loads(text))
            except ValueError:
                pass
        return _redact(value)
    return _redact(str(value))


def record_exchange(*, method, url, request_headers, request_body, status, response_body):
    entry = {
        "id": uuid.uuid4().hex,
        "time": datetime.now(timezone.utc).isoformat(),
        "peer": peer_for(url),
        "method": (method or "").upper(),
        "url": url,
        "request": {
            "headers": _as_object(dict(request_headers or {})),
            "body": _as_object(request_body),
        },
        "status": status,
        "response": _as_object(response_body),
    }
    with _lock:
        _entries.append(entry)
    logger.info("diagnosi %s", json.dumps(entry, ensure_ascii=False, default=str))


def list_entries() -> list[dict]:
    with _lock:
        return list(_entries)


def remove_entries(ids: list[str]) -> int:
    wanted = {str(item) for item in ids if item}
    if not wanted:
        return 0
    with _lock:
        kept = [entry for entry in _entries if str(entry.get("id")) not in wanted]
        removed = len(_entries) - len(kept)
        _entries.clear()
        _entries.extend(kept)
    return removed
