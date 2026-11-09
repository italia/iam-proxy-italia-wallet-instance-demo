"""Local transaction log for Relying Party presentations."""

import json
import os
import threading
from datetime import datetime, timezone

from app.constants import CONFIG_DIR
from app.utils.utils import generate_nonce

_LOCK = threading.Lock()
_PATH = os.path.join(CONFIG_DIR, "transaction_log.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> list:
    if not os.path.isfile(_PATH):
        return []
    with open(_PATH, encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict) and isinstance(record.get("id"), str)]


def _save(records: list) -> None:
    directory = os.path.dirname(_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = _PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({"records": records}, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(temporary, _PATH)


def start_presentation(relying_party: dict, requested: list) -> str:
    record = {
        "id": generate_nonce(16),
        "category": "presentation",
        "created": _now(),
        "updated": _now(),
        "outcome": "in_corso",
        "rp": relying_party,
        "requested": requested,
        "presented": [],
    }
    with _LOCK:
        records = _load()
        records.append(record)
        _save(records)
    return record["id"]


def finish_presentation(transaction_id: str, outcome: str, presented: list) -> None:
    if outcome not in {"completata", "fallita"}:
        return
    with _LOCK:
        records = _load()
        for record in records:
            if record.get("id") != transaction_id:
                continue
            record["outcome"] = outcome
            record["presented"] = presented
            record["updated"] = _now()
            _save(records)
            return


def interrupt_if_open(transaction_id: str) -> None:
    with _LOCK:
        records = _load()
        for record in records:
            if record.get("id") != transaction_id or record.get("outcome") != "in_corso":
                continue
            record["outcome"] = "interrotta"
            record["updated"] = _now()
            _save(records)
            return


def abandon_open_presentation(session) -> None:
    transaction_id = session.get("rp_transaction_id") if session is not None else None
    if isinstance(transaction_id, str) and transaction_id:
        interrupt_if_open(transaction_id)


def list_records() -> list:
    with _LOCK:
        records = _load()
    return list(reversed(records))


def get_record(transaction_id: str) -> dict | None:
    for record in list_records():
        if record.get("id") == transaction_id:
            return record
    return None


def records_by_ids(identifiers: list[str]) -> list:
    wanted = set(identifiers)
    return [record for record in list_records() if record.get("id") in wanted]


def delete_all() -> None:
    with _LOCK:
        _save([])


def delete_records(identifiers: list[str]) -> None:
    wanted = set(identifiers)
    with _LOCK:
        records = [record for record in _load() if record.get("id") not in wanted]
        _save(records)
