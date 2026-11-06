import unittest
from unittest.mock import patch

import requests

from app.constants import METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_WALLET_PROVIDER
from app.service.itwallet_helpers import validate_ec
from app.store.credential_store import CredentialStore
from app.utils.itwalletUtils import request_status_list

_ISSUER = "https://issuer.example.org"
_FEDERATION = METADATA_TYPE_FEDERATION_ENTITY
_PROVIDER = METADATA_TYPE_WALLET_PROVIDER


def _entity_configuration(metadata_types):
    metadata = {metadata_type: {"jwks": {"keys": []}} for metadata_type in metadata_types}
    return {
        "iss": _ISSUER,
        "sub": _ISSUER,
        "authority_hints": ["https://trust.example.org"],
        "metadata": metadata,
    }


class CredentialStoreTests(unittest.TestCase):
    def test_insert_delete_and_status_list_index(self):
        store = CredentialStore()
        store.add_credential("issuer", "pid", "credential", "urn:pid")

        self.assertEqual(store._get_credential_into_store("issuer", "pid")["vct"], "urn:pid")

        updated = store.update_status("pid", "status-list-token", "1")
        self.assertTrue(updated)
        entry = store._get_credential_into_store("issuer", "pid")
        self.assertEqual(entry["status"], "1")
        self.assertEqual(entry["status_assertion"], "status-list-token")

        self.assertTrue(store.remove_held("issuer", "pid"))
        self.assertIsNone(store._get_credential_into_store("issuer", "pid"))
        self.assertFalse(store.update_status("pid", "status-list-token", "0"))


class ValidateEcTests(unittest.TestCase):
    def test_accepts_iss_sub_hint_metadata_and_jwks(self):
        payload = _entity_configuration([_FEDERATION, _PROVIDER])
        validate_ec(payload, _ISSUER, [_FEDERATION, _PROVIDER], "https://trust.example.org")

    def test_rejects_iss_sub_mismatch(self):
        payload = _entity_configuration([_FEDERATION])
        with self.assertRaises(ValueError):
            validate_ec(payload, "https://other.example.org", [_FEDERATION])

    def test_rejects_missing_hint(self):
        payload = _entity_configuration([_FEDERATION])
        with self.assertRaises(ValueError):
            validate_ec(payload, _ISSUER, [_FEDERATION], "https://missing.example.org")

    def test_rejects_missing_metadata(self):
        payload = _entity_configuration([_FEDERATION])
        with self.assertRaises(ValueError):
            validate_ec(payload, _ISSUER, [_FEDERATION, _PROVIDER])

    def test_rejects_missing_jwks(self):
        payload = _entity_configuration([_PROVIDER])
        del payload["metadata"][_PROVIDER]["jwks"]
        with self.assertRaises(ValueError):
            validate_ec(payload, _ISSUER, [_PROVIDER])


class StatusListTests(unittest.TestCase):
    def test_request_status_list_reads_fake_token(self):
        response = requests.Response()
        response.status_code = 200
        response._content = b"header.payload.signature"
        response.headers["Content-Type"] = "application/statuslist+jwt"
        response.url = "https://issuer.example.org/status"

        with patch("app.utils.http_utils.requests.get", return_value=response):
            token = request_status_list("https://issuer.example.org/status")

        self.assertEqual(token, "header.payload.signature")


if __name__ == "__main__":
    unittest.main()
