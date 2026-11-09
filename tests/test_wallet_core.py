import unittest
from unittest.mock import patch

import cbor2
import requests

from app.constants import (
    METADATA_TYPE_CREDENTIAL_ISSUER,
    METADATA_TYPE_FEDERATION_ENTITY,
    METADATA_TYPE_WALLET_PROVIDER,
)
from app.service.itwallet_helpers import (
    credential_configuration_doctype,
    credential_configuration_namespaces,
    validate_ec,
)
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

    def test_configuration_id_and_nested_vct(self):
        store = CredentialStore()
        store.add_credential(
            "https://issuer.example.org",
            "dc_sd_jwt_pid_ab",
            "credential",
            "urn:eudi:pid:it:1",
            configuration_id="dc_sd_jwt_pid",
        )
        store.add_credential(
            "https://issuer.example.org",
            "mso_mdoc_mDL_cd",
            "credential",
            "org.iso.18013.5.1.mDL",
            configuration_id="mso_mdoc_mDL",
        )

        found_config = store.find_by_configuration_id("dc_sd_jwt_pid")
        self.assertEqual(found_config[0], "dc_sd_jwt_pid_ab")
        self.assertIsNone(store.find_by_configuration_id("dc_sd_jwt"))

        found_vct = store.find_by_vct("urn:eudi:pid:it:1")
        self.assertEqual(found_vct[0], "dc_sd_jwt_pid_ab")
        found_doc = store.find_by_vct("org.iso.18013.5.1.mDL")
        self.assertEqual(found_doc[0], "mso_mdoc_mDL_cd")


class MdocDiagnosticTests(unittest.TestCase):
    def test_iso_notation_keeps_embedded_cbor_and_byte_strings(self):
        from app.service.credential_view import _iso_mdoc_diag

        item = {
            "digestID": 1,
            "random": bytes.fromhex("aa"),
            "elementIdentifier": "family_name",
            "elementValue": "Rossi",
        }
        issued = cbor2.dumps(item)
        full_date = cbor2.CBORTag(1004, "2024-02-22")
        dated = cbor2.dumps({"elementValue": full_date})
        issuer_signed = {
            "nameSpaces": {
                "org.iso.18013.5.1": [
                    cbor2.CBORTag(24, issued),
                    cbor2.CBORTag(24, dated),
                ]
            },
            "issuerAuth": [
                cbor2.dumps({1: -7}),
                {33: b"\x01\x02"},
                cbor2.dumps(
                    cbor2.CBORTag(24, cbor2.dumps({"docType": "org.iso.18013.5.1.mDL", "version": "1.0"}))
                ),
                b"\x03\x04",
            ],
        }
        text = _iso_mdoc_diag(cbor2.dumps(issuer_signed))
        self.assertIn('24(<<', text)
        self.assertIn('"family_name"', text)
        self.assertIn("1004(\"2024-02-22\")", text)
        self.assertIn("h'AA'", text)
        self.assertIn("<<\n", text)
        self.assertIn("1: -7", text)
        self.assertIn('"docType": "org.iso.18013.5.1.mDL"', text)
        self.assertIn("h'0304'", text)


class IssuerConfigurationTests(unittest.TestCase):
    def test_doctype_and_namespaces_come_from_the_credential_configuration(self):
        configuration = {
            "metadata": {
                METADATA_TYPE_CREDENTIAL_ISSUER: {
                    "credential_configurations_supported": {
                        "mso_mdoc_mDL": {
                            "doctype": "org.iso.18013.5.1.mDL",
                            "credential_metadata": {
                                "claims": [
                                    {"path": ["org.iso.18013.5.1", "family_name"]},
                                    {"path": ["org.iso.18013.5.1", "given_name"]},
                                ]
                            },
                        }
                    }
                }
            }
        }
        self.assertEqual(
            credential_configuration_doctype(configuration, "mso_mdoc_mDL"),
            "org.iso.18013.5.1.mDL",
        )
        self.assertEqual(
            credential_configuration_namespaces(configuration, "mso_mdoc_mDL"),
            ["org.iso.18013.5.1"],
        )

    def test_missing_doctype_stops_the_read(self):
        configuration = {
            "metadata": {
                METADATA_TYPE_CREDENTIAL_ISSUER: {
                    "credential_configurations_supported": {"mso_mdoc_mDL": {}}
                }
            }
        }
        with self.assertRaises(ValueError):
            credential_configuration_doctype(configuration, "mso_mdoc_mDL")


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
