import base64
import datetime
import json
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
                cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps({"docType": "org.iso.18013.5.1.mDL", "version": "1.0"}))),
                b"\x03\x04",
            ],
        }
        text = _iso_mdoc_diag(cbor2.dumps(issuer_signed))
        self.assertIn("24(<<", text)
        self.assertIn('"family_name"', text)
        self.assertIn('1004("2024-02-22")', text)
        self.assertIn("h'AA'", text)
        self.assertIn("<<\n", text)
        self.assertIn("1: -7", text)
        self.assertIn('"docType": "org.iso.18013.5.1.mDL"', text)
        self.assertIn("h'0304'", text)

    def test_value_digest_indexes_stay_numeric(self):
        from app.service.credential_view import _json_text, _jsonable

        rendered = _json_text(_jsonable({"valueDigests": {"org.iso.18013.5.1": {0: b"a", 1: b"b", 4: b"c"}}}))
        digests = json.loads(rendered)["valueDigests"]["org.iso.18013.5.1"]
        self.assertEqual(set(digests), {"0", "1", "4"})


class HttpHistoryTests(unittest.TestCase):
    def test_http_message_keeps_the_body_in_the_format_that_was_sent(self):
        from app.utils.diagnostic_log import (
            http_request_message,
            http_response_message,
            list_entries,
            record_exchange,
            remove_entries,
        )

        request_http = http_request_message(
            "POST",
            "https://issuer.example.org/token?x=1",
            {"Content-Type": "application/json", "X-Private-Key": "secret"},
            '{"grant":"code"}',
        )
        response_http = http_response_message(200, "OK", {"Content-Type": "application/json"}, '{"access_token":"tok"}')
        self.assertTrue(request_http.startswith("POST /token?x=1 HTTP/1.1\n"))
        self.assertIn("Host: issuer.example.org", request_http)
        self.assertIn("X-Private-Key: [omesso]", request_http)
        self.assertNotIn("secret", request_http)
        self.assertIn('{"grant":"code"}', request_http)
        self.assertTrue(response_http.startswith("HTTP/1.1 200 OK\n"))
        self.assertIn('{"access_token":"tok"}', response_http)
        form_http = http_request_message(
            "POST",
            "https://issuer.example.org/par",
            {"Content-Type": "application/x-www-form-urlencoded"},
            "scope=pid&client_id=wallet",
        )
        self.assertTrue(form_http.startswith("POST /par HTTP/1.1\n"))
        self.assertIn("Content-Type: application/x-www-form-urlencoded", form_http)
        self.assertIn("scope=pid&client_id=wallet", form_http)

        record_exchange(
            method="POST",
            url="https://issuer.example.org/token?x=1",
            request_headers={"Content-Type": "application/json"},
            request_body={"grant": "code"},
            status=200,
            response_body={"access_token": "tok"},
            request_http=request_http,
            response_http=response_http,
        )
        stored = [entry for entry in list_entries() if entry.get("url") == "https://issuer.example.org/token?x=1"]
        self.assertTrue(stored)
        entry = stored[-1]
        self.assertEqual(entry["request_http"], request_http)
        self.assertEqual(entry["response_http"], response_http)
        self.assertEqual(entry["request"]["body"]["grant"], "code")
        self.assertEqual(entry["response"]["access_token"], "tok")
        remove_entries([entry["id"]])


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
            "metadata": {METADATA_TYPE_CREDENTIAL_ISSUER: {"credential_configurations_supported": {"mso_mdoc_mDL": {}}}}
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


class CredentialValidityDatesTests(unittest.TestCase):
    def test_issued_and_expires_come_from_sd_jwt_claims(self):
        from app.service.credential_view import _expires_at, _issued_at

        body = base64.urlsafe_b64encode(json.dumps({"iat": 1_700_000_000, "exp": 1_700_003_600}).encode()).decode().rstrip("=")
        entry = {"data_row": f"e30.{body}.sig"}
        self.assertEqual(_issued_at(entry), "2023-11-14T22:13:20Z")
        self.assertEqual(_expires_at(entry), "2023-11-14T23:13:20Z")

    def test_mdoc_validity_info_supplies_dates(self):
        from app.service.credential_view import _expires_at, _issued_at

        entry = {
            "claims": {
                "mso": {
                    "validityInfo": {
                        "signed": "2026-11-10T10:00:00Z",
                        "validUntil": "2026-11-10T11:00:00+00:00",
                    }
                }
            }
        }
        self.assertEqual(_issued_at(entry), "2026-11-10T10:00:00Z")
        self.assertEqual(_expires_at(entry), "2026-11-10T11:00:00Z")


class HeldAttributeTests(unittest.TestCase):
    def test_sd_jwt_attributes_include_disclosures_and_skip_protocol_fields(self):
        from app.service.credential_view import _attribute_lines

        disclosure = base64.urlsafe_b64encode(json.dumps(["salt", "given_name", "Mario"]).encode()).decode().rstrip("=")
        entry = {
            "data_row": f"e30.e30.sig~{disclosure}",
            "claims": {"iss": "https://issuer.example.org", "vct": "urn:pid", "family_name": "Rossi"},
        }
        lines = _attribute_lines(
            entry,
            "dc+sd-jwt",
            [
                {"label": "Nome", "path": ["given_name"]},
                {"label": "Cognome", "path": ["family_name"]},
            ],
        )
        self.assertEqual(lines, ["Nome: Mario", "Cognome: Rossi"])

    def test_mdoc_attributes_come_from_namespaces_and_from_the_credential(self):
        from app.service.credential_view import _attribute_lines

        stored = _attribute_lines(
            {"claims": {"nameSpaces": {"org.iso.18013.5.1": {"family_name": "Rossi", "given_name": "Mario"}}}},
            "mso_mdoc",
            [{"label": "Cognome", "path": ["org.iso.18013.5.1", "family_name"]}],
        )
        self.assertEqual(stored, ["Cognome: Rossi", "given_name: Mario"])

        item = cbor2.dumps(
            {
                "digestID": 1,
                "random": bytes.fromhex("aa"),
                "elementIdentifier": "family_name",
                "elementValue": "Bianchi",
            }
        )
        issuer_signed = {
            "nameSpaces": {"org.iso.18013.5.1": [cbor2.CBORTag(24, item)]},
            "issuerAuth": [cbor2.dumps({1: -7}), {}, cbor2.dumps({"docType": "org.iso.18013.5.1.mDL"}), b""],
        }
        token = base64.urlsafe_b64encode(cbor2.dumps(issuer_signed)).decode().rstrip("=")
        from_token = _attribute_lines({"data_row": token}, "mso_mdoc", [])
        self.assertEqual(from_token, ["family_name: Bianchi"])

    def test_mdoc_header_uses_names_and_keeps_raw_bytes_in_the_diagnostic_notation(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        from app.service.credential_view import _cose_headers_text, _iso_mdoc_diag

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer.example.org")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        der = certificate.public_bytes(serialization.Encoding.DER)
        header = _cose_headers_text(cbor2.dumps({1: -7, 4: b"issuer-key"}), {33: der})
        self.assertIn("alg: ES256", header)
        self.assertIn("kid: issuer-key", header)
        self.assertIn("x5chain: CN=issuer.example.org", header)
        self.assertNotIn("h'", header)

        diagnostic = _iso_mdoc_diag(cbor2.dumps({1: -7, 33: der}))
        self.assertIn("1: -7", diagnostic)
        self.assertIn("h'", diagnostic)


def _sd_jwt(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"e30.{body}.sig"


class PresentationValidityTests(unittest.TestCase):
    def test_status_list_code_reads_the_index(self):
        import zlib

        from app.service.credential_status import status_list_code

        raw = bytes([0b00000001])
        listed = base64.urlsafe_b64encode(zlib.compress(raw)).decode().rstrip("=")
        self.assertEqual(status_list_code(listed, 1, 0), 1)
        self.assertEqual(status_list_code(listed, 1, 1), 0)

    def test_expired_credential_is_reported_before_presentation(self):
        from types import SimpleNamespace

        from app.service.credential_status import collect_presentation_issues
        from app.store import app_state

        issuer = "https://issuer.example.org"
        key = "eid-expired"
        token = _sd_jwt({"exp": 1})
        app_state.credential_store.add_credential(issuer, key, token, "urn:it-wallet:eid:1")
        item = {"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:it-wallet:eid:1"]}}
        try:
            issues = collect_presentation_issues([item], SimpleNamespace())
        finally:
            app_state.credential_store.remove_held(issuer, key)
        self.assertEqual(len(issues), 1)
        self.assertTrue(issues[0]["expired"])
        self.assertFalse(issues[0]["revoked"])
        self.assertFalse(issues[0]["status_unknown"])

    def test_revoked_credential_is_reported_before_presentation(self):
        from types import SimpleNamespace

        from app.service.credential_status import collect_presentation_issues
        from app.store import app_state

        issuer = "https://issuer.example.org"
        key = "eid-revoked"
        token = _sd_jwt(
            {
                "exp": 4_000_000_000,
                "status": {"status_list": {"uri": "https://issuer.example.org/status", "idx": 0}},
            }
        )
        app_state.credential_store.add_credential(issuer, key, token, "urn:it-wallet:eid:1")
        item = {"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:it-wallet:eid:1"]}}
        service = SimpleNamespace(proxies=None, no_proxy_domains=None)
        try:
            with (
                patch("app.service.credential_status.issuer_status_jwks", return_value={"keys": []}),
                patch("app.service.credential_status.store_status_list", return_value=(1, {})),
            ):
                issues = collect_presentation_issues([item], service)
        finally:
            app_state.credential_store.remove_held(issuer, key)
        self.assertEqual(len(issues), 1)
        self.assertFalse(issues[0]["expired"])
        self.assertTrue(issues[0]["revoked"])

    def test_valid_credential_does_not_warn(self):
        from types import SimpleNamespace

        from app.service.credential_status import collect_presentation_issues
        from app.store import app_state

        issuer = "https://issuer.example.org"
        key = "eid-valid"
        token = _sd_jwt({"exp": 4_000_000_000})
        app_state.credential_store.add_credential(issuer, key, token, "urn:it-wallet:eid:1")
        item = {"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:it-wallet:eid:1"]}}
        try:
            issues = collect_presentation_issues([item], SimpleNamespace())
        finally:
            app_state.credential_store.remove_held(issuer, key)
        self.assertEqual(issues, [])

    def test_dialog_offers_continue_or_new_issuance(self):
        from flask import Flask
        from flask_babel import Babel

        from app.service.credential_status import eloquent_presentation_error, presentation_dialog

        app = Flask(__name__)
        Babel(app)
        issue = {"name": "eID", "expired": True, "revoked": False, "suspended": False, "status_unknown": False}
        with app.app_context():
            dialog = presentation_dialog([issue])
        self.assertIn("eID è scaduta", dialog["message"])
        self.assertIn("presentarla comunque", dialog["message"])
        self.assertIn("nuova emissione", dialog["reissue"])
        verifier = (
            "Errore ritornato dall'endpoint https://iam-proxy-italia.example.org/OpenID4VP/response-uri: "
            "invalid_request - invalid DCQL response: validation error (HTTP Status code: 400)"
        )
        self.assertIn("scaduta", eloquent_presentation_error(verifier, dialog["failure"]))
        self.assertEqual(eloquent_presentation_error("altro errore", dialog["failure"]), "altro errore")


if __name__ == "__main__":
    unittest.main()
