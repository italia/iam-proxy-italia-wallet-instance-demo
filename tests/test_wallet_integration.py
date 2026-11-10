"""Integration coverage for the wallet demo pages and the protocol helpers they call."""

import base64
import datetime
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flask import session

from app.constants import METADATA_TYPE_CREDENTIAL_ISSUER
from app.store import app_state

_CONFIG = """
provider_config:
  spec_version: "1.4.7"
  public_url: https://demo-wi.example.org:8080
credentials_config:
  supported_credentials:
    pid:
      proto_version: "1"
      valid_for_wallet_activation: true
      internal_mapping_ref: pid
      document_identifier:
        type: vct
        value: urn:eudi:pid:it:1
      document_format:
        id: sd-jwt-vc
        specs: {}
  internal_attributes_mappings:
    pid:
      given_name:
        sd-jwt-vc:
          element_identifier: given_name
      family_name:
        mdoc-cbor:
          namespace: org.iso.18013.5.1
          element_identifier: family_name
app:
  host: 127.0.0.1
  port: 8080
  debug_mode: false
  favicon_subpath: img/IT-Wallet-Symbol-Primary-BlueItalia.svg
  static_folder: static
  secret_key: test-secret
  password: wallet
  http_params:
    proxy:
      use_proxy: false
  logging:
    level: WARNING
    libs_enabled: false
wallet_instance: {}
ms_trust_configuration:
  IT:
    trust_root: https://trust-anchor.example.org
    trust_framework: oid-fed
metadata:
  initialize_flow:
    credential_configuration_id: dc_sd_jwt_eid
    response_mode: query
    response_type: code
    redirect_uri: https://demo-wi.example.org:8080/wallet/cb
    idphints:
      CIE3: ""
      SPID2: https://demo.spid.example.org
  credential_flow:
    response_mode: direct_post.jwt
    response_type: code
    redirect_uri: https://demo-wi.example.org:8080/wallet/cb
  presentation_flow:
    response_mode: direct_post.jwt
    response_type: vp_token
    status_assertion_supported: false
credential_issuers: ""
eudiw_lotl: ""
"""

_ISSUER = "https://issuer.example.org"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _certificate() -> bytes:
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
    return certificate.public_bytes(serialization.Encoding.DER)


def _mdoc_token() -> str:
    item = cbor2.dumps(
        {
            "digestID": 1,
            "random": bytes.fromhex("aa"),
            "elementIdentifier": "family_name",
            "elementValue": "Rossi",
        }
    )
    issuer_signed = {
        "nameSpaces": {"org.iso.18013.5.1": [cbor2.CBORTag(24, item)]},
        "issuerAuth": [
            cbor2.dumps({1: -7, 4: b"issuer-key"}),
            {33: _certificate()},
            cbor2.dumps({"docType": "org.iso.18013.5.1.mDL", "version": "1.0"}),
            b"\x03",
        ],
    }
    return _b64(cbor2.dumps(issuer_signed))


def _sd_jwt() -> str:
    disclosure = _b64(json.dumps(["salt", "given_name", "Mario"]).encode())
    return f"e30.e30.sig~{disclosure}"


def _issuer_configuration() -> dict:
    return {
        "iss": _ISSUER,
        "sub": _ISSUER,
        "metadata": {
            METADATA_TYPE_CREDENTIAL_ISSUER: {
                "credential_issuer": _ISSUER,
                "display": [{"locale": "it-IT", "name": "Issuer demo"}],
                "credential_configurations_supported": {
                    "dc_sd_jwt_pid": {
                        "format": "dc+sd-jwt",
                        "display": [{"locale": "it", "name": "PID"}],
                        "credential_metadata": {
                            "claims": [
                                {"path": ["given_name"], "display": [{"locale": "it", "name": "Nome"}]},
                                {"path": ["family_name"], "display": [{"locale": "it", "name": "Cognome"}]},
                            ]
                        },
                    },
                    "mso_mdoc_mDL": {
                        "format": "mso_mdoc",
                        "display": [{"locale": "it", "name": "Patente"}],
                        "credential_metadata": {
                            "claims": [
                                {
                                    "path": ["org.iso.18013.5.1", "family_name"],
                                    "display": [{"locale": "it", "name": "Cognome"}],
                                }
                            ]
                        },
                    },
                },
            }
        },
    }


def demo_app():
    if getattr(demo_app, "app", None) is not None:
        return demo_app.app
    config_dir = tempfile.mkdtemp(prefix="wallet-demo-")
    with open(os.path.join(config_dir, "app_config.yaml"), "w", encoding="utf-8") as handle:
        handle.write(_CONFIG)
    import app as app_module

    demo_app.previous_config = app_module.CONFIG_DIR
    demo_app.config_dir = config_dir
    app_module.CONFIG_DIR = config_dir
    from app import create_app

    demo_app.app = create_app()
    return demo_app.app


class WalletDemoIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = demo_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        import app as app_module

        app_module.CONFIG_DIR = demo_app.previous_config
        shutil.rmtree(demo_app.config_dir, ignore_errors=True)

    def setUp(self):
        app_state.credential_store.clear()
        app_state.ec_store.clear()
        app_state.wallet_initialized = False
        app_state.selected_country = ""
        self.client.post("/wallet/access", data={"password": "wallet"})

    def _hold_credentials(self):
        app_state.ec_store.add(_ISSUER, _issuer_configuration())
        app_state.credential_store.add_credential(
            _ISSUER,
            "pid",
            _sd_jwt(),
            "urn:eudi:pid:it:1",
            claims={"iss": _ISSUER, "vct": "urn:eudi:pid:it:1", "family_name": "Rossi"},
            configuration_id="dc_sd_jwt_pid",
        )
        app_state.credential_store.add_credential(
            _ISSUER,
            "mdl",
            _mdoc_token(),
            "org.iso.18013.5.1.mDL",
            claims={"nameSpaces": {"org.iso.18013.5.1": {"family_name": "Rossi", "given_name": "Mario"}}},
            configuration_id="mso_mdoc_mDL",
        )

    def test_language_access_and_obtained_credentials_show_user_attributes(self):
        self._hold_credentials()
        italian = self.client.get("/wallet/lang/it?next=/wallet/credentials")
        self.assertEqual(italian.status_code, 302)
        page = self.client.get("/wallet/credentials")
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("metadata, attributi, attestazione e stato di revoca.", body)
        self.assertIn("Nome: Mario", body)
        self.assertIn("Cognome: Rossi", body)
        self.assertIn("alg: ES256", body)
        self.assertIn("x5chain: CN=issuer.example.org", body)
        self.assertIn("Notazione diagnostica", body)
        self.assertNotIn("<dt>Dati contenuti</dt>", body)

        english = self.client.get("/wallet/lang/en?next=/wallet/access", follow_redirects=True)
        self.assertIn("Sign in", english.get_data(as_text=True))
        present = self.client.get("/wallet/present")
        present_body = present.get_data(as_text=True)
        self.assertIn("modal-lg", present_body)
        self.assertIn("presentation-credentials", present_body)
        self.assertIn('id="qr-scanner-modal"', present_body)

    def test_presentation_response_is_what_the_confirmation_dialog_renders(self):
        requested = [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}],
            }
        ]
        relying_party = {
            "name": "Demo verifier",
            "client_name": "Sportello",
            "client_id": "https://verifier.example.org",
            "homepage_uri": "https://verifier.example.org",
            "policy_uri": "https://verifier.example.org/privacy",
            "tos_uri": "https://verifier.example.org/terms",
            "contacts": ["desk@verifier.example.org"],
        }

        def present(service, client_id, request_uri, method, state):
            session["rp_display"] = relying_party
            session["rp_transaction_id"] = "tx-1"
            return requested

        with patch("app.routes.wallet_routes.ItWalletService.present_to_verifier", present):
            response = self.client.post(
                "/wallet/presentation",
                json={"qrcode_data": "https://verifier.example.org/authorize?client_id=https://verifier.example.org&request_uri=https://verifier.example.org/request"},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["data"], requested)
        self.assertEqual(payload["relying_party"]["client_id"], "https://verifier.example.org")
        self.assertEqual(payload["transaction_id"], "tx-1")
        interrupted = self.client.post("/wallet/presentation/transaction", json={"id": "tx-1", "outcome": "interrotta"})
        self.assertTrue(interrupted.get_json()["success"])

    def test_pages_status_delete_and_diagnostics(self):
        self._hold_credentials()
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/wallet/home").status_code, 200)
        self.assertEqual(self.client.get("/wallet/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/wallet/diagnostics").status_code, 200)
        self.assertEqual(self.client.get("/favicon.ico").status_code, 200)
        missing = self.client.get("/wallet/missing")
        self.assertEqual(missing.status_code, 404)
        status = self.client.post("/wallet/credentials/status", data={"issuer": _ISSUER, "credential_id": "pid"})
        self.assertIn(status.status_code, (200, 302))
        if status.status_code == 302:
            status = self.client.get(status.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertIn("status list", status.get_data(as_text=True))
        removed = self.client.post(
            "/wallet/credentials/delete", data={"issuer": _ISSUER, "credential_id": "pid"}, follow_redirects=True
        )
        self.assertIn("rimossa", removed.get_data(as_text=True))
        self.assertEqual(self.client.get("/wallet/logout", follow_redirects=True).status_code, 200)
        self.assertEqual(self.client.get("/wallet/home").status_code, 302)

    def test_api_catalog_diagnostics_and_reset(self):
        self._hold_credentials()
        catalog = self.client.get("/itwallet/issuerCatalog")
        self.assertTrue(catalog.get_json()["success"])
        self.assertEqual(self.client.post("/itwallet/issuerCatalog", json={}).status_code, 400)
        supported = self.client.get("/itwallet/credentialSupported")
        self.assertTrue(supported.get_json()["success"])
        types = self.client.get("/itwallet/objectTypesInMemory")
        self.assertIn("CredentialStore", types.get_json()["data"])
        viewed = self.client.post("/itwallet/viewObjectTypeInMemory", json={"objectType": "CredentialStore"})
        self.assertTrue(viewed.get_json()["success"])
        diagnostics = self.client.get("/itwallet/diagnostics")
        self.assertTrue(diagnostics.get_json()["success"])
        removed = self.client.delete("/itwallet/diagnostics", json={"ids": []})
        self.assertTrue(removed.get_json()["success"])
        rejected = self.client.delete("/itwallet/diagnostics", json={"ids": "no"})
        self.assertEqual(rejected.status_code, 400)
        offer = self.client.get("/itwallet/credential-offer.svg?offer=not-an-offer")
        self.assertEqual(offer.status_code, 400)
        reset = self.client.get("/itwallet/reset")
        self.assertTrue(reset.get_json()["success"])
        self.assertEqual(app_state.credential_store.get_store(), {})


class ProtocolHelperIntegrationTests(unittest.TestCase):
    def test_http_helpers_parse_success_and_errors(self):
        import requests

        from app.utils.http_utils import (
            _extract_error_from_response,
            _parse_json_response,
            _should_use_proxy,
            http_request_with_retry,
        )
        from app.utils.itwalletUtils import (
            get_status_description,
            request_as_par,
            request_authorize,
            request_nonce,
            request_status_list,
        )

        self.assertFalse(_should_use_proxy("https://issuer.example.org", None, None))
        self.assertTrue(_should_use_proxy("https://issuer.example.org", {"https": "http://proxy"}, ["localhost"]))
        self.assertFalse(_should_use_proxy("https://api.localhost", {"https": "http://proxy"}, ["localhost"]))

        ok = requests.Response()
        ok.status_code = 200
        ok.headers["Content-Type"] = "application/json"
        ok._content = b'{"request_uri":"urn:request","expires_in":60}'
        ok.url = "https://issuer.example.org/par"
        ok.reason = "OK"
        ok.request = requests.Request("POST", ok.url).prepare()
        self.assertEqual(_parse_json_response(ok, ok.url)["request_uri"], "urn:request")

        broken = requests.Response()
        broken.status_code = 400
        broken.headers["Content-Type"] = "application/json"
        broken._content = b'{"error":"invalid_request","error_description":"no"}'
        broken.url = "https://issuer.example.org/par"
        self.assertIn("invalid_request", _extract_error_from_response(broken))

        with patch("app.utils.http_utils.requests.post", return_value=ok), patch("app.utils.http_utils.time.sleep"):
            parsed = request_as_par("https://issuer.example.org/par", "att", "pop", "request", "wallet")
        self.assertEqual(parsed["request_uri"], "urn:request")

        text = requests.Response()
        text.status_code = 200
        text.headers["Content-Type"] = "application/jwt"
        text._content = b"header.payload.signature"
        text.url = "https://issuer.example.org/authorize"
        text.reason = "OK"
        text.request = requests.Request("GET", text.url).prepare()
        with patch("app.utils.http_utils.requests.get", return_value=text):
            self.assertEqual(request_authorize("https://issuer.example.org/authorize", "?request=1"), "header.payload.signature")

        nonce = requests.Response()
        nonce.status_code = 200
        nonce.headers["Content-Type"] = "application/json"
        nonce._content = b'{"c_nonce":"abc"}'
        nonce.url = "https://issuer.example.org/nonce"
        nonce.reason = "OK"
        nonce.request = requests.Request("POST", nonce.url).prepare()
        with patch("app.utils.http_utils.requests.post", return_value=nonce):
            self.assertEqual(request_nonce("https://issuer.example.org/nonce"), "abc")

        status = requests.Response()
        status.status_code = 200
        status.headers["Content-Type"] = "application/statuslist+jwt"
        status._content = b"status.jwt.sig"
        status.url = "https://issuer.example.org/status"
        status.reason = "OK"
        status.request = requests.Request("GET", status.url).prepare()
        with patch("app.utils.http_utils.requests.get", return_value=status):
            self.assertEqual(request_status_list("https://issuer.example.org/status"), "status.jwt.sig")

        failed = requests.Response()
        failed.status_code = 503
        failed.headers["Content-Type"] = "text/plain"
        failed._content = b"down"
        failed.url = "https://issuer.example.org/par"
        failed.reason = "Unavailable"
        failed.request = requests.Request("POST", failed.url).prepare()
        with patch("app.utils.http_utils.requests.post", return_value=failed), patch("app.utils.http_utils.time.sleep"):
            with self.assertRaises(RuntimeError):
                http_request_with_retry("POST", failed.url, max_retries=1, retry_delay=0)
        self.assertEqual(get_status_description("0x00"), "Valido")
        self.assertEqual(get_status_description("0x09"), "Indefinito")

    def test_keys_jwt_and_sd_jwt_round_trip(self):
        from jwcrypto import jwk

        from app.utils import jwtUtils, sdJwtUtils, utils

        private = ec.generate_private_key(ec.SECP256R1())
        private_jwk = jwk.JWK.from_pem(
            private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        ).export(as_dict=True)
        private_jwk["kid"] = "issuer-key"
        public_jwk = json.loads(jwk.JWK.from_json(json.dumps(private_jwk)).export_public())
        public_jwk["kid"] = "issuer-key"
        issued = sdJwtUtils.issue_sd_jwt(
            "urn:pid",
            private_jwk,
            {"given_name": "Mario", "family_name": "Rossi", "vct": "urn:pid"},
            ["given_name", "family_name"],
            {"kid": "issuer-key", "typ": "dc+sd-jwt"},
            public_jwk,
        )
        self.assertIn("~", issued)
        revealed = sdJwtUtils.decode_and_verify_sd_jwt(issued, {"keys": [public_jwk]})
        self.assertEqual(revealed["given_name"], "Mario")
        self.assertTrue(jwtUtils.is_jwt(issued.split("~", 1)[0]))
        self.assertTrue(utils.check_curve_supported(private)[0])
        pair = utils.generate_pkce_pair()
        self.assertEqual(len(pair["code_verifier"]) >= 43, True)
        self.assertEqual(utils.parse_url_to_dict("haip://?client_id=wallet&request_uri=https://rp.example.org/r")["client_id"], "wallet")
        encoded = utils.base64url_encode(b"wallet")
        self.assertEqual(utils.base64url_decode(encoded), b"wallet")
        self.assertIn("family_name", utils.sanitize_for_logging("family_name\nRossi"))

    def test_service_error_paths_and_transaction_log(self):
        import app as app_module
        from app.service.itwallet_service import ItWalletService
        from app.store import transaction_log

        directory = tempfile.mkdtemp(prefix="wallet-log-")
        self.addCleanup(shutil.rmtree, directory, True)
        with patch.object(transaction_log, "_PATH", os.path.join(directory, "transaction_log.json")):
            transaction_id = transaction_log.start_presentation({"name": "RP"}, [{"id": "pid"}])
            transaction_log.finish_presentation(transaction_id, "completata", [{"id": "pid"}])
            self.assertEqual(transaction_log.list_records()[0]["outcome"], "completata")
            open_id = transaction_log.start_presentation({"name": "RP"}, [])
            transaction_log.interrupt_if_open(open_id)
            transaction_log.abandon_open_presentation({"rp_transaction_id": "missing"})

        with demo_app().test_request_context():
            from flask import session as flask_session

            flask_session["session_id"] = "session"
            service = ItWalletService(flask_session)
            with self.assertRaises(ValueError):
                service.initialize_wallet("CIE3", "ZZ")
            flask_session.clear()
            with self.assertRaises(ValueError):
                service.complete_presentation([])
            removed = service.delete_credential_wallet("dc_sd_jwt_eid")
            self.assertTrue(removed["success"])
            self.assertFalse(removed["data"]["wallet_initialized"])
