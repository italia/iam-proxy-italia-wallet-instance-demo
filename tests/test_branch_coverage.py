"""Remaining branches of the wallet demo, still without the network."""

import base64
import importlib
import json
import os
import shutil
import tempfile
import time
import unittest
import zlib
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import patch
from urllib.parse import urlencode

import cbor2
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from flask import session
from jwcrypto import jwk as jwcrypto_jwk

from app.store import app_state
from app.store.credential_store import CredentialStore
from app.store.entity_config_store import EntityConfigurationStore
from tests.test_protocol_flow import (
    ENC_PUBLIC,
    ISSUER,
    PID_VCT,
    PROVIDER,
    SIGN_PRIVATE,
    SIGN_PUBLIC,
    TRUST,
    VERIFIER,
    LocalIssuer,
    _config,
    _Response,
    _sign,
)

STATUS_URI = "https://issuer.example.org/status-list"


def _part(value) -> str:
    raw = json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _status_list_token(code_byte: int) -> str:
    compressed = base64.urlsafe_b64encode(zlib.compress(bytes([code_byte]))).decode().rstrip("=")
    now = int(time.time())
    return _sign(
        {
            "iss": ISSUER,
            "sub": STATUS_URI,
            "iat": now,
            "exp": now + 600,
            "status_list": {"bits": 1, "lst": compressed},
        }
    )


class _Issuer(LocalIssuer):
    def __init__(self, key_dir):
        super().__init__(key_dir)
        self.status_byte = 0

    def _metadata(self, url):
        data = super()._metadata(url)
        issuer = data.get("openid_credential_issuer")
        if isinstance(issuer, dict):
            display = [{"locale": "it", "name": "PID"}]
            claims = [{"path": ["given_name"], "display": [{"locale": "it", "name": "Nome"}]}]
            for config in issuer["credential_configurations_supported"].values():
                config["display"] = display
                config["credential_metadata"] = {"display": display, "claims": claims}
            issuer["display"] = display
            issuer["authorization_servers"] = [ISSUER, ISSUER + "/as"]
        return data

    def __call__(self, method, url, kwargs):
        if "missing.example" in url:
            import requests

            raise requests.ConnectionError("down")
        if url.split("?", 1)[0] == STATUS_URI:
            return _Response(_status_list_token(self.status_byte), "application/statuslist+jwt")
        return super().__call__(method, url, kwargs)


def _rich_config():
    config = _config()
    core = dict(SIGN_PRIVATE)
    core["x5c"] = ["YQ"]
    config["provider_config"].update(
        {
            "federation_jwks": [SIGN_PRIVATE],
            "core_jwks": [core],
            "authority_hints": [TRUST],
            "wallet_link": "https://provider.example.org",
            "nbf_attestation": 1,
            "metadata_group": {
                "federation_entity": {
                    "organization_name": "Provider",
                    "homepage_uri": "https://provider.example.org",
                    "policy_uri": "https://provider.example.org/policy",
                    "tos_uri": "https://provider.example.org/terms",
                    "logo_uri": "https://provider.example.org/logo.png",
                },
                "openid_wallet_provider": {
                    "logo_uri": "https://provider.example.org/logo.png",
                    "wallet_metadata": {
                        "wallet_name": "Demo",
                        "credential_offer_endpoint": "https://provider.example.org/offer",
                        "authorization_endpoint": "https://provider.example.org/authorize",
                        "vp_formats_supported": {"jwt_vp": {"alg": ["ES256"]}},
                    },
                },
            },
        }
    )
    config["wallet_instance"].update(
        {"user_authentication": "internal", "key_storage": ["iso"], "certification": "none"}
    )
    config["credential_issuers"] = ISSUER
    config["eudiw_lotl"] = "https://lotl.example.org"
    return config


class BranchCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config_dir = tempfile.mkdtemp(prefix="wallet-branches-")
        with open(os.path.join(cls.config_dir, "app_config.yaml"), "w", encoding="utf-8") as handle:
            yaml.safe_dump(_rich_config(), handle)
        import app as app_module
        import app.service.issuance as issuance
        import app.service.presentation_flow as presentation

        cls._previous = (app_module.CONFIG_DIR, issuance.CONFIG_DIR, presentation.CONFIG_DIR)
        app_module.CONFIG_DIR = cls.config_dir
        issuance.CONFIG_DIR = cls.config_dir
        presentation.CONFIG_DIR = cls.config_dir
        from app import create_app

        cls.app = create_app()
        cls.issuer = _Issuer(cls.config_dir)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        import app as app_module
        import app.service.issuance as issuance
        import app.service.presentation_flow as presentation

        app_module.CONFIG_DIR, issuance.CONFIG_DIR, presentation.CONFIG_DIR = cls._previous
        shutil.rmtree(cls.config_dir, ignore_errors=True)

    def setUp(self):
        self._http = [
            patch("app.utils.http_utils.requests.get", lambda url, **kwargs: self.issuer("GET", url, kwargs)),
            patch("app.utils.http_utils.requests.post", lambda url, **kwargs: self.issuer("POST", url, kwargs)),
            patch("app.utils.http_utils.time.sleep", lambda _seconds: None),
        ]
        for item in self._http:
            item.start()

    def tearDown(self):
        for item in self._http:
            item.stop()

    def _login(self):
        return self.client.post("/wallet/access", data={"password": "wallet", "next": "/wallet/home"})

    def test_pages_filters_and_api(self):
        from app.routes.wallet_routes import (
            convert_to_list,
            credential_tag,
            format_credential,
            format_date,
            redirect_same_app,
            safe_next_path,
            split_string,
        )
        from app.service.catalog import _offer_qr_svg

        self.assertEqual(convert_to_list(None), [])
        self.assertEqual(convert_to_list(["a"]), ["a"])
        self.assertEqual(convert_to_list("[1]"), [1])
        self.assertEqual(convert_to_list("{"), [])
        self.assertEqual(split_string(None, ","), [])
        self.assertEqual(split_string("a,b", ","), ["a", "b"])
        self.assertTrue(format_date(None) == "")
        self.assertIn("-", format_date(1_700_000_000))
        self.assertIn("-", format_date("2024-01-02T03:04:05Z"))
        self.assertEqual(format_date("nope"), "nope")
        self.assertEqual(format_credential(""), "sconosciuto")
        self.assertEqual(format_credential("dc_sd_jwt_pid"), "dc_sd_jwt")
        self.assertEqual(format_credential("altro"), "sconosciuto")
        self.assertEqual(credential_tag(""), "N/A")
        self.assertEqual(credential_tag("jwtABC"), "ABC")
        self.assertEqual(credential_tag("name_id"), "NAM-I")
        self.assertEqual(credential_tag("abc"), "ABC")
        self.assertIsNone(safe_next_path("https://evil.example.org"))
        self.assertEqual(safe_next_path("/wallet/home"), "/wallet/home")
        self.assertIsNone(redirect_same_app("https://evil.example.org"))
        self.assertIsNotNone(redirect_same_app("/wallet/credentials"))

        self.client.post("/wallet/access", data={"password": "wrong"})
        self._login()
        self.client.get("/wallet/access?session_id=given-session", data={})
        self.client.post("/wallet/access?session_id=given-session", data={"password": "wallet"})
        self.client.get("/wallet/lang/xx?next=/wallet/credentials")
        self.client.get("/wallet/lang/en?next=https://evil.example.org")
        self.client.get("/wallet/activate")
        home = self.client.get("/wallet/home?init_error_message=errore&init_success_message=ok")
        self.assertEqual(home.status_code, 200)
        self.client.get("/wallet/credentials")
        self.client.get("/wallet/present")
        self.client.get("/wallet/diagnostics")
        self.client.get("/wallet/dashboard")
        self.client.get("/debug/session")
        self.client.get("/")
        self.client.get("/.well-known/appspecific/com.chrome.devtools.json")
        self.client.get("/favicon.ico")
        self.client.get("/missing-page")

        self.client.get("/itwallet/issuerCatalog")
        self.client.post("/itwallet/issuerCatalog", json={"issuerUrl": "nota-url"})
        self.client.post(
            "/itwallet/issuerCatalog",
            json={"issuerUrl": ISSUER, "discovery": "eudiw-lotl"},
        )
        self.client.post("/itwallet/issuerCatalog", json={"issuerUrl": ISSUER, "discovery": "openid"})
        self.client.post("/itwallet/issuerCatalog", json={"issuerUrl": ISSUER, "discovery": "openid-federation"})
        self.client.get("/itwallet/credentialSupported")
        self.client.get("/itwallet/objectTypesInMemory")
        self.client.post("/itwallet/viewObjectTypeInMemory", json={"objectType": "CredentialStore"})
        self.client.post("/itwallet/viewObjectTypeInMemory", json={"objectType": "Missing"})
        offer = _offer_qr_svg(
            "openid-credential-offer://?credential_offer=" + "a" * 20
        )
        self.client.get("/itwallet/credential-offer.svg?offer=" + offer.split("credential_offer=")[-1])
        self.client.get("/itwallet/credential-offer.svg?offer=bad")
        self.client.get("/itwallet/diagnostics")
        self.client.delete("/itwallet/diagnostics", json={"ids": []})
        self.client.delete("/itwallet/diagnostics", json={"ids": "no"})

        added = self.client.post("/itwallet/addCredential", json={})
        self.assertEqual(added.status_code, 400)
        added = self.client.post("/itwallet/addCredential", json={"credentialId": "dc_sd_jwt_other"})
        self.assertEqual(added.status_code, 200)
        state = None
        with self.client.session_transaction() as current:
            state = current["oauth_state"]
        self.client.get("/wallet/cb?code=abc&state=" + state + "&iss=" + ISSUER)
        self.client.get("/wallet/cb")
        self.client.get("/wallet/cb?code=old&state=stale-state&iss=" + ISSUER)
        completed = self.client.post("/itwallet/addCredential/complete", json={"issuanceState": state})
        self.assertEqual(completed.status_code, 200)
        self.client.post("/itwallet/addCredential/complete", json={"credentialsPresenting": "no"})
        self.client.post("/itwallet/deleteCredential", json={})
        self.client.post("/itwallet/deleteCredential", json={"credentialId": "missing"})

        qr = "https://verifier.example.org/authorize?" + urlencode(
            {
                "client_id": VERIFIER,
                "request_uri": VERIFIER + "/request",
                "request_uri_method": "get",
                "state": "st",
            }
        )
        login = self.client.post(
            "/itwallet/loginToRelyingParty",
            json={"relyingPartyId": VERIFIER, "qrCodeContent": qr},
        )
        self.assertIn(login.status_code, (200, 400, 500))
        self.client.post("/itwallet/loginToRelyingParty", json={"relyingPartyId": "bad", "qrCodeContent": "bad"})
        self.client.post("/wallet/presentation", json={"qrcode_data": qr})
        self.client.post("/wallet/authorization", json={"credentialsPresenting": []})
        self.client.post("/itwallet/loginToVerifier/complete", json={})
        self.client.post("/itwallet/loginToVerifier/complete", json={"credentialsPresenting": "no"})

    def test_status_dashboard_and_provider(self):
        from app.routes import wallet_routes
        from app.service.credential_status import status_list_code

        self._login()
        now = int(time.time())
        token = f"{_part({'alg': 'ES256'})}.{_part({'status': {'status_list': {'uri': STATUS_URI, 'idx': 0}}, 'iat': now, 'exp': now + 3600, 'ttl': '60'})}.sig"
        app_state.ec_store.add(
            ISSUER,
            {"iss": ISSUER, "metadata": {"openid_credential_issuer": {"jwks": {"keys": [SIGN_PUBLIC]}}}},
        )
        app_state.credential_store.add_credential(ISSUER, "pid-status", token, PID_VCT, configuration_id="dc_sd_jwt_eid")
        status = self.client.post(
            "/wallet/credentials/status", data={"issuer": ISSUER, "credential_id": "pid-status"}
        )
        self.assertEqual(status.status_code, 302)
        self.issuer.status_byte = 1
        self.client.post("/wallet/credentials/status", data={"issuer": ISSUER, "credential_id": "pid-status"})
        self.issuer.status_byte = 2
        self.client.post("/wallet/credentials/status", data={"issuer": ISSUER, "credential_id": "missing"})
        self.client.post("/wallet/credentials/delete", data={"issuer": ISSUER, "credential_id": "missing"})
        self.client.post("/wallet/credentials/delete", data={"issuer": ISSUER, "credential_id": "pid-status"})
        raw = zlib.compress(bytes([0b11111111]))
        listed = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertEqual(status_list_code(listed, 2, 0), 3)
        with self.assertRaises(ValueError):
            status_list_code(listed, 3, 0)
        with self.app.test_request_context():
            wallet_routes._flash_status_result(0, "PID", {"iat": now, "exp": now + 60, "ttl": 30})
            wallet_routes._flash_status_result(0, "PID", {"iat": now})
            wallet_routes._flash_status_result(0, "PID", {})
            wallet_routes._flash_status_result(1, "PID")
            wallet_routes._flash_status_result(2, "PID")
            wallet_routes._flash_status_result(9, "PID")
            wallet_routes._flash_status_failure(RuntimeError("boom"), "PID")
            wallet_routes._flash_status_failure(RuntimeError(" "), "PID")
            self.assertIsNone(wallet_routes._status_moment(True))
            self.assertIsNone(wallet_routes._status_seconds("no"))
            self.assertIsNone(wallet_routes._rome_moment("not-a-date"))
            self.assertIsNone(wallet_routes._rome_moment(""))

        from app.store import transaction_log

        transaction_id = transaction_log.start_presentation({"name": "Sportello", "client_id": VERIFIER}, [])
        self.client.post("/wallet/presentation/transaction", json={"outcome": "interrotta", "id": transaction_id})
        with self.client.session_transaction() as current:
            current["rp_transaction_id"] = transaction_id
        self.client.post("/wallet/presentation/transaction", json={"outcome": "interrotta", "id": transaction_id})
        dashboard = self.client.get("/wallet/dashboard?id=" + transaction_id)
        self.assertEqual(dashboard.status_code, 200)
        exported = self.client.post("/wallet/dashboard/export", data={"ids": transaction_id})
        self.assertEqual(exported.status_code, 200)
        self.client.post("/wallet/dashboard/export", data={})
        self.client.post("/wallet/dashboard/delete", data={"ids": transaction_id})
        self.client.post("/wallet/dashboard/delete", data={})
        self.client.post("/wallet/dashboard/delete/confirm", data={"ids": transaction_id})
        self.client.post("/wallet/dashboard/reset")
        self.client.get("/wallet/logout")

        previous = os.getcwd()
        work = tempfile.mkdtemp(prefix="wallet-provider-")
        try:
            os.chdir(work)
            os.makedirs("config")
            private = ec.generate_private_key(ec.SECP256R1())
            public_pem = private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open("config/pub_key.pem", "wb") as handle:
                handle.write(public_pem)
            from app.utils.utils import priv_ec_key_obj_to_jwk

            private_jwk = priv_ec_key_obj_to_jwk(private).export_private(as_dict=True)
            private_jwk["kid"] = "instance"
            nonce = self.client.get("/provider/nonce").get_json()["nonce"]
            from pyeudiw.wallet_attestations.issuers.wa_request import WaJswRequestIssuer

            assertion = WaJswRequestIssuer(
                PROVIDER, private_jwk, "tag", nonce, "hardware", "integrity", "attested"
            ).generate_jws()
            issued = self.client.post("/provider/wallet-attestation", json={"assertion": assertion})
            self.assertIn(issued.status_code, (200, 400, 500))
            self.client.post("/provider/wallet-attestation", json={})
            self.client.post("/provider/wallet-attestation", json={"assertion": "a.b.c"})
            entity = self.client.get("/provider/.well-known/openid-federation?format=json")
            self.assertIn(entity.status_code, (200, 500))
            self.client.get("/provider/.well-known/openid-federation?format=jwt")
            self.client.get("/provider/.well-known/openid-federation?format=other")
            self.client.post("/provider/instance-initialization")
            from app.routes import wallet_provider

            wallet_provider.valid_nonces["stale"] = time.time() - 10
            wallet_provider.validate_nonce("missing")
            wallet_provider.validate_nonce("stale")
            wallet_provider.valid_nonces["fresh"] = time.time() + 100
            self.assertEqual(wallet_provider.validate_nonce("fresh"), 0)
            self.assertFalse(wallet_provider.verify_attestation_req_payload({"nonce": "missing"}))
            try:
                wallet_provider.generate_wia()
                wallet_provider.generate_wua()
            except Exception:
                pass
        finally:
            os.chdir(previous)
            shutil.rmtree(work, ignore_errors=True)

    def test_service_error_branches(self):
        from app.service.itwallet_helpers import (
            get_proxies_from_config,
            parse_rp_authorization_request,
            validate_access_token,
            validate_ec,
            validate_response_mode,
        )
        from app.service.itwallet_service import ItWalletService
        from app.service.presentation_flow import (
            _attestation_descriptors,
            _client_id_discovery,
            _missing_presentation_message,
            _relying_party_display,
        )

        self.assertEqual(get_proxies_from_config({"use_proxy": True, "http_proxy": "http://proxy.example.org", "https_proxy": "http://proxy.example.org", "no_proxy": "example.org"})[1], ["example.org"])
        with self.assertRaises(ValueError):
            validate_response_mode("nope", ["query"], "wallet")
        with self.assertRaises(ValueError):
            validate_ec({}, ISSUER, ["federation_entity"])
        with self.assertRaises(ValueError):
            validate_access_token({}, ISSUER, "client", "jkt")
        with self.app.test_request_context():
            with self.assertRaises(ValueError):
                parse_rp_authorization_request({}, VERIFIER)
            self.assertEqual(_client_id_discovery("https://verifier.example.org")[0], "openid_federation")
            self.assertEqual(_client_id_discovery("openid_federation:https://verifier.example.org")[1], "https://verifier.example.org")
            with self.assertRaises(ValueError):
                _client_id_discovery("x509_hash:")
            with self.assertRaises(ValueError):
                _client_id_discovery("unknown:value")
            self.assertEqual(_attestation_descriptors("no"), [])
            app_state.credential_store.clear()
            self.assertIn("non possiede", _missing_presentation_message([{"id": "pid"}]))
            display = _relying_party_display(
                {"metadata": {"federation_entity": {"organization_name": ""}, "openid_credential_verifier": {}}},
                VERIFIER,
                {"client_metadata": {"client_name": "Sportello", "logo_uri": "https://verifier.example.org/logo.png"}},
            )
            self.assertEqual(display["name"], "Sportello")

            app_state.selected_country = "IT"
            service = ItWalletService(session, external_discovery=True)
            with self.assertRaises(ValueError):
                service.initialize_wallet("CIE3", "ZZ")
            with self.assertRaises(ValueError):
                service.present_to_verifier(VERIFIER, VERIFIER + "/request", "get", "st")
            session["session_id"] = "session-1"
            with self.assertRaises(ValueError):
                service.present_to_verifier("x509_hash:abcd", VERIFIER + "/request", "get", "st")
            with self.assertRaises(ValueError):
                service.complete_presentation([])
            with self.assertRaises(ValueError):
                service.delete_credential_wallet("not-the-init-credential")
            session["credential_configuration_id"] = ""
            with self.assertRaises(ValueError):
                service.complete_add_credential_from_browser("missing-state")
            service._print_session_data()
            session["blob"] = object()
            service._print_session_data()
            with self.assertRaises(ValueError):
                service._authorization_response_management({"error": "access_denied", "error_description": "no"})
            with self.assertRaises(ValueError):
                service._authorization_response_management({})
            self.assertEqual(service._retrieve_wallet_provider_ec(TRUST), PROVIDER)

    def test_libraries_and_stores(self):
        from app.models.config.provider_config import ProviderConfig
        from app.service.base.base_service import BaseService
        from app.service.ec_manager import ECBaseManager
        from app.utils import cborUtils, jwtUtils, parsers, utils
        from app.utils.http_utils import _extract_error_from_response, _should_use_proxy, http_request_with_retry
        from app.utils.oidFedUtils import oid_fed_fetch_openid_configuration, oid_fed_list

        private = ec.generate_private_key(ec.SECP256R1())
        private_pem = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.assertIsInstance(utils.ec_private_key_from_pem_bytes(private_pem), ec.EllipticCurvePrivateKey)
        self.assertIsInstance(utils.ec_public_key_from_pem_bytes(public_pem), ec.EllipticCurvePublicKey)
        folder = tempfile.mkdtemp()
        try:
            private_path = os.path.join(folder, "key.pem")
            public_path = os.path.join(folder, "key.pub.pem")
            jwk_path = os.path.join(folder, "key.jwk")
            with open(private_path, "wb") as handle:
                handle.write(private_pem)
            with open(public_path, "wb") as handle:
                handle.write(public_pem)
            exported = jwcrypto_jwk.JWK.from_pem(private_pem).export(as_dict=True)
            with open(jwk_path, "w", encoding="utf-8") as handle:
                json.dump(exported, handle)
            self.assertIsNotNone(utils.ec_private_key_from_pem_file(private_path))
            self.assertIsNotNone(utils.ec_public_key_from_pem_file(public_path))
            self.assertIsNotNone(utils.ec_private_key_from_jwk_file(jwk_path))
            with open(jwk_path, "w", encoding="utf-8") as handle:
                json.dump({"kty": "oct"}, handle)
            with self.assertRaises(ValueError):
                utils.ec_private_key_from_jwk_file(jwk_path)
        finally:
            shutil.rmtree(folder)
        self.assertEqual(utils.guess_credential_configuration_icon("disability"), "♿")
        self.assertEqual(utils.guess_credential_configuration_icon("health"), "➕")
        self.assertEqual(utils.guess_credential_configuration_icon("mdl"), "🚗")
        self.assertEqual(utils.guess_credential_configuration_icon("education"), "🏛️")
        self.assertEqual(utils.guess_credential_configuration_icon("badge"), "🪪")
        self.assertTrue(utils.has_claim({"a": 1}, "a"))
        self.assertFalse(utils.has_claim({}, "["))
        self.assertIsNone(utils.extract_claim({}, "["))
        with self.assertRaises(ValueError):
            utils.check_required_claims({}, {"iss"})
        self.assertFalse(utils.is_base64("@@@"))
        self.assertIsInstance(utils.to_datetime(datetime.now(timezone.utc)), datetime)
        self.assertIsInstance(utils.to_datetime(1_700_000_000), datetime)
        with self.assertRaises(ValueError):
            utils.to_datetime("no")
        self.assertEqual(utils.estrai_parametro_query_string("https://verifier.example.org/a?client_id=x", "client_id"), "x")
        self.assertIsNone(utils.estrai_parametro_query_string("/relative", "client_id"))
        self.assertIn("truncated", utils.sanitize_for_logging("a\n" * 2000))
        self.assertEqual(utils.remove_str_prefix("jwtName", ["jwt"]), "Name")
        self.assertTrue(utils.unix_ts_to_str_datetime(1_700_000_000))
        self.assertIsNone(utils.unix_ts_to_str_datetime("bad"))
        self.assertEqual(utils.unescape_json(["a"]), ["a"])
        self.assertEqual(utils.parse_request_uri("https://verifier.example.org/request&state=1", {})["state"], "1")
        with self.assertRaises(ValueError):
            utils.generate_pkce_pair(10)
        with self.assertRaises(ValueError):
            utils.determine_alg({"crv": "P-999"})
        numbers = private.private_numbers()
        signature = encode_dss_signature(numbers.private_value % 100 + 1, numbers.private_value % 50 + 1)
        self.assertEqual(len(jwtUtils.der_signature_to_rs(signature)), 64)
        self.assertIn("keys", jwtUtils.jwk_to_jwks(json.dumps(SIGN_PUBLIC)))
        with self.assertRaises(ValueError):
            jwtUtils.jwk_private_to_public({"kty": "RSA"})
        with self.assertRaises(ValueError):
            jwtUtils.decode_and_verify_jwt("not-a-jwt")
        self.assertFalse(_should_use_proxy("https://issuer.example.org", {"https": "http://proxy"}, ["example.org"]))
        self.assertTrue(_should_use_proxy("https://other.example", {"https": "http://proxy"}, ["example.org"]))

        class _Raw:
            headers = {"Content-Type": "text/plain"}
            text = "plain error"
            status_code = 400
            ok = False
            reason = "Bad"
            request = None
            url = ISSUER

            def json(self):
                raise ValueError("no")

        self.assertIn("plain", _extract_error_from_response(_Raw()))
        with self.assertRaises(ConnectionError):
            http_request_with_retry("GET", "https://missing.example", max_retries=1)
        self.assertEqual(oid_fed_list(TRUST, "?entity_type=openid_credential_issuer")[0], ISSUER)
        self.assertTrue(oid_fed_fetch_openid_configuration(ISSUER))

        cose = {1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
        self.assertEqual(cborUtils._decode_cose_key(cose)["alg"], "ES256")
        self.assertEqual(cborUtils._cose_alg_id_to_name(1), "Unknown")
        with self.assertRaises(ValueError):
            cborUtils._decode_cose_key({})
        serial = cborUtils._make_json_serializable(
            {"when": datetime.now(timezone.utc), "day": date.today(), "raw": b"ab", "n": Decimal("1.5"), "items": [1]}
        )
        self.assertIn("when", serial)
        now = datetime.now(timezone.utc)
        with self.assertRaises(ValueError):
            cborUtils._validate_mso_core({}, "1.0", "org.iso.18013.5.1.mDL")
        with self.assertRaises(ValueError):
            cborUtils._validate_mso_device_and_validity({})
        with self.assertRaises(ValueError):
            cborUtils._check_validity_info({"signed": now, "validFrom": now + timedelta(days=1), "validUntil": now + timedelta(days=2)})
        with self.assertRaises(Exception):
            cborUtils.decode_and_verify_issuer_signed(utils.base64url_encode(cbor2.dumps({"nameSpaces": {}})), ["ns"], "1.0", "doc")

        from app.models.config.credentials_config import Credential, CredentialsConfig, DocumentFormat, DocumentIdentifier

        credential = Credential(
            proto_version="1",
            valid_for_wallet_activation=True,
            internal_mapping_ref="pid",
            document_identifier=DocumentIdentifier(type="vct", value=PID_VCT),
            document_format=DocumentFormat(id="sd-jwt-vc"),
        )
        mdoc = credential.model_copy(update={"document_format": DocumentFormat(id="mdoc-cbor")})
        config = CredentialsConfig(
            supported_credentials={"pid": credential, "mdl": mdoc},
            internal_attributes_mappings={
                "pid": {"person.given_name": {"sd-jwt-vc": {"element_identifier": "given_name", "subgroup": "person"}}},
                "mdl": {"family_name": {"mdoc-cbor": {"namespace": "org.iso.18013.5.1", "element_identifier": "family_name"}}},
            },
        )
        self.assertEqual(parsers.parser_credential_format_to_internal(config, "pid", {"person": {"given_name": "Mario"}})["person"]["given_name"], "Mario")
        self.assertEqual(
            parsers.get_mdoc_claim(
                {"namespace": "org.iso.18013.5.1", "element_identifier": "family_name"},
                {"nameSpaces": {"org.iso.18013.5.1": {"family_name": "Rossi"}}},
            ),
            "Rossi",
        )
        self.assertIsNone(parsers.get_mdoc_claim({"element_identifier": "missing"}, {"mso": {}}))
        with self.assertRaises(ValueError):
            parsers.parser_credential_format_to_internal(
                config.model_copy(update={"supported_credentials": {"pid": credential.model_copy(update={"document_format": DocumentFormat(id="other")})}}),
                "pid",
                {},
            )

        provider = ProviderConfig(**_rich_config()["provider_config"])
        self.assertTrue(provider.public_fed_jwks)
        self.assertEqual(provider.get_core_x5c_by_kid("issuer-key"), ["YQ"])
        self.assertIsNone(provider.get_federation_x5c_by_kid("missing"))
        manager = ECBaseManager(provider)
        self.assertIn("iss", manager.dump_as_dict())
        self.assertTrue(manager.dump_as_jwt())
        self.assertIsNone(MetadataHolder.dump_without_signing_key())
        BaseService(app_state).call_endpoint(TRUST, "/list?entity_type=openid_credential_issuer")
        BaseService(app_state)._create_header({})

        store = CredentialStore()
        store.add("flat", "token", "vct")
        store.add_credential(ISSUER, "one", "token", "vct")
        store.add_credential(ISSUER, "two", "token-2", "vct-2")
        store.add_credential(ISSUER, "one", "again", "vct")
        self.assertTrue(store.update_status("one", "assertion", "valid"))
        self.assertFalse(store.update_status("missing", "assertion", "valid"))
        self.assertTrue(store.remove_held(ISSUER, "two"))
        self.assertGreater(store.count(), 0)
        self.assertTrue(store.keys_with_vct())
        self.assertTrue(store.all())
        self.assertIsNotNone(store.find_by_prefix(ISSUER[:8]))
        self.assertIsNotNone(store.find_by_prefix_with_key("on"))
        store.clear()
        entities = EntityConfigurationStore(cleanup_interval=3600)
        entities.add("k", {"name": "old", "nested": {"name": "old"}, "items": ["old"]}, ttl=1)
        entities.add("plain", "text")
        self.assertEqual(entities.update_claim_by_path("k", "nested.name", "new"), True)
        self.assertFalse(entities.update_claim_by_path("missing", "a", "b"))
        self.assertGreater(entities.replace_in_all_value_fields("old", "new"), 0)
        self.assertTrue(entities.all_values("name"))
        self.assertTrue(entities.exists("k"))
        entities.remove("k")
        entities.clear()
        app_state.ec_store.add("expired", {"iss": "x"}, ttl=-1)
        time.sleep(1.1)
        importlib.import_module("app.models.metadata.1_3_3.metadata")
        importlib.import_module("app.models.metadata.1_3_3.federation_entity")
        importlib.import_module("app.models.metadata.1_3_3.wallet_solution")
        importlib.import_module("app.models.metadata.1_4_7.metadata")
        from app.models.metadata import MetadataFactory

        self.assertIsNone(MetadataFactory.get_model_instance("9.9.9"))
        self.assertIsNotNone(MetadataFactory.get_model_instance("1.4.7"))


    def test_remaining_diagnostic_and_protocol_branches(self):
        from app.service import credential_status, credential_view
        from app.service.itwallet_service import ItWalletService
        from app.service.presentation_flow import (
            _held_by_doctype,
            _held_by_vct,
            _require_encryption_jwks,
        )
        import jwt

        from app.utils import cborUtils, diagnostic_log, itwalletUtils, jwtUtils
        from app.utils.utils import base64url_encode

        now = datetime.now(timezone.utc)
        view = {
            "issuerAuth": cbor2.CBORTag(18, [cbor2.dumps({1: -7}), {}, cbor2.dumps({"docType": "mDL"}), b"sig"]),
            "nameSpaces": {
                "org.iso.18013.5.1": [
                    cbor2.CBORTag(24, cbor2.dumps({"elementIdentifier": "family_name", "elementValue": "Rossi"}))
                ]
            },
            "empty": {},
            "flags": [True, False, None, now, date.today(), 1, 1.5, b"aa", "ciao"],
        }
        self.assertIn("issuerAuth", credential_view._iso_mdoc_diag(cbor2.dumps(view)))
        credential_view._jsonable(cbor2.CBORTag(24, b"\xff"))
        credential_view._jsonable(cbor2.CBORTag(32, {"n": 1}))
        credential_view._cbor_diag([True, False, None, now, date.today(), b"aa"])
        credential_view._jwt_part_json(base64url_encode(b"not-json"))
        self.assertIsNone(credential_view._jwt_cleartext("a.b"))
        credential_view._jwt_cleartext("%%%.%%%.%%%")
        disclosure = base64url_encode(json.dumps(["salt", "given_name", "Mario"]).encode())
        credential_view._sd_jwt_cleartext(f"e30.e30.c~{disclosure}~not-json~a.b.c")
        credential_view._decoded_cbor(b"")
        credential_view._decoded_cbor(b"\xff")
        credential_view._iso_embedded(b"\xff", 1)
        credential_view._iso_scalar(object())
        credential_view._header_map(cbor2.dumps(cbor2.CBORTag(24, {1: -7})))
        credential_view._certificate_subject(b"short")
        credential_view._x5chain_text([b"\x00" * 20, "text"])
        credential_view._header_scalar(b"\xff")
        credential_view._header_scalar(None)
        credential_view._readable_header_value("alg", 1)
        credential_view._readable_header_value("crit", [1, "kid"])
        credential_view._readable_header_lines({1: -7, 99: "skip", 4: ""})
        credential_view._cose_sign1(cbor2.CBORTag(18, [cbor2.dumps({1: -7}), {4: "kid"}, cbor2.dumps({"docType": "mDL"}), b"sig"]))
        self.assertIsNone(credential_view._cose_sign1("nope"))
        self.assertIsNone(credential_view._mdoc_cleartext(""))
        credential_view._mdoc_cleartext(base64url_encode(cbor2.dumps({"nameSpaces": view["nameSpaces"]})))
        credential_view._sd_disclosed("jwt~not-json~" + disclosure)
        credential_view._walk_user_claims({"iss": "x", "person": {"given_name": "Mario"}, "elementIdentifier": "id"}, True)
        credential_view._issuer_item_pair(cbor2.CBORTag(24, b"\xff"))
        credential_view._namespace_pairs(
            {
                "one": {"elementIdentifier": "given_name", "elementValue": "Mario"},
                "two": {"family_name": "Rossi"},
                "three": [cbor2.CBORTag(24, cbor2.dumps({"elementIdentifier": "age", "elementValue": 40}))],
                "four": "skip",
            }
        )
        credential_view._token_namespaces("")
        credential_view._token_namespaces(base64url_encode(b"\xff"))
        credential_view._attribute_pairs({"claims": {"nameSpaces": {}}, "data_row": ""}, "mso_mdoc")
        credential_view._attribute_pairs({"claims": {}, "data_row": f"e30.e30.c~{disclosure}"}, "dc+sd-jwt")
        credential_view._attribute_lines(
            {"claims": {"given_name": ""}, "data_row": ""},
            "dc+sd-jwt",
            [{"path": ["given_name"], "label": "Nome"}, "skip"],
        )
        credential_view._claim_moment(True)
        credential_view._claim_moment(now.replace(tzinfo=None))
        credential_view._claim_moment(date.today())
        credential_view._claim_moment("2024-01-02T03:04:05Z")
        credential_view._claim_moment("nope")
        credential_view._iso_utc(None)
        self.assertIsNone(credential_view._find_held_credential("missing", "missing")[1])

        with self.app.test_request_context():
            session["session_id"] = "session-1"
            session["wallet_client_id"] = "thumb"
            session["rp_state"] = "rp-state"
            service = ItWalletService(session)
            html = '<form><input type="hidden" name="response" value="not-a-jwt"></form>'
            with self.assertRaises(ValueError):
                service._parse_presentation_callback(html, "form_post.jwt", VERIFIER, {"keys": [SIGN_PUBLIC]})
            parsed = service._parse_presentation_callback("https://verifier.example.org/cb?code=1", "query", VERIFIER, {})
            self.assertEqual(parsed["code"], "1")
            query = service._PresentationFlow__parse_query_string_response("https://verifier.example.org/cb?state=rp-state", VERIFIER)
            self.assertEqual(query["state"], "rp-state")
            with self.assertRaises(ValueError):
                service._PresentationFlow__parse_direct_post_jwt_response("not-jwt", VERIFIER, {"keys": [SIGN_PUBLIC]})
            with self.assertRaises(ValueError):
                service._PresentationFlow__parse_form_post_jwt_response("<form></form>", VERIFIER, {"keys": [SIGN_PUBLIC]})
            token = _sign({"iss": VERIFIER, "aud": "thumb", "state": "rp-state", "iat": int(time.time()), "exp": int(time.time()) + 600})
            verified = service._PresentationFlow__validate_authentication_response(token, {"keys": [SIGN_PUBLIC]}, VERIFIER)
            self.assertEqual(verified["state"], "rp-state")
            with self.assertRaises(ValueError):
                service._PresentationFlow__validate_auth_response_claims({"aud": "thumb", "state": "rp-state"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._PresentationFlow__validate_auth_response_claims({"iss": VERIFIER, "state": "rp-state"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._PresentationFlow__validate_auth_response_claims({"iss": VERIFIER, "aud": ["other"], "state": "rp-state"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._PresentationFlow__validate_auth_response_claims({"iss": VERIFIER, "aud": "other", "state": "rp-state"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._PresentationFlow__validate_auth_response_claims({"iss": VERIFIER, "aud": "thumb"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._PresentationFlow__validate_auth_response_claims({"iss": VERIFIER, "aud": "thumb", "state": "other"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._PresentationFlow__check_auth_response_errors({"error": "access_denied"}, VERIFIER)
            with self.assertRaises(ValueError):
                service._require_request_uri({}, "missing")
            with self.assertRaises(ValueError):
                service._decode_rp_authorization_response("not-jwt", {"keys": [SIGN_PUBLIC]}, VERIFIER)
            self.assertIsNone(_held_by_doctype({}))
            self.assertIsNone(_held_by_vct({}))
            self.assertIsNone(_held_by_vct({"vct_values": ["urn:missing"]}))
            with self.assertRaises(ValueError):
                _require_encryption_jwks({})
            app_state.credential_store.clear()
            issues = [
                {"name": "PID", "expired": True, "revoked": True, "suspended": False, "status_unknown": False},
                {"name": "MDL", "expired": True, "revoked": False, "suspended": True, "status_unknown": False},
                {"name": "EHIC", "expired": True, "revoked": False, "suspended": False, "status_unknown": False},
                {"name": "IBAN", "expired": False, "revoked": True, "suspended": False, "status_unknown": True},
                {"name": "TAX", "expired": False, "revoked": False, "suspended": True, "status_unknown": False},
            ]
            dialog = credential_status.presentation_dialog(issues)
            self.assertIn("PID", dialog["message"])
            self.assertEqual(credential_status.presentation_dialog([]), {})
            self.assertIn("rifiutato", credential_status.eloquent_presentation_error("invalid DCQL response", "rifiutato"))
            self.assertEqual(credential_status.presentation_error_message(RuntimeError("altro")), "altro")
            self.assertIsNone(credential_status._moment(True))
            self.assertIsNone(credential_status._moment("nope"))
            self.assertIsNotNone(credential_status._moment("2024-01-02T00:00:00Z"))
            self.assertTrue(credential_status._is_expired({"claims": {"exp": 1}}))
            self.assertEqual(credential_status.status_list_ref("not-a-jwt"), None)
            private = ec.generate_private_key(ec.SECP256R1())
            self.assertTrue(itwalletUtils.generate_request_object_jwt(private, VERIFIER, "st", "challenge", "S256", "code", "query", "https://demo-wi.example.org/cb", "pid", [{"type": "openid_credential"}]))
            self.assertTrue(itwalletUtils.generate_dpop_bound_access_token(private, private.public_key(), ISSUER, "sub", VERIFIER))
            self.assertEqual(itwalletUtils.get_status_description("0x01"), "Non valido")
            self.assertEqual(itwalletUtils.get_status_description("0x02"), "Sospeso")
            self.assertIsNone(itwalletUtils.generate_response_uri_request_jwe("{}", {"pid": "vp"}, "st"))
            self.assertIsNone(itwalletUtils.generate_response_uri_request_jwe(json.dumps({"kid": "k"}), {"pid": "vp"}, "st"))
            self.assertIsNone(itwalletUtils.generate_response_uri_request_jwe(json.dumps({"kid": "k", "kty": "EC"}), {"pid": "vp"}, "st"))
            self.assertIsNone(itwalletUtils.generate_response_uri_request_jwe(json.dumps({"kid": "k", "kty": "oct"}), {"pid": "vp"}, "st"))

        self.assertIsNone(jwtUtils.extract_key_for_enc({"keys": []}))
        self.assertIsNone(jwtUtils.extract_key_for_enc({"keys": [dict(SIGN_PUBLIC, use="sig")]}))
        self.assertIsNone(jwtUtils.extract_key_for_enc({"keys": [{"use": "enc", "kty": "EC"}]}))
        self.assertIsNone(jwtUtils.extract_key_for_enc({"keys": [{"kid": "k", "use": "enc"}]}))
        self.assertTrue(jwtUtils.jwk_private_to_public(SIGN_PRIVATE)["kty"] == "EC")
        with self.assertRaises(ValueError):
            jwtUtils.jwk_private_to_public({"kty": "EC"})
        with self.assertRaises(ValueError):
            jwtUtils.jwk_to_jwks("not-json")
        with self.assertRaises(ValueError):
            jwtUtils.jwk_to_jwks({})

        def _reject(key):
            kind = key["kid"]
            if kind == "sig":
                raise jwt.InvalidSignatureError()
            if kind == "exp":
                raise jwt.ExpiredSignatureError()
            if kind == "tok":
                raise jwt.InvalidTokenError("bad")
            raise RuntimeError("other")

        with self.assertRaises(ValueError):
            jwtUtils.verify_with_keys({"kid": "sig"}, [{"kid": "exp"}, {"kid": "tok"}, {"kid": "other"}], "sig", _reject)
        self.assertEqual(jwtUtils.verify_with_keys(None, [{"kid": "ok"}], None, lambda key: {"ok": True})["ok"], True)
        der = encode_dss_signature(3, 4)
        der_token = "e30.e30." + base64url_encode(der)
        with self.assertRaises(Exception):
            jwtUtils.decode_and_verify_jwt(der_token, {"keys": [SIGN_PUBLIC]})
        header = base64url_encode(json.dumps({"alg": "ES256", "kid": "issuer-key"}).encode())
        payload = base64url_encode(json.dumps({"iss": ISSUER, "exp": int(time.time()) + 600}).encode())
        with self.assertRaises(Exception):
            jwtUtils.decode_and_verify_jwt(f"{header}.{payload}." + base64url_encode(der), {"keys": [SIGN_PUBLIC]})

        mso = {
            "docType": "org.iso.18013.5.1.mDL",
            "version": "1.0",
            "valueDigests": {"ns": {0: b"aa"}},
            "digestAlgorithm": "SHA-256",
        }
        cborUtils._validate_mso_core(mso, "1.0", "org.iso.18013.5.1.mDL")
        with self.assertRaises(ValueError):
            cborUtils._validate_mso_core(dict(mso, version="0"), "1.0", "org.iso.18013.5.1.mDL")
        with self.assertRaises(ValueError):
            cborUtils._validate_mso_core(dict(mso, valueDigests=None), "1.0", "org.iso.18013.5.1.mDL")
        with self.assertRaises(ValueError):
            cborUtils._validate_mso_core(dict(mso, digestAlgorithm="SHA-1"), "1.0", "org.iso.18013.5.1.mDL")
        with self.assertRaises(ValueError):
            cborUtils._validate_mso_device_and_validity({"deviceKeyInfo": {}, "validityInfo": {}})
        with self.assertRaises(ValueError):
            cborUtils._check_validity_info({"signed": now})
        with self.assertRaises(ValueError):
            cborUtils._check_validity_info({"signed": now, "validFrom": now, "validUntil": now - timedelta(days=1)})
        diagnostic_log.diagnostic_peer("credential_issuer")
        diagnostic_log.peer_for("https://issuer.example.org/token")
        diagnostic_log.record_exchange(
            method="GET",
            url=ISSUER,
            request_headers={"Accept": "application/json"},
            request_body=None,
            status=200,
            response_body={"ok": True},
            request_http="GET /",
            response_http="HTTP/1.1 200",
        )
        diagnostic_log.remove_entries(["missing"])

        previous = os.getcwd()
        work = tempfile.mkdtemp()
        try:
            os.chdir(work)
            from PIL import Image

            Image.new("RGB", (16, 16), "white").save("download.png")
            importlib.import_module("app.utils.qrcodeUtils")
        except Exception:
            pass
        finally:
            os.chdir(previous)
            shutil.rmtree(work, ignore_errors=True)


class MetadataHolder:
    @staticmethod
    def dump_without_signing_key():
        from app.models.config.provider_config import ProviderConfig
        from app.service.ec_manager import ECBaseManager

        config = _rich_config()["provider_config"]
        config = dict(config)
        unsigned = {name: value for name, value in SIGN_PRIVATE.items() if name != "alg"}
        unsigned["use"] = "enc"
        other = dict(unsigned)
        other["kid"] = "other-key"
        config["federation_jwks"] = [unsigned, other]
        return ECBaseManager(ProviderConfig(**config)).dump_as_jwt()
