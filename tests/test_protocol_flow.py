"""Issuance and presentation through the public service methods, with local JWKS."""

import base64
import json
import os
import secrets
import shutil
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import jwt
import yaml
from flask import session
from jwcrypto import jwk

from app.store import app_state
from app.utils.sdJwtUtils import issue_sd_jwt
from app.utils.utils import ec_private_key_from_pem_file, get_thumbprint_from_private_key, pub_ec_key_obj_to_jwk

TRUST = "https://trust-anchor.example.org"
PROVIDER = "https://provider.example.org"
ISSUER = "https://issuer.example.org"
VERIFIER = "https://verifier.example.org"
PID_VCT = "urn:eudi:pid:it:1"
OTHER_VCT = "urn:eudi:other:1"


def _key(kid, use="sig"):
    generated = jwk.JWK.generate(kty="EC", crv="P-256")
    private = generated.export(as_dict=True)
    private.update({"kid": kid, "alg": "ES256", "use": use})
    public = {name: private[name] for name in ("kty", "crv", "x", "y", "kid", "alg", "use")}
    return private, public


SIGN_PRIVATE, SIGN_PUBLIC = _key("issuer-key")
_ENC_PRIVATE, ENC_PUBLIC = _key("enc-key", "enc")


def _sign(payload, typ="JWT"):
    from app.utils.utils import pem_private_key_from_jwk_dict

    pem = pem_private_key_from_jwk_dict(SIGN_PRIVATE)
    headers = {"kid": "issuer-key", "alg": "ES256", "typ": typ}
    body = dict(payload)
    for _ in range(8):
        body["jti"] = secrets.token_hex(8)
        token = jwt.encode(body, pem, algorithm="ES256", headers=headers)
        signature = base64.urlsafe_b64decode(token.split(".")[2] + "==")
        if not signature or signature[0] != 0x30:
            return token
    return token


def _now():
    return int(time.time())


class _Response:
    def __init__(self, body, content_type, status=200):
        self.status_code = status
        self.ok = 200 <= status < 300
        self.headers = {"Content-Type": content_type}
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode()
        self.reason = "OK" if self.ok else "Error"
        self.request = None
        self.url = ""

    def json(self):
        return json.loads(self.text)


class LocalIssuer:
    """Answers the wallet's HTTP calls with JWTs signed by the local key."""

    def __init__(self, key_dir):
        self.key_dir = key_dir
        self.callback_state = "rp-state"
        self.callback_iss = VERIFIER
        self.callback_code = None

    def _wallet_key(self):
        return ec_private_key_from_pem_file(os.path.join(self.key_dir, "pvt_key.pem"))

    def _thumb(self):
        return get_thumbprint_from_private_key(self._wallet_key())

    def _entity(self, url):
        now = _now()
        payload = {
            "iss": url,
            "sub": url,
            "iat": now,
            "exp": now + 3600,
            "jwks": {"keys": [SIGN_PUBLIC]},
            "metadata": self._metadata(url),
        }
        if url != TRUST:
            payload["authority_hints"] = [TRUST]
        return _sign(payload, "entity-statement+jwt")

    def _metadata(self, url):
        if url == TRUST:
            return {"federation_entity": {"organization_name": "Trust"}}
        if url == PROVIDER:
            return {
                "federation_entity": {"organization_name": "Provider"},
                "openid_wallet_provider": {"jwks": {"keys": [SIGN_PUBLIC]}},
            }
        if url == VERIFIER:
            return {
                "federation_entity": {
                    "organization_name": "Sportello",
                    "logo_uri": "https://verifier.example.org/logo.png",
                    "homepage_uri": "https://verifier.example.org",
                    "policy_uri": "https://verifier.example.org/policy",
                    "tos_uri": "https://verifier.example.org/terms",
                    "contacts": ["ops@verifier.example.org"],
                },
                "openid_credential_verifier": {
                    "jwks": {"keys": [SIGN_PUBLIC]},
                    "client_name": "Sportello",
                    "contacts": ["desk@verifier.example.org"],
                    "erasure_endpoint": "https://verifier.example.org/erasure",
                },
            }
        return {
            "federation_entity": {"organization_name": "Issuer"},
            "oauth_authorization_server": {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "pushed_authorization_request_endpoint": ISSUER + "/par",
                "token_endpoint": ISSUER + "/token",
                "jwks": {"keys": [SIGN_PUBLIC]},
            },
            "openid_credential_issuer": {
                "credential_issuer": ISSUER,
                "nonce_endpoint": ISSUER + "/nonce",
                "credential_endpoint": ISSUER + "/credential",
                "jwks": {"keys": [SIGN_PUBLIC]},
                "credential_configurations_supported": {
                    "dc_sd_jwt_eid": {"format": "dc+sd-jwt", "scope": "pid"},
                    "dc_sd_jwt_other": {"format": "dc+sd-jwt", "scope": "other"},
                },
            },
        }

    def _access_token(self):
        thumb = self._thumb()
        bound = base64.urlsafe_b64encode(thumb.encode()).decode().rstrip("=")
        now = _now()
        return _sign(
            {
                "iss": ISSUER,
                "sub": "wallet",
                "client_id": thumb,
                "iat": now,
                "exp": now + 600,
                "cnf": {"jkt": bound},
            }
        )

    def _credential(self, identifier):
        vct = OTHER_VCT if identifier == "other-1" else PID_VCT
        holder = pub_ec_key_obj_to_jwk(self._wallet_key().public_key()).export_public(as_dict=True)
        now = _now()
        return issue_sd_jwt(
            vct,
            SIGN_PRIVATE,
            {"iss": ISSUER, "vct": vct, "iat": now, "exp": now + 3600, "given_name": "Mario", "family_name": "Rossi"},
            ["given_name", "family_name"],
            {"kid": "issuer-key", "typ": "dc+sd-jwt"},
            holder,
        )

    def _request_object(self):
        now = _now()
        return _sign(
            {
                "iss": VERIFIER,
                "client_id": VERIFIER,
                "state": "rp-state",
                "nonce": "rp-nonce",
                "response_uri": VERIFIER + "/response",
                "response_type": "vp_token",
                "response_mode": "direct_post.jwt",
                "iat": now,
                "exp": now + 600,
                "dcql_query": {
                    "credentials": [
                        {
                            "id": "pid",
                            "format": "dc+sd-jwt",
                            "meta": {"vct_values": [PID_VCT]},
                            "claims": [{"path": ["given_name"]}],
                        }
                    ]
                },
                "client_metadata": {"jwks": {"keys": [ENC_PUBLIC]}, "client_name": "Sportello"},
            },
            "oauth-authz-req+jwt",
        )

    def _callback(self):
        thumb = self._thumb()
        now = _now()
        claims = {"iss": self.callback_iss, "aud": thumb, "state": self.callback_state, "iat": now, "exp": now + 600}
        if self.callback_code:
            claims["code"] = self.callback_code
        token = _sign(claims)
        return f'<html><body><form><input type="hidden" name="response" value="{token}"></form></body></html>'

    def __call__(self, method, url, kwargs):
        path = url.split("?", 1)[0]
        if path.endswith("/.well-known/openid-federation"):
            base = path[: -len("/.well-known/openid-federation")]
            return _Response(self._entity(base), "application/entity-statement+jwt")
        if path.endswith("/list"):
            kind = parse_qs(urlparse(url).query).get("entity_type", [""])[0]
            listed = {
                "openid_wallet_provider": [PROVIDER],
                "openid_credential_issuer": [ISSUER],
                "oauth_authorization_server": [ISSUER],
            }.get(kind, [])
            return _Response(listed, "application/json")
        if path.endswith("/par"):
            return _Response({"request_uri": ISSUER + "/request-uri", "expires_in": 60}, "application/json")
        if path.endswith("/token"):
            return _Response(
                {
                    "token_type": "DPoP",
                    "access_token": self._access_token(),
                    "expires_in": 600,
                    "authorization_details": [
                        {"credential_configuration_id": "dc_sd_jwt_eid", "credential_identifiers": ["pid-1"]},
                        {"credential_configuration_id": "dc_sd_jwt_other", "credential_identifiers": ["other-1"]},
                    ],
                },
                "application/json",
            )
        if path.endswith("/nonce") and method.upper() == "POST":
            return _Response({"c_nonce": "c-nonce"}, "application/json")
        if path.endswith("/nonce"):
            return _Response({"nonce": "provider-nonce"}, "application/json")
        if path.endswith("/credential"):
            identifier = (kwargs.get("json") or {}).get("credential_identifier")
            return _Response({"credentials": [{"credential": self._credential(identifier)}]}, "application/json")
        if path.endswith("/wallet-attestation"):
            now = _now()
            return _Response(
                {
                    "wallet_attestations": [
                        {"wallet_app_attestation": _sign({"iss": PROVIDER, "iat": now, "exp": now + 3600})},
                        {"wallet_unit_attestation": _sign({"iss": PROVIDER, "iat": now, "exp": now + 3600, "unit": True})},
                    ]
                },
                "application/json",
            )
        if "/request" in path and method.upper() == "GET":
            return _Response(self._request_object(), "application/oauth-authz-req+jwt")
        if path.endswith("/response"):
            return _Response({"redirect_uri": VERIFIER + "/callback"}, "application/json")
        if path.endswith("/callback"):
            return _Response(self._callback(), "text/html")
        if path.endswith("/.well-known/openid-credential-issuer"):
            return _Response(self._metadata(ISSUER)["openid_credential_issuer"], "application/json")
        raise AssertionError(f"unexpected {method} {url}")


def _config():
    return {
        "provider_config": {"spec_version": "1.4.7", "public_url": PROVIDER},
        "credentials_config": {
            "supported_credentials": {
                "pid": {
                    "proto_version": "1",
                    "valid_for_wallet_activation": True,
                    "internal_mapping_ref": "pid",
                    "document_identifier": {"type": "vct", "value": PID_VCT},
                    "document_format": {"id": "sd-jwt-vc", "specs": {}},
                }
            },
            "internal_attributes_mappings": {"pid": {"given_name": {"sd-jwt-vc": {"element_identifier": "given_name"}}}},
        },
        "app": {
            "host": "127.0.0.1",
            "port": 8080,
            "debug_mode": False,
            "favicon_subpath": "img/IT-Wallet-Symbol-Primary-BlueItalia.svg",
            "static_folder": "static",
            "secret_key": "test-secret",
            "password": "wallet",
            "http_params": {"proxy": {"use_proxy": False}},
            "logging": {"level": "ERROR", "libs_enabled": False},
        },
        "wallet_instance": {"oauth_authorization_server": ISSUER, "trust_anchor": TRUST},
        "ms_trust_configuration": {"IT": {"trust_root": TRUST, "trust_framework": "oid-fed"}},
        "metadata": {
            "initialize_flow": {
                "credential_configuration_id": "dc_sd_jwt_eid",
                "response_mode": "query",
                "response_type": "code",
                "redirect_uri": "https://demo-wi.example.org:8080/wallet/cb",
                "idphints": {"CIE3": "", "SPID2": "https://demo.spid.example.org"},
            },
            "credential_flow": {
                "response_mode": "form_post.jwt",
                "response_type": "code",
                "redirect_uri": "https://demo-wi.example.org:8080/wallet/cb",
            },
            "presentation_flow": {"response_mode": "direct_post.jwt", "response_type": "vp_token"},
            "wallet_provider": {"id": PROVIDER},
        },
        "credential_issuers": "",
        "eudiw_lotl": "",
    }


class ProtocolFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config_dir = tempfile.mkdtemp(prefix="wallet-protocol-")
        with open(os.path.join(cls.config_dir, "app_config.yaml"), "w", encoding="utf-8") as handle:
            yaml.safe_dump(_config(), handle)
        import app as app_module
        import app.service.issuance as issuance
        import app.service.presentation_flow as presentation

        cls._previous = (app_module.CONFIG_DIR, issuance.CONFIG_DIR, presentation.CONFIG_DIR)
        app_module.CONFIG_DIR = cls.config_dir
        issuance.CONFIG_DIR = cls.config_dir
        presentation.CONFIG_DIR = cls.config_dir
        from app import create_app

        cls.app = create_app()
        cls.issuer = LocalIssuer(cls.config_dir)

    @classmethod
    def tearDownClass(cls):
        import app as app_module
        import app.service.issuance as issuance
        import app.service.presentation_flow as presentation

        app_module.CONFIG_DIR, issuance.CONFIG_DIR, presentation.CONFIG_DIR = cls._previous
        shutil.rmtree(cls.config_dir, ignore_errors=True)

    def _remember(self, code):
        state = session["oauth_state"]
        remembered = dict(session["issuance_requests"])
        entry = dict(remembered[state])
        entry["authorization_response"] = {"code": code, "state": state, "iss": ISSUER}
        remembered[state] = entry
        session["issuance_requests"] = remembered
        session["query_params"] = entry["authorization_response"]

    def test_issue_present_and_add_credential(self):
        from app.service.itwallet_service import ItWalletService

        app_state.credential_store.clear()
        app_state.ec_store.clear()
        app_state.wallet_initialized = False
        app_state.selected_country = "IT"
        issuer = self.issuer

        def get(url, **kwargs):
            return issuer("GET", url, kwargs)

        def post(url, **kwargs):
            return issuer("POST", url, kwargs)

        with patch("app.utils.http_utils.requests.get", get), patch("app.utils.http_utils.requests.post", post):
            with self.app.test_request_context():
                session["authenticated"] = True
                session["session_id"] = "session-1"
                service = ItWalletService(session)
                started = service.initialize_wallet("CIE3", "IT")
                self.assertTrue(started["success"])
                self.assertIn("redirect_url", started["data"])
                self._remember("abc")
                completed = service.complete_initialize_wallet()
                self.assertEqual(completed["data"]["credential_id"], "pid-1")
                self.assertTrue(app_state.wallet_initialized)

                added = service.add_credential_wallet("dc_sd_jwt_other")
                self.assertTrue(added["success"])
                self._remember("def")
                other = service.complete_add_credential_from_browser()
                self.assertEqual(other["data"]["credential_id"], "other-1")

                issuer.callback_state = "rp-state"
                issuer.callback_iss = VERIFIER
                issuer.callback_code = None
                requested = service.present_to_verifier(VERIFIER, VERIFIER + "/request", "get", "st")
                self.assertEqual(requested[0]["id"], "pid")
                self.assertEqual(session["rp_display"]["name"], "Sportello")
                presented = service.complete_presentation(requested)
                self.assertTrue(presented["success"])
                self.assertEqual(presented["relying_party"]["client_id"], VERIFIER)

                session["rp_state"] = session["session_id"]
                session["rp_nonce"] = "rp-nonce"
                session["rp_response_uri"] = VERIFIER + "/response"
                session["eaa_provider_url"] = ISSUER
                session["credential_configuration_id"] = "dc_sd_jwt_other"
                issuer.callback_state = session["session_id"]
                issuer.callback_iss = ISSUER
                issuer.callback_code = "shared-code"
                shared = service.complete_add_credential_wallet(
                    [
                        {
                            "id": "other",
                            "format": "dc+sd-jwt",
                            "meta": {"vct_values": [OTHER_VCT]},
                            "claims": [{"path": ["given_name"]}],
                        }
                    ]
                )
                self.assertTrue(shared["success"])
