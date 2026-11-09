"""IT Wallet service layer for credential issuance and presentation flows.

This module implements the core business logic for the Italian Digital Identity Wallet
(IT Wallet) instance demo. It orchestrates OpenID4VCI credential issuance flows and
OpenID4VP presentation flows, integrating with OID-Fed (OpenID Federation) for trust
and entity discovery.

Main flows implemented:
- Wallet initialization: PID credential issuance via EAA provider (oid_fed_list, PAR, auth)
- Add credential: Additional credential issuance (e.g. driving license) via EAA provider
- Login to verifier: Presentation flow to Relying Parties / Verifiers (request_uri, dcql)

Dependencies and data flow:
- Entity configurations (EC) are fetched via oid_fed_fetch_openid_configuration
- Credentials are stored in app_state.credential_store
- Session holds OAuth state (code_verifier, rp_state, rp_nonce, etc.)

Key components:
- ItWalletService: Main service class, uses session and app_state
- Token/credential flows use PAR, DPoP, PKCE per OAuth 2.0 / OIDC specs
- SD-JWT and mDL (ISO 18013-5) credential formats are supported
"""

import base64
import json
import logging
import os
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from flask import current_app
from flask_babel import gettext
from jwcrypto.common import base64url_decode
from pyeudiw.jwt.exceptions import LifetimeException
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.wallet_attestations.issuers.wa_request import WaJswRequestIssuer

from app import AppConfig
from app.constants import (
    APP_SETTINGS_KEY,
    AUTH_RESPONSE_MODE_FORM_POST_JWT,
    AUTH_RESPONSE_MODE_QUERY,
    AUTH_RESPONSE_TYPE_CODE,
    CONFIG_DIR,
    JWT_PREFIX,
    METADATA_TYPE_AUTHORIZATION_SERVER,
    METADATA_TYPE_CREDENTIAL_ISSUER,
    METADATA_TYPE_CREDENTIAL_VERIFIER,
    METADATA_TYPE_FEDERATION_ENTITY,
    METADATA_TYPE_WALLET_PROVIDER,
    MSO_MDOC_PREFIX,
    PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT,
    SD_JWT_PREFIX,
    WALLET_ATTESTATION_NAME,
    WALLET_UNIT_ATTESTATION_NAME,
)
from app.models.config.app_config import AppSettings
from app.models.config.credentials_config import Credential, CredentialsConfig
from app.service.discovery import FederationDiscovery
from app.service.itwallet_helpers import (
    apply_credential_issuer_overrides,
    apply_replace_values,
    get_proxies_from_config,
    get_trust_root_and_eaa_provider_ec,
    parse_rp_authorization_request,
    require_jwt_claim,
    require_session_key,
    validate_access_token,
    validate_credential_and_presentation_flow,
    validate_ec,
    validate_response_mode,
    validate_response_type,
)
from app.store import app_state
from app.utils.cborUtils import decode_and_verify_issuer_signed
from app.utils.diagnostic_log import diagnostic_peer
from app.utils.http_utils import _parse_json_response, http_request_with_retry
from app.utils.itwalletUtils import (
    generate_dpop_jwt,
    generate_par_request_object_jwt,
    generate_proof_jwt,
    generate_response_uri_request_jwe,
    generate_response_uri_request_jws,
    generate_wallet_attestation_pop_jwt,
    get_status_description,
    request_as_par,
    request_authorize,
    request_credential,
    request_nonce,
    request_presentation_callback,
    request_request_uri,
    request_response_uri,
    request_token,
)
from app.utils.jwtUtils import decode_and_verify_jwt, extract_key_for_enc, is_jwt
from app.utils.oidFedUtils import oid_fed_fetch_openid_configuration, oid_fed_list
from app.utils.sdJwtUtils import decode_and_verify_sd_jwt, paths_to_nested_dict, present_sd_jwt
from app.utils.utils import (
    ec_private_key_from_pem_file,
    ec_public_key_from_pem_file,
    extract_claim,
    generate_pem_keys,
    generate_pkce_pair,
    get_thumbprint_from_private_key,
    priv_ec_key_obj_to_jwk,
    pub_ec_key_obj_to_jwk,
    sanitize_for_logging,
)

logger = logging.getLogger(__name__)



class PresentationFlow:
    """Credential presentation for the wallet demo."""

    def _require_request_uri(self, response: dict, error_message: str) -> str:
        request_uri = response.get("request_uri")
        if not request_uri:
            raise ValueError(error_message)
        return request_uri


    def _decode_rp_authorization_response(
        self,
        authorize_response: str,
        eaa_provider_verifier_jwks: dict,
        eaa_provider_url: str,
    ) -> tuple[list[dict], str, str, str]:
        try:
            jwt_payload = decode_and_verify_jwt(authorize_response, eaa_provider_verifier_jwks)
        except ValueError as ve:
            raise ValueError(f"Validation JWT failed: {ve}")

        credentials_requested, rp_state, rp_nonce, rp_response_uri = parse_rp_authorization_request(
            jwt_payload, eaa_provider_url
        )
        logger.info("📄 Request_uri response JWT payload:")
        logger.info(f"jwt_payload {json.dumps(jwt_payload, indent=2, ensure_ascii=False)}")
        return credentials_requested, rp_state, rp_nonce, rp_response_uri


    def present_to_verifier(self, clientId: str, requestUri: str, requestUriMethod: str, state: str):
        """
        Metodo pubblico per effettuare il login ad un Relying Party / Verifier, incluso fetch dell'EC del Relying Party / Verifier.
        In sessione vengono salvati:
             self.session["rp_client_id"]
             self.session["rp_nonce"]
             self.session["rp_state"]
             self.session["rp_response_uri"]
        """
        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        # # recupero del response_mode relativo al presentation flow dalla configurazione e sua validazione
        # presentation_response_mode = extract_claim(current_app.config, "metadata.presentation_flow.response_mode")
        #
        # presentation_response_mode_supported = [PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT]
        # if presentation_response_mode not in presentation_response_mode_supported:
        #     raise ValueError(
        #         f"Il response_mode '{presentation_response_mode}' configurato per la presentazione delle credenziali del wallet non è supportato, i valori ammessi sono: {presentation_response_mode_supported}"
        #     )
        #
        # # recupero del response_type relativo al presentation flow dalla configurazione e sua validazione
        # presentation_response_type = extract_claim(current_app.config, "metadata.presentation_flow.response_type")
        #
        # presentation_response_type_supported = [PRESENTATION_RESPONSE_TYPE_VP_TOKEN]
        # if presentation_response_type not in presentation_response_type_supported:
        #     raise ValueError(
        #         f"Il response_type '{presentation_response_type}' configurato per l'inizializzazione del wallet non è supportato, i valori ammessi sono: {presentation_response_type_supported}"
        #     )

        country = app_state.selected_country
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)

        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")

        logger.info(f"query_trust_root: {query_trust_root}")

        # Richiama il metodo privato per ottenere l'EC, validarlo e recuperne il payload
        external_verifier_ec = self._entity_configuration_management(
            clientId, [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_VERIFIER], trust_root_url
        )

        logger.info(
            f"EC for {clientId} validated successfully with metadata types: {[METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_VERIFIER]}"
        )

        # Salvataggio in memoria Flask external_verifier_ec
        app_state.ec_store.add(clientId, external_verifier_ec)

        # Build authorization query string
        params = {
            "client_id": clientId,
            "request_uri": requestUri,
            "request_uri_method": requestUriMethod,
            "state": state,
        }
        query_string = f"?{urlencode(params)}"

        # @TODO Implements the POST logic: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/pid-eaa-presentation.html Steps 6-9 (Authorization Request)!!!
        # @TODO Add strategy pattern for
        request_uri_response = request_request_uri(
            url=requestUri, query_string=query_string, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains
        )

        logger.info(f"response: {request_uri_response}")

        if not is_jwt(request_uri_response):
            raise ValueError("La Request_uri response ricevuta dal Relying Party / Verifier non è un JWT")

        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_VERIFIER}.jwks"
        verifier_jwks = extract_claim(external_verifier_ec, query_filter)
        if not verifier_jwks:
            raise ValueError(f"Non trovata in memoria alcuna chiave JWK del Relying Party / Verifier {clientId}")

        try:
            request_uri_response_jwt_payload = decode_and_verify_jwt(request_uri_response, verifier_jwks)
            credentials_requested, rp_state, rp_nonce, rp_response_uri = parse_rp_authorization_request(
                request_uri_response_jwt_payload, clientId
            )
            logger.info(f"credential_requested: {credentials_requested}")
        except ValueError as ve:
            raise ValueError(f"Exception during JWT validation: {str(ve)}")

        self.session["rp_client_id"] = clientId
        self.session["rp_state"] = rp_state
        self.session["rp_nonce"] = rp_nonce
        self.session["rp_response_uri"] = rp_response_uri

        return credentials_requested


    def complete_presentation(self, credentials_presenting: list[dict]):
        """
        Metodo pubblico per completare il login ad un Verifier
        """

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        # recupero id del Relying Party / Verifier dalla sessione
        rp_client_id = self.session.get("rp_client_id")

        if not rp_client_id:
            raise ValueError("Non trovato l'URL del Relying Party / Verifier nella sessione")

        # recupero EC del Relying Party / Verifier dalla memoria usando come chiave di ricerca l'id del Relying Party / Verifier
        rp_ec = app_state.ec_store.get(rp_client_id)
        if not rp_ec:
            raise ValueError(f"Non trovato in memoria l'Entity Configuration dell'entità {rp_client_id}")

        # recupero i dati del RP Authorization Request dalla sessione
        rp_state = self.session.get("rp_state")
        rp_nonce = self.session.get("rp_nonce")
        rp_response_uri = self.session.get("rp_response_uri")

        if not rp_state:
            raise ValueError("Nessun rp_state trovato nella memoria")

        if not rp_nonce:
            raise ValueError("Nessun rp_nonce trovato nella memoria")

        if not rp_response_uri:
            raise ValueError("Nessun rp_response_uri trovato nella memoria")

        # Recupero JWK da usare per validare il jwt ricevuto in risposta dalla presentazione
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_VERIFIER}.jwks"
        rp_jwks = extract_claim(rp_ec, query_filter)
        if not rp_jwks:
            raise ValueError(f"Non trovata in memoria alcuna chiave JWK Relying Party / Verifier {rp_client_id}")

        logger.debug(f"rp_jwks: {rp_jwks}")

        # recupero del response_mode relativo al credentialflow dalla configurazione
        credential_flow_response_mode = extract_claim(current_app.config, "metadata.credential_flow.response_mode")

        logger.debug(f"credential_flow_response_mode: {credential_flow_response_mode}")

        authorizationResponse = self._presentation_management_v133(
            enc=True,
            credentials_presenting=credentials_presenting,
            rp_state=rp_state,
            rp_nonce=rp_nonce,
            rp_response_uri=rp_response_uri,
            rp_client_id=rp_client_id,
            rp_jwks=rp_jwks,
            response_mode=credential_flow_response_mode,
        )

        logger.info(
            f"ℹ️  Prodotto messaggio di risposta per la richiesta di completamento dell'operazione di login presso il Relying Party / Verifiier {rp_client_id} effettuata dal wallet"
        )
        logger.info("%s", sanitize_for_logging(json.dumps(authorizationResponse, indent=2, ensure_ascii=False)))

        # Stampo i dati in sessione
        self._print_session_data()

        return {"success": True}


    def _add_credential_presentation_to_vp(
        self,
        item: dict,
        vp_token_claims: dict,
        rp_client_id: str,
        rp_nonce: str,
        wallet_private_key_jwk_dict: dict,
    ) -> None:
        """Find credential for item, build SD-JWT presentation, add to vp_token_claims if found."""
        logger.debug(
            f"Entering method: _add_credential_presentation_to_vp. Params [item: {item}, vp_token_claims: {vp_token_claims}]"
        )
        result = self._find_credential_by_dcql_item(item)
        if not result:
            return
        key, value = result
        logger.info("✅ Recuperata la credenziale che è stata richiesta al wallet di presentare")
        vct = value.get("vct", "")
        status = value.get("status", "")
        logger.info(
            "ℹ️  Credenziale %s in stato: %s %s",
            sanitize_for_logging(vct),
            sanitize_for_logging(status),
            sanitize_for_logging(get_status_description(status)),
        )
        claim_paths = [c["path"][0] for c in item.get("claims", []) if c.get("path")]
        claim_paths_nested = paths_to_nested_dict(claim_paths)
        presentation = present_sd_jwt(
            vct=vct,
            sd_jwt_compact=value.get("data_row"),
            aud=rp_client_id,
            nonce=rp_nonce,
            claims_to_reveal=claim_paths_nested,
            holder_private_jwk_dict=wallet_private_key_jwk_dict,
        )
        if presentation:
            vp_token_claims[item["id"]] = presentation


    def _build_response_uri_request(
        self, enc: bool, vp_token_claims: dict, rp_state: str, rp_jwks: dict, wallet_private_key
    ) -> str:
        """Build JWE or JWS for response_uri request. Raises ValueError on failure."""
        if enc:
            enc_key_jwk = extract_key_for_enc(rp_jwks)
            if not enc_key_jwk:
                raise ValueError("Key not found for sign JWE")

            jwt = generate_response_uri_request_jwe(
                enc_key_json_str=enc_key_jwk, vp_token=vp_token_claims, state=rp_state
            )
        else:
            jwt = generate_response_uri_request_jws(
                private_key=wallet_private_key, vp_token=vp_token_claims, state=rp_state
            )
        if not jwt:
            raise ValueError("Exception generation Response_uri request JWE/JWS")
        return jwt


    def _presentation_management_v133(
        self,
        enc: bool,
        credentials_presenting: list[dict],
        rp_state: str,
        rp_nonce: str,
        rp_response_uri: str,
        rp_jwks: dict,
        response_mode: str,
        rp_client_id: str | None = None,
    ) -> dict:
        """Build vp_token from credentials_presenting, send response_uri request, return auth response."""
        logger.debug(
            f"Entering method: _presentation_management_v133. Params [enc: {enc}, credentials_presenting: {credentials_presenting}, rp_state: {rp_state}]"
        )

        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)

        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Public and private Key not found for wallet")

        wallet_private_key_jwk = priv_ec_key_obj_to_jwk(wallet_private_key)

        wallet_private_key_jwk_dict = wallet_private_key_jwk.export(as_dict=True)

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(f"wallet_client_id: {wallet_client_id}")

        self.session["wallet_client_id"] = wallet_client_id

        vp_token_claims = {}

        for item in credentials_presenting:
            self._add_credential_presentation_to_vp(
                item,
                vp_token_claims,
                rp_client_id if rp_client_id else rp_response_uri,  # todo check
                rp_nonce,
                wallet_private_key_jwk_dict,
            )

        if len(vp_token_claims) == 0:
            raise ValueError("vp_token empty claim")

        logger.info(f"vp_token: {(list(vp_token_claims.keys()))}")

        response_uri_request_jwt = self._build_response_uri_request(
            enc, vp_token_claims, rp_state, rp_jwks, wallet_private_key
        )

        logger.info(f"rp_response_uri: {rp_response_uri}")

        response_uri_response = request_response_uri(
            url=rp_response_uri,
            response_uri_request_jwt=response_uri_request_jwt,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info(f"response_uri_response: {response_uri_response}")

        redirect_uri = response_uri_response.get("redirect_uri")

        if redirect_uri:
            logger.info(f"redirect_uri: {redirect_uri}")

            callback_response = request_presentation_callback(
                url=redirect_uri, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains
            )

            logger.info(f"callback_response: {callback_response}")
            if rp_client_id:  # todo: Check if necessary and compare the differences
                return self._parse_presentation_callback(callback_response, response_mode, redirect_uri, rp_jwks)

            return self.__parse_presentation_callback_v133(callback_response, response_mode, redirect_uri, rp_jwks)
        else:
            logger.warning(f"redirect_uri empty, json: {json.dumps(response_uri_response, indent=2)}")

            return response_uri_response


    def _parse_presentation_callback(
        self, callback_response: str, response_mode: str, redirect_uri: str, rp_jwks: dict
    ) -> dict:
        """Parse presentation callback (HTML form or query string) and return payload."""
        if response_mode == AUTH_RESPONSE_MODE_FORM_POST_JWT:
            soup = BeautifulSoup(callback_response, "html.parser")
            inp = soup.find("input", {"type": "hidden", "name": "response"})
            if not inp or not inp.has_attr("value"):
                raise ValueError(f"Pagina HTML da {redirect_uri} non contiene campo 'response'")
            jwt_val = inp["value"]
            if not is_jwt(jwt_val):
                raise ValueError(f"Il campo 'response' da {redirect_uri} non è un JWT")
            return decode_and_verify_jwt(jwt_val, rp_jwks)
        parsed = urlparse(callback_response)
        return {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}


    def __parse_presentation_callback_v133(
        self, callback_response: str, response_mode: str, redirect_uri: str, rp_jwks: dict
    ) -> dict:
        logger.debug(
            f"Entering method: _parse_presentation_callback_v133. Params [callback_response: {callback_response}, response_mode: {response_mode}]"
        )

        if response_mode == AUTH_RESPONSE_MODE_FORM_POST_JWT:
            return self.__parse_form_post_jwt_response(callback_response, redirect_uri, rp_jwks)
        elif response_mode == PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT:
            return self.__parse_direct_post_jwt_response(callback_response, redirect_uri, rp_jwks)
        else:
            return self.__parse_query_string_response(callback_response, redirect_uri)


    def __parse_form_post_jwt_response(self, callback_response: str, redirect_uri: str, rp_jwks: dict) -> dict:
        logger.debug(
            f"Entering method: _parse_form_post_jwt_response. Params [callback_response: {callback_response}, redirect_uri: {redirect_uri}]"
        )

        bea_soup = BeautifulSoup(callback_response, "html.parser")

        input = bea_soup.find("input", {"type": "hidden", "name": "response"})

        if not input or not input.has_attr("value"):
            raise ValueError("Hidden response not found.")

        jwt_val = input["value"]

        if not is_jwt(jwt_val):
            raise ValueError("Validation Exception: jwt_val not valid")

        return self.__validate_authentication_response(jwt_val, rp_jwks, redirect_uri)


    def __parse_direct_post_jwt_response(self, callback_response: str, redirect_uri: str, rp_jwks: dict) -> dict:
        logger.debug(
            f"Entering method: __parse_direct_post_jwt_response. Params [callback_response: {callback_response}]"
        )

        response_str = callback_response.strip()

        if not is_jwt(response_str):
            raise ValueError("JWT not valid")

        return self.__validate_authentication_response(response_str, rp_jwks, redirect_uri)


    def __parse_query_string_response(self, callback_response: str, redirect_uri: str) -> dict:
        logger.debug(
            f"Entering method: __parse_query_string_response. Params [callback_response: {callback_response}, redirect_uri: {redirect_uri}]"
        )

        parsed = urlparse(callback_response)

        result = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}

        logger.info(f"list(result.keys(): {list(result.keys())}")

        return result


    def __validate_authentication_response(self, jwt_response: str, rp_jwks: dict, redirect_uri: str) -> dict:

        logger.debug(
            f"Entering method: _validate_authentication_response. Params [jwt_response: {jwt_response}, rp_jwks: {rp_jwks}]"
        )

        try:
            auth_response_payload = decode_and_verify_jwt(jwt_response, rp_jwks)
            logger.info("JWT signature valid")
        except ValueError as e:
            raise ValueError(f"JWT not valid, cause: {e}")

        self.__validate_auth_response_claims(auth_response_payload, redirect_uri)

        self.__check_auth_response_errors(auth_response_payload, redirect_uri)

        logger.info(f"auth_response_payload: {json.dumps(auth_response_payload, indent=2, ensure_ascii=False)}")

        return auth_response_payload


    def __validate_auth_response_claims(self, payload: dict, redirect_uri: str) -> None:
        logger.debug(
            f"Entering method: _validate_auth_response_claims. Params [payload: {payload}, redirect_uri: {redirect_uri}]"
        )

        iss = payload.get("iss")

        if not iss:
            raise ValueError("iss not found")

        logger.info(f"iss: {iss}")

        aud = payload.get("aud")

        if not aud:
            raise ValueError("aud not found")

        logger.debug(f"aud: {aud}")

        wallet_client_id = self.session.get("wallet_client_id")

        logger.info(f"wallet_client_id: {wallet_client_id}")

        if not wallet_client_id:
            raise ValueError("Exception: wallet_client_id not found")

        if isinstance(aud, list) and wallet_client_id not in aud:
            raise ValueError(f"Exception: expected {wallet_client_id} in {aud}")

        if isinstance(aud, str) and aud != wallet_client_id:
            raise ValueError(f"Exception: expected {wallet_client_id} found {aud}")

        state = payload.get("state")

        if not state:
            raise ValueError("Exception: state not found")

        rp_state = self.session.get("rp_state")

        logger.info(f"state: {state}, rp_state: {rp_state}")

        if state != rp_state:
            raise ValueError(f"Exception: {rp_state} != {state}")


    def __check_auth_response_errors(self, payload: dict, redirect_uri: str) -> None:
        logger.debug(
            f"Entering method: __check_auth_response_errors. Params: [payload: {payload}, redirect_uri: {redirect_uri}]"
        )

        error = payload.get("error")
        if error:
            raise ValueError(f"Exception {redirect_uri}: {error}")


    def _find_credential_by_dcql_item(self, item: dict) -> dict | None:
        """Find a held credential by DCQL meta.vct_values or meta.doctype_value."""
        logger.debug(f"Entering method: _find_credential_by_dcql_item. Params [item: {item}]")
        if not item.get("format"):
            logger.info("❌ Il DCQL non presenta il claim 'format'")
            return None

        meta = item.get("meta")
        if not isinstance(meta, dict):
            logger.info("❌ Il DCQL non presenta il claim 'meta'")
            return None

        if item.get("format") == "mso_mdoc":
            doctype = meta.get("doctype_value")
            if not isinstance(doctype, str) or not doctype:
                logger.info("❌ Il DCQL non presenta il claim 'meta.doctype_value'")
                return None
            result = app_state.credential_store.find_by_vct(doctype)
            if not result:
                logger.info(
                    "❌ Il doctype '%s' non ha individuato alcuna credenziale nel wallet",
                    sanitize_for_logging(doctype),
                )
            return result

        vct_values = meta.get("vct_values")
        if not isinstance(vct_values, list) or not vct_values:
            logger.info("❌ Il DCQL non presenta il claim 'meta.vct_values'")
            return None
        for vct in vct_values:
            result = app_state.credential_store.find_by_vct(vct)
            if result:
                return result
        logger.info("❌ Nessun vct del DCQL ha individuato una credenziale nel wallet")
        return None
