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
import re
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
    PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT,
    WALLET_ATTESTATION_NAME,
    WALLET_UNIT_ATTESTATION_NAME,
)
from app.models.config.app_config import AppSettings
from app.service.discovery import FederationDiscovery
from app.service.itwallet_helpers import (
    apply_credential_issuer_overrides,
    apply_replace_values,
    credential_configuration_doctype,
    credential_configuration_format,
    credential_configuration_namespaces,
    credential_configuration_scope,
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
    generate_nonce,
    generate_pem_keys,
    generate_pkce_pair,
    get_thumbprint_from_private_key,
    priv_ec_key_obj_to_jwk,
    pub_ec_key_obj_to_jwk,
    sanitize_for_logging,
)

logger = logging.getLogger(__name__)



class IssuanceFlow:
    """Credential issuance for the wallet demo."""

    def _find_pid_provider_and_process_issuers(self, entity_ids: list, cred_config_id: str, trust_root_url: str):
        """Process credential issuers from oid_fed_list, apply overrides, return PID provider EC."""
        pid_provider_ec = None
        for entity_id in entity_ids:
            # codeql[py/log-injection]
            logger.info("➡️  Entity ID: %s", sanitize_for_logging(entity_id))
            ec_payload = self._entity_configuration_management(
                entity_id, [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_ISSUER], trust_root_url
            )
            app_state.ec_store.add(entity_id, ec_payload)
            supported = (
                ec_payload.get("metadata", {})
                .get(METADATA_TYPE_CREDENTIAL_ISSUER, {})
                .get("credential_configurations_supported")
            )
            if cred_config_id in supported:
                pid_provider_ec = ec_payload
                apply_replace_values(entity_id, "initialize_flow")
                apply_credential_issuer_overrides(entity_id, "initialize_flow")
            else:
                apply_replace_values(entity_id, "credential_flow")
                apply_credential_issuer_overrides(entity_id, "credential_flow")
        return pid_provider_ec


    def _get_pid_provider_url(self, pid_provider_ec, cred_config_id: str) -> str:
        """Extract iss from pid provider EC. Raises ValueError if EC or iss missing."""
        if not pid_provider_ec:
            raise ValueError(f"Non trovata alcuna entità che rilascia credenziali di tipo {cred_config_id}")
        url = extract_claim(pid_provider_ec, "iss")
        if not url:
            raise ValueError(f"EC per {cred_config_id} non presenta claim 'iss'")
        return url

    def _remember_issuance(
        self, state: str, code_verifier: str, issuer_url: str, credential_configuration_id: str | None
    ) -> None:
        remembered = self.session.get("issuance_requests")
        if not isinstance(remembered, dict):
            remembered = {}
        else:
            remembered = dict(remembered)
        remembered[state] = {
            "code_verifier": code_verifier,
            "issuer_url": issuer_url,
            "credential_configuration_id": credential_configuration_id,
        }
        unanswered = [
            key
            for key, value in remembered.items()
            if key != state and not (isinstance(value, dict) and value.get("authorization_response"))
        ]
        while len(remembered) > 8 and unanswered:
            remembered.pop(unanswered.pop(0), None)
        self.session["issuance_requests"] = remembered

    def _issuance_context(self, issuance_state: str | None) -> dict | None:
        remembered = self.session.get("issuance_requests")
        state = issuance_state or self.session.get("oauth_state")
        if not isinstance(remembered, dict) or not isinstance(state, str):
            return None
        entry = remembered.get(state)
        if not isinstance(entry, dict) or not entry.get("code_verifier"):
            return None
        if not isinstance(entry.get("authorization_response"), dict):
            return None
        return {
            "state": state,
            "code_verifier": entry["code_verifier"],
            "credential_configuration_id": entry.get("credential_configuration_id"),
            "issuer_url": entry.get("issuer_url"),
            "authorization_response": entry["authorization_response"],
        }

    def _forget_issuance(self, state: str) -> None:
        remembered = self.session.get("issuance_requests")
        if not isinstance(remembered, dict) or state not in remembered:
            return
        remembered = dict(remembered)
        remembered.pop(state, None)
        self.session["issuance_requests"] = remembered


    def initialize_wallet(self, idp: str, country: str):
        """
        Metodo pubblico per inizializzare l'IT Wallet per il paese indicato
        In sessione vengono salvati:
             self.session["code_verifier"]
             self.session["pid_provider_url]
        """
        logger.info("➡️  Richiesta di Inizializzazione del wallet per il paese: %s", sanitize_for_logging(country))
        cred_config_id = extract_claim(current_app.config, "metadata.initialize_flow.credential_configuration_id")
        init_response_mode = extract_claim(current_app.config, "metadata.initialize_flow.response_mode")
        validate_response_mode(init_response_mode, [AUTH_RESPONSE_MODE_QUERY], "inizializzazione wallet")
        init_response_type = extract_claim(current_app.config, "metadata.initialize_flow.response_type")
        validate_response_type(init_response_type, [AUTH_RESPONSE_TYPE_CODE], "inizializzazione wallet")

        trust_root_url = self._get_trust_root_url(country)
        logger.info(
            "Trust root individuato per il paese %s: %s",
            sanitize_for_logging(country),
            sanitize_for_logging(trust_root_url),
        )
        self._ensure_trust_root_ec(trust_root_url)
        self._load_wallet_provider_ec(trust_root_url)

        credential_issuer_list = self.discovery.list_entities(
            trust_root_url,
            METADATA_TYPE_CREDENTIAL_ISSUER,
            f"No credential issuer was found within the url: {trust_root_url}",
        )
        app_state.ec_store.add("credential_issuer_list", credential_issuer_list)

        pid_provider_ec = self._find_pid_provider_and_process_issuers(
            credential_issuer_list, cred_config_id, trust_root_url
        )

        pid_provider_url = self._get_pid_provider_url(pid_provider_ec, cred_config_id)
        # pid_provider_url = pid_provider_ec.get("metadata", {}).get(METADATA_TYPE_AUTHORIZATION_SERVER, {}).get(
        #     "authorization_endpoint")

        logger.info(
            "Trovata entità %s che rilascia credenziali di tipo %s",
            sanitize_for_logging(pid_provider_url),
            sanitize_for_logging(cred_config_id),
        )

        # Salvo in sessione il pid_provider_url estratto dall'EC individuato
        self.session["pid_provider_url"] = pid_provider_url

        # retrieve wallet instance hardware keys
        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Fallita generazione coppia di chiavi pvt e pub del wallet")

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(
            "Calcolato client id del wallet come thumbprint della sua chiave pvt: %s",
            sanitize_for_logging(wallet_client_id),
        )

        logger.info("Generazione nuova Wallet Attestation PoP JWT per il wallet...")
        client_attestation_pop_jwt = generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key, audience=pid_provider_url
        )
        if not client_attestation_pop_jwt:
            raise ValueError("Fallita generazione Wallet Attestation PoP JWT")

        logger.info("Wallet Attestation PoP JWT generata.")

        provider_ec = self._wallet_provider_entity()
        pub_core_jwks = extract_claim(provider_ec, f"metadata.{METADATA_TYPE_WALLET_PROVIDER}.jwks.keys")
        wallet_attestation_jwt, _ = self._get_or_create_wallet_attestations(provider_ec.get("iss"), pub_core_jwks)

        # Generazione PKCE
        pkce = generate_pkce_pair()
        logger.info("🧪 PKCE Info")
        # codeql[py/log-injection]
        logger.info(" 🔐 code_verifier: %s", sanitize_for_logging(pkce.get("code_verifier", "")))
        # codeql[py/log-injection]
        logger.info(" 🧠 code_challenge: %s", sanitize_for_logging(pkce.get("code_challenge", "")))
        # codeql[py/log-injection]
        logger.info(" 🔧 method: %s", sanitize_for_logging(pkce.get("code_challenge_method", "")))

        # Salvataggio in sessione del PKCE code verifier e dello state di questa richiesta
        oauth_state = generate_nonce()
        self.session["oauth_state"] = oauth_state
        self.session["code_verifier"] = pkce["code_verifier"]
        self._remember_issuance(oauth_state, pkce["code_verifier"], pid_provider_url, cred_config_id)

        # Generazione Request Object JWT per richiedere il PID
        logger.info("Generazione Request Object JWT per il wallet...")
        authorization_details = [{"type": "openid_credential", "credential_configuration_id": cred_config_id}]

        initialize_flow_response_type = extract_claim(current_app.config, "metadata.initialize_flow.response_type")
        initialize_flow_redirect_uri = extract_claim(current_app.config, "metadata.initialize_flow.redirect_uri")

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        request_object_jwt = generate_par_request_object_jwt(
            issuer_private_key=wallet_private_key,
            audience=pid_provider_url,
            state=oauth_state,
            code_challenge=pkce["code_challenge"],
            code_challenge_method=pkce["code_challenge_method"],
            response_type=initialize_flow_response_type,
            redirect_uri=initialize_flow_redirect_uri,
            scope=credential_configuration_scope(pid_provider_ec, cred_config_id),
            authorization_details=authorization_details,
        )
        if not request_object_jwt:
            raise ValueError("Fallita generazione Request Object JWT")

        logger.info("📄 Request Object JWT generato.")

        # recupero EC del pid provider dalla memoria
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.pushed_authorization_request_endpoint"
        pid_provider_as_par_url = extract_claim(pid_provider_ec, query_filter)

        # codeql[py/log-injection]
        logger.info("🚀 Invio PAR request al PAR endpoint %s", sanitize_for_logging(pid_provider_as_par_url))

        # Effettua una par request
        as_par_response = request_as_par(
            url=pid_provider_as_par_url,
            wallet_attestation_jwt=wallet_attestation_jwt,
            wallet_attestation_dpop_jwt=client_attestation_pop_jwt,
            request_object_jwt=request_object_jwt,
            client_id=wallet_client_id,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info("✅ Ricevuta risposta dal PAR endpoint %s", sanitize_for_logging(pid_provider_as_par_url))

        logger.info("%s", sanitize_for_logging(as_par_response))

        request_uri = as_par_response.get("request_uri")
        if not request_uri:
            raise ValueError("PAR Response non contiene un claim 'request_uri'")

        pid_provider_authorization_url = self._get_pid_provider_authorization_url(pid_provider_ec, trust_root_url)

        # query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.authorization_endpoint"
        # pid_provider_authorization_url = extract_claim(pid_provider_ec, query_filter)
        params = {
            "client_id": wallet_client_id,
            "request_uri": request_uri,
        }

        self._maybe_add_initialize_idphint(params, idp)

        authorization_url = f"{pid_provider_authorization_url}?{urlencode(params)}"

        logger.info(
            f"🌐 Apro il browser per inviare un'AUTHORIZE request all'AUTHORIZE endpoint del PID Provider: {authorization_url}"
        )

        self._print_session_data()

        return {"success": True, "data": {"redirect_url": authorization_url}}


    def _get_pid_provider_authorization_url(self, pid_provider_ec: dict, trust_root_url: str) -> str:
        oauth_authorization_server_url = extract_claim(current_app.config, "wallet_instance.oauth_authorization_server")
        if oauth_authorization_server_url:
            query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.authorization_endpoint"
            return extract_claim(pid_provider_ec, query_filter)
        oauth_authorization_server = self._authorization_server_configuration(
            trust_root_url, oauth_authorization_server_url
        )
        app_state.ec_store.add(oauth_authorization_server_url, oauth_authorization_server)
        return oauth_authorization_server_url


    def _maybe_add_initialize_idphint(self, params: dict, idp: str) -> None:
        if self.external_discovery:
            return
        initialize_flow_idphint = extract_claim(current_app.config, f"metadata.initialize_flow.idphints.{idp}")
        params["idphint"] = initialize_flow_idphint


    def complete_initialize_wallet(self):
        """
        Metodo pubblico per completare l'Inizializzazione dell'IT Wallet.
        """
        logger.info("Entering method: complete_initialize_wallet. Params []")

        # Recupera la tipologia di credenziale da richiedere per l'inizializazzione del wallet dalla configurazione
        CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING = extract_claim(
            current_app.config, "metadata.initialize_flow.credential_configuration_id"
        )

        country = app_state.selected_country

        query_trust_root = f"ms_trust_configuration.{country}.trust_root"

        trust_root_url = extract_claim(current_app.config, query_trust_root)

        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        context = self._issuance_context(None)
        if context:
            pkce_code_verifier = context["code_verifier"]
            oauth_state = context["state"]
            authorization_response = context["authorization_response"]
            pid_provider_url = context["issuer_url"]
        else:
            pkce_code_verifier = self.session.get("code_verifier")
            oauth_state = self.session.get("oauth_state")
            authorization_response = self.session.get("query_params")
            pid_provider_url = self.session.get("pid_provider_url")
        if not pkce_code_verifier or not oauth_state:
            raise ValueError("Non trovato il PKCE code verifier nella sessione")
        if not authorization_response:
            raise ValueError("Non trovata l'Authorization Response nella sessione")
        if not pid_provider_url:
            raise ValueError("Non trovato l'URL del PID provider nella sessione")

        # recupero EC del PID provider dalla memoria usando come chiave di ricerca il pid provider url
        pid_provider_ec = app_state.ec_store.get(pid_provider_url)
        if not pid_provider_ec:
            raise ValueError(f"Non trovato in memoria l'Entity Configuration dell'entità {pid_provider_url}")

        # recupero della URL dell'Authorization Server dall'EC
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.issuer"
        authorization_server_url = extract_claim(pid_provider_ec, query_filter)

        # recupero del token endpoint dell'Authorization Server dall'EC
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.token_endpoint"
        authorization_server_token_url = extract_claim(pid_provider_ec, query_filter)

        # recupero del jwks dell'Authorization Server dall'EC
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.jwks"
        authorization_server_jwks = extract_claim(pid_provider_ec, query_filter)

        # recupero della URL del Credential Issuer dall'EC
        # query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_issuer"
        # credential_issuer_url = extract_claim(pid_provider_ec, query_filter)

        # recupero del nonce endpoint del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.nonce_endpoint"
        credential_issuer_nonce_url = extract_claim(pid_provider_ec, query_filter)

        # recupero del credential endpoint del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_endpoint"
        credential_issuer_credential_url = extract_claim(pid_provider_ec, query_filter)

        # recupero del jwks del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks"
        credential_issuer_jwks = extract_claim(pid_provider_ec, query_filter)

        # recupero redirect_uri dalla configurazione dell'app
        redirect_uri = extract_claim(current_app.config, "metadata.initialize_flow.redirect_uri")

        # gestisco l'Authorization Response
        authorization_response_code, _, _ = self._authorization_response_management(
            authorization_response=authorization_response, state_expected=oauth_state, iss_expected=pid_provider_url
        )

        # gestione rilascio dell'access token
        dpop_bound_access_token, credential_identifiers = self._token_issuing_management(
            authorization_server_url=authorization_server_url,
            authorization_server_jwks=authorization_server_jwks,
            authorization_server_token_url=authorization_server_token_url,
            pkce_code_verifier=pkce_code_verifier,
            authorization_response_code=authorization_response_code,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING,
            redirect_uri=redirect_uri,
        )

        # gestione rilascio della credenziale
        credential_id = self._credential_issuing_management_v1_3(
            credential_issuer_url=pid_provider_url,
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token,
            entity_configuration=pid_provider_ec,
        )

        self._forget_issuance(oauth_state)
        if self.session.get("oauth_state") == oauth_state:
            self.session.pop("query_params", None)

        # Stampo i dati in sessione
        self._print_session_data()

        return {"success": True, "data": {"credential_id": credential_id}}


    def delete_credential_wallet(self, credential_id: str):
        """
        Metodo pubblico per rimuovere una credenziale dal proprio wallet.
        """
        # codeql[py/log-injection]
        logger.info("➡️  Richiesta di rimozione dal wallet della credenziale %s", sanitize_for_logging(credential_id))

        # Recupera la tipologia di credenziale riservata all'inizalizazzione del wallet
        CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING = extract_claim(
            current_app.config, "metadata.initialize_flow.credential_configuration_id"
        )

        if CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING in credential_id:
            # resetta il wallet rimuovendo tutte le credenziali
            app_state.credential_store.clear()
            app_state.selected_country = ""
            app_state.wallet_initialized = False
        else:
            # Controlla se la credenziale richiesta è presente nel wallet
            credentialIsPresent = app_state.credential_store.get(credential_id)

            if not credentialIsPresent:
                raise ValueError(f"La credenziale {credential_id} non è presente nel wallet")

            # codeql[py/log-injection]
            logger.info("ℹ️  La credenziale %s è presente nel wallet", sanitize_for_logging(credential_id))

            # Rimuove una credenziale se esiste ricercandola per key.
            app_state.credential_store.remove(credential_id)

            # codeql[py/log-injection]
            logger.info("✅ Rimmossa dal wallet la credenziale %s", sanitize_for_logging(credential_id))

        return {
            "success": True,
            "data": {
                "credential_id": credential_id,
                "wallet_initialized": app_state.wallet_initialized,
            },
        }


    def add_credential_wallet(self, credential_configuration_id: str):
        """
        Metodo pubblico per aggiungere credenziali al proprio wallet richieste all'EAA PROVIDER, incluso fetch dell'EC dell'EAA PROVIDER se non presente in memoria.
        In sessione vengono salvati:
             self.session["credential_configuration_id"]
             self.session["code_verifier"]
             self.session["rp_nonce"]
             self.session["rp_state"]
             self.session["rp_response_uri"]
        """

        logger.info(
            f"Entering method: add_credential_wallet. Params: [credential_configuration_id: {sanitize_for_logging(credential_configuration_id)}]"
        )

        logger.info(f"credential_store: {sanitize_for_logging(app_state.credential_store.keys_with_vct())}")

        if app_state.credential_store.find_by_configuration_id(credential_configuration_id):
            raise ValueError("Questa attestazione è già nel wallet.")

        validate_credential_and_presentation_flow()

        trust_root_url, eaa_provider_url, eaa_provider_ec = get_trust_root_and_eaa_provider_ec(
            credential_configuration_id
        )

        logger.info(
            f"Trust_root_url: {trust_root_url}, eaa_provider_url: {eaa_provider_url}, credential_configuration_id: {credential_configuration_id}"
        )

        self.session["credential_configuration_id"] = credential_configuration_id

        self.session["eaa_provider_url"] = eaa_provider_url

        # Lettura coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Mancano le chiavi di questo wallet. Reimposta la demo e riprova.")

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)

        logger.info(f"wallet_client_id: {wallet_client_id}", sanitize_for_logging(wallet_client_id))

        client_attestation_pop_jwt = generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key, audience=eaa_provider_url
        )
        if not client_attestation_pop_jwt:
            raise ValueError("Non riesco a preparare la prova di possesso richiesta dall'issuer.")
        logger.info(f"client_attestation_pop_jwt: {client_attestation_pop_jwt}.")

        provider_ec = self._wallet_provider_entity()
        pub_core_jwks = extract_claim(provider_ec, f"metadata.{METADATA_TYPE_WALLET_PROVIDER}.jwks.keys")
        if not pub_core_jwks:
            raise ValueError("Il wallet provider non pubblica le chiavi per firmare l'attestazione del wallet.")
        wallet_attestation_jwt, _ = self._get_or_create_wallet_attestations(provider_ec["iss"], pub_core_jwks)

        # Generazione PKCE
        pkce = generate_pkce_pair()
        logger.info(" code_verifier: %s", pkce.get("code_verifier", ""))

        logger.info("code_challenge: %s", pkce.get("code_challenge", ""))

        logger.info("method: %s", pkce.get("code_challenge_method", ""))

        # Salvataggio in sessione del PKCE code verifier e dello state di questa richiesta
        oauth_state = generate_nonce()
        self.session["oauth_state"] = oauth_state
        self.session["code_verifier"] = pkce["code_verifier"]
        self._remember_issuance(oauth_state, pkce["code_verifier"], eaa_provider_url, credential_configuration_id)

        logger.info("Generate Request Object JWT ")
        authorization_details = [
            {"type": "openid_credential", "credential_configuration_id": credential_configuration_id}
        ]

        credential_flow_response_type = extract_claim(current_app.config, "metadata.credential_flow.response_type")

        # DEPRECATED
        # credential_flow_response_mode = extract_claim(current_app.config, "metadata.credential_flow.response_mode")

        credential_flow_redirect_uri = extract_claim(current_app.config, "metadata.credential_flow.redirect_uri")

        session_id = require_session_key(
            self.session, "session_id", "La sessione della demo non è più valida. Esci e accedi di nuovo."
        )

        logger.info(f"session_id: {session_id}")

        request_object_jwt = generate_par_request_object_jwt(
            issuer_private_key=wallet_private_key,
            audience=eaa_provider_url,
            state=oauth_state,
            code_challenge=pkce["code_challenge"],
            code_challenge_method=pkce["code_challenge_method"],
            response_type=credential_flow_response_type,
            redirect_uri=credential_flow_redirect_uri,
            scope=credential_configuration_scope(eaa_provider_ec, credential_configuration_id),
            authorization_details=authorization_details,
        )
        if not request_object_jwt:
            raise ValueError("Non riesco a preparare la richiesta di autorizzazione verso l'issuer.")

        eaa_provider_as_par_url = self._get_eaa_par_url(eaa_provider_ec)
        as_par_response = request_as_par(
            url=eaa_provider_as_par_url,
            wallet_attestation_jwt=wallet_attestation_jwt,
            wallet_attestation_dpop_jwt=client_attestation_pop_jwt,
            request_object_jwt=request_object_jwt,
            client_id=wallet_client_id,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info(f"Par response: {as_par_response}")

        request_uri = self._require_request_uri(
            as_par_response, "L'issuer non ha restituito l'indirizzo della richiesta di autorizzazione."
        )
        eaa_provider_authorization_url = self._get_eaa_authorization_url(eaa_provider_ec)
        params = {
            "client_id": wallet_client_id,
            "request_uri": request_uri,
        }
        authorization_url = f"{eaa_provider_authorization_url}?{urlencode(params)}"
        logger.info("Apro l'accesso dell'issuer: %s", sanitize_for_logging(authorization_url))
        return {"success": True, "data": {"redirect_url": authorization_url}}


    def complete_add_credential_from_browser(self, issuance_state: str | None = None):
        """Completa il rilascio dopo che il browser torna dall'issuer con il codice di autorizzazione."""
        logger.info("Entering method: complete_add_credential_from_browser")

        country = app_state.selected_country or ""
        trust_root_url = extract_claim(current_app.config, f"ms_trust_configuration.{country}.trust_root")
        if not trust_root_url:
            raise ValueError("Non è configurato il trust anchor della demo, quindi non posso completare il rilascio.")

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("La sessione della demo non è più valida. Esci e accedi di nuovo.")

        context = self._issuance_context(issuance_state)
        if issuance_state and not context:
            raise ValueError("Non trovo più la verifica della richiesta. Premi di nuovo Ottieni.")
        if context:
            credential_configuration_id = context["credential_configuration_id"]
            pkce_code_verifier = context["code_verifier"]
            oauth_state = context["state"]
            authorization_response = context["authorization_response"]
            eaa_provider_url = context["issuer_url"]
        else:
            credential_configuration_id = self.session.get("credential_configuration_id")
            pkce_code_verifier = self.session.get("code_verifier")
            oauth_state = self.session.get("oauth_state")
            authorization_response = self.session.get("query_params")
            eaa_provider_url = self.session.get("eaa_provider_url")
        if not credential_configuration_id:
            raise ValueError("Non trovo più l'attestazione richiesta. Premi di nuovo Ottieni.")
        if not pkce_code_verifier or not oauth_state:
            raise ValueError("Non trovo più la verifica della richiesta. Premi di nuovo Ottieni.")
        if not authorization_response:
            raise ValueError("L'issuer non ha ancora restituito l'autorizzazione. Completa l'accesso e riprova.")
        if not eaa_provider_url:
            raise ValueError("Non trovo più l'issuer di questa richiesta. Premi di nuovo Ottieni.")

        eaa_provider_ec = app_state.ec_store.get(eaa_provider_url)
        if not eaa_provider_ec:
            raise ValueError("Non ho più la configurazione dell'issuer. Ricarica la pagina e premi di nuovo Ottieni.")

        authorization_server_url = extract_claim(
            eaa_provider_ec, f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.issuer"
        )
        authorization_server_token_url = extract_claim(
            eaa_provider_ec, f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.token_endpoint"
        )
        authorization_server_jwks = extract_claim(
            eaa_provider_ec, f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.jwks"
        )
        credential_issuer_nonce_url = extract_claim(
            eaa_provider_ec, f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.nonce_endpoint"
        )
        credential_issuer_credential_url = extract_claim(
            eaa_provider_ec, f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_endpoint"
        )
        credential_issuer_jwks = extract_claim(eaa_provider_ec, f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks")
        redirect_uri = extract_claim(current_app.config, "metadata.credential_flow.redirect_uri")

        authorization_response_code, _, _ = self._authorization_response_management(
            authorization_response=authorization_response,
            state_expected=oauth_state,
            iss_expected=eaa_provider_url,
        )
        dpop_bound_access_token, credential_identifiers = self._token_issuing_management(
            authorization_server_url=authorization_server_url,
            authorization_server_jwks=authorization_server_jwks,
            authorization_server_token_url=authorization_server_token_url,
            pkce_code_verifier=pkce_code_verifier,
            authorization_response_code=authorization_response_code,
            credential_configuration_id=credential_configuration_id,
            redirect_uri=redirect_uri,
        )
        credential_id = self._credential_issuing_management_v1_3(
            credential_issuer_url=eaa_provider_url,
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=credential_configuration_id,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token,
            entity_configuration=eaa_provider_ec,
        )
        self._forget_issuance(oauth_state)
        if self.session.get("oauth_state") == oauth_state:
            self.session.pop("query_params", None)
        return {"success": True, "data": {"credential_id": credential_id}}


    def _get_eaa_par_url(self, eaa_provider_ec: dict) -> str:
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.pushed_authorization_request_endpoint"
        logger.info(f"query_filter: {query_filter}")
        eaa_provider_as_par_url = extract_claim(eaa_provider_ec, query_filter)
        logger.info(f"sanitize_for_logging(eaa_provider_as_par_url): {sanitize_for_logging(eaa_provider_as_par_url)}")
        return eaa_provider_as_par_url


    def _get_eaa_authorization_url(self, eaa_provider_ec: dict) -> str:
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.authorization_endpoint"
        return extract_claim(eaa_provider_ec, query_filter)


    def complete_add_credential_wallet(self, credentials_presenting: list[dict]):
        """
        Metodo pubblico per completare l'aggiunta della credenziale
        """
        logger.info(
            f"Entering method: complete_add_credential_wallet. Params [credentials_presenting: {credentials_presenting}]"
        )

        country = app_state.selected_country

        logger.info(f"country: {country}")

        wallet_provider_url = extract_claim(current_app.config, "metadata.wallet_provider.id")

        logger.info(f"wallet_provider_url: {wallet_provider_url}")

        credential_flow_response_mode = extract_claim(current_app.config, "metadata.credential_flow.response_mode")

        logger.info(f"credential_flow_response_mode: {credential_flow_response_mode}")

        query_trust_root = f"ms_trust_configuration.{country}.trust_root"

        logger.info(f"query_trust_root: {query_trust_root}")

        trust_root_url = extract_claim(current_app.config, query_trust_root)

        logger.info(f"trust_root_url: {trust_root_url}")

        if not trust_root_url:
            raise ValueError(f"Trust root empty for {country}")

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Session empty")

        credential_configuration_id = self.session.get("credential_configuration_id")

        if not credential_configuration_id:
            raise ValueError("Credential_configuration_id not found in memory")

        pkce_code_verifier = self.session.get("code_verifier")
        if not pkce_code_verifier:
            raise ValueError("PKCE code verifier not fount in session")

        rp_state = self.session.get("rp_state")
        rp_nonce = self.session.get("rp_nonce")
        rp_response_uri = self.session.get("rp_response_uri")

        if not rp_state:
            raise ValueError("rp_state not found in memory")

        if not rp_nonce:
            raise ValueError("rp_nonce not found in memory")

        if not rp_response_uri:
            raise ValueError("rp_response_uri not found in memory")

        logger.info(f"rp_state: {rp_state}, rp_nonce: {rp_nonce}, rp_response_uri: {rp_response_uri}")

        eaa_provider_url = self.session.get("eaa_provider_url")
        if not eaa_provider_url:
            raise ValueError("URL EAA provider not found in memory")

        logger.info(f"eaa_provider_url: {eaa_provider_url}")

        eaa_provider_ec = app_state.ec_store.get(eaa_provider_url)
        if not eaa_provider_ec:
            raise ValueError(f"Entity-configuration not found in memory for {eaa_provider_url}")

        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.issuer"
        authorization_server_url = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"authorization_server_url: {authorization_server_url}")

        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.token_endpoint"
        authorization_server_token_url = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"authorization_server_token_url: {authorization_server_token_url}")

        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.jwks"
        authorization_server_jwks = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"authorization_server_jwks: {authorization_server_jwks}")

        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.nonce_endpoint"
        credential_issuer_nonce_url = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"credential_issuer_nonce_url: {credential_issuer_nonce_url}")

        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_endpoint"
        credential_issuer_credential_url = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"credential_issuer_credential_url: {credential_issuer_credential_url}")

        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks"
        credential_issuer_jwks = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"credential_issuer_jwks: {credential_issuer_jwks}")

        redirect_uri = extract_claim(current_app.config, "metadata.credential_flow.redirect_uri")

        logger.info(f"redirect_uri: {redirect_uri}")

        # @TODO Chiedere a di clemente
        authorization_response = self._presentation_management_v133(
            enc=False,
            credentials_presenting=credentials_presenting,
            rp_state=rp_state,
            rp_nonce=rp_nonce,
            rp_response_uri=rp_response_uri,
            rp_jwks=authorization_server_jwks,
            response_mode=credential_flow_response_mode,
        )

        # @TODO che serve la fase di authorization?
        authorization_response_code, _, _ = self._authorization_response_management(
            authorization_response=authorization_response,
            state_expected=session_id,
            iss_expected=authorization_server_url,
        )

        # gestione rilascio dell'access token
        dpop_bound_access_token, credential_identifiers = self._token_issuing_management(
            authorization_server_url=authorization_server_url,
            authorization_server_jwks=authorization_server_jwks,
            authorization_server_token_url=authorization_server_token_url,
            pkce_code_verifier=pkce_code_verifier,
            authorization_response_code=authorization_response_code,
            credential_configuration_id=credential_configuration_id,
            redirect_uri=redirect_uri,
        )
        credential_id = self._credential_issuing_management_v1_3(
            credential_issuer_url=credential_issuer_credential_url,
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=credential_configuration_id,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token,
            entity_configuration=eaa_provider_ec,
        )

        self._print_session_data()

        return {"success": True, "data": {"credential_id": credential_id}}


    def _token_issuing_management(
        self,
        authorization_server_url: str,
        authorization_server_jwks: dict,
        authorization_server_token_url: str,
        pkce_code_verifier: str,
        authorization_response_code: str,
        credential_configuration_id: str,
        redirect_uri: str,
    ) -> Tuple[str, list]:
        """Exchange auth code for DPoP access token, validate, return token and credential_identifiers."""
        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)

        logger.info(
            f"Entering method: _token_issuing_management. Params [authorization_server_url: {authorization_server_url}, redirect_uri: {redirect_uri}]"
        )

        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Mancano le chiavi di questo wallet. Reimposta la demo e riprova.")

        wallet_key_thumbprint = get_thumbprint_from_private_key(wallet_private_key)

        client_attestation_pop_jwt = generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key, audience=authorization_server_url
        )
        logger.info(f"client_attestation_pop_jwt: {client_attestation_pop_jwt}")

        provider_ec = self._wallet_provider_entity()
        pub_core_jwks = extract_claim(provider_ec, f"metadata.{METADATA_TYPE_WALLET_PROVIDER}.jwks.keys")
        wallet_attestation_jwt, _ = self._get_or_create_wallet_attestations(provider_ec["iss"], pub_core_jwks)

        dpop_token_request = generate_dpop_jwt(
            issuer_private_key=wallet_private_key, http_method="POST", http_url=authorization_server_token_url
        )
        logger.info(f"dpop_token_request: {dpop_token_request}.")
        token_response = request_token(
            url=authorization_server_token_url,
            wallet_attestation_jwt=wallet_attestation_jwt,
            wallet_attestation_dpop_jwt=client_attestation_pop_jwt,
            dpop_proof_jwt=dpop_token_request,
            grant_type="authorization_code",
            code=authorization_response_code,
            code_verifier=pkce_code_verifier,
            redirect_uri=redirect_uri,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info(f"token_response: {token_response}")

        require_jwt_claim(token_response, "token_type", expected="DPoP", msg="token_type must be DPoP")

        dpop_bound_access_token = require_jwt_claim(token_response, "access_token", msg="access_token not found")

        authorization_details_claim = require_jwt_claim(
            token_response, "authorization_details", msg="authorization_details not found"
        )

        require_jwt_claim(token_response, "expires_in", msg="expires_in not found")

        try:
            dpop_bound_access_token_claims = decode_and_verify_jwt(dpop_bound_access_token, authorization_server_jwks)
            expected_jkt = base64.urlsafe_b64encode(wallet_key_thumbprint.encode()).decode("utf-8").rstrip("=")
            validate_access_token(
                dpop_bound_access_token_claims,
                authorization_server_url,
                wallet_key_thumbprint,
                expected_jkt,
            )
            logger.info(
                f"The access token is valid: {json.dumps(dpop_bound_access_token_claims, indent=2, ensure_ascii=False)} "
            )
        except ValueError as ve:
            raise ValueError(f"The access token is invalid: {ve}")

        all_identifiers = [
            identifier
            for detail in authorization_details_claim
            for identifier in detail.get("credential_identifiers", [])
        ]

        logger.info(f"all_identifiers: {all_identifiers}")

        matching_identifiers = next(
            (
                detail.get("credential_identifiers", [])
                for detail in authorization_details_claim
                if detail.get("credential_configuration_id") == credential_configuration_id
            ),
            [],
        )

        if not matching_identifiers:
            logger.error(f"credential_configuration_id not found: {credential_configuration_id}")
            raise ValueError(f"credential_configuration_id not found: {credential_configuration_id}")

        logger.debug(f"{credential_configuration_id} len: {len(matching_identifiers)}")

        return dpop_bound_access_token, matching_identifiers


    def _get_or_create_wallet_attestations(self, provider_url: str, provider_jwks: list[dict]) -> tuple[str, str]:
        """Get wallet attestation JWT from store, or create if missing/expired. Returns JWT string."""
        logger.debug(f"Entering method: _get_or_create_wallet_attestation. Params [provider_url: {provider_url}]")

        wa_id = JWT_PREFIX + "_" + WALLET_ATTESTATION_NAME
        w_unit_att_is = JWT_PREFIX + "_" + WALLET_UNIT_ATTESTATION_NAME

        jwt_app_attestation = app_state.ec_store.get(wa_id) or ""
        jwt_unit_attestation = app_state.ec_store.get(w_unit_att_is) or ""

        def validate_jws(value):
            try:
                _helper = JWSHelper(provider_jwks)
                return _helper.verify(value)
            except LifetimeException:
                logger.error("App attestation jwt expired")
                return None
            except Exception as e:
                logger.error("Validation of the app wallet attestation jwt failed: {}".format(e))
                return None

        if not validate_jws(jwt_app_attestation) or not validate_jws(jwt_unit_attestation):
            attestations = self._retrieve_attestations_jws(provider_url)
            jwt_app_attestation = attestations.get("wallet_app_attestation", "")
            jwt_unit_attestation = attestations.get("wallet_unit_attestation", "")
            if jwt_app_attestation and jwt_unit_attestation:
                app_state.ec_store.add(wa_id, jwt_app_attestation)
                app_state.ec_store.add(w_unit_att_is, jwt_unit_attestation)

        return jwt_app_attestation, jwt_unit_attestation


    def _decode_and_validate_single_credential(
        self,
        cred: dict,
        index: int,
        credential_configuration_id: str,
        credential_issuer_jwks: dict,
        entity_configuration: dict,
    ) -> tuple | None:
        """Decode and validate a single credential (SD-JWT or mdoc). Returns (credential, vct, claims) or None."""
        credential = cred.get("credential")
        if not credential:
            logger.info("Content of credential #%d is missing or invalid.", index)
            return None

        credential_format = credential_configuration_format(entity_configuration, credential_configuration_id).lower()

        if credential_format in {"dc+sd-jwt", "vc+sd-jwt"}:
            claims = decode_and_verify_sd_jwt(sd_jwt_compact=credential, jwks=credential_issuer_jwks)
            logger.info("Valid credential #%d SD-JWT)", index)
            return credential, claims.get("vct", ""), claims
        if credential_format == "mso_mdoc":
            expected_doc = credential_configuration_doctype(entity_configuration, credential_configuration_id)
            result_json = decode_and_verify_issuer_signed(
                issuer_signed_base64_url=credential,
                expected_namespaces=credential_configuration_namespaces(
                    entity_configuration, credential_configuration_id
                ),
                expected_version="1.0",
                expected_doc_type=expected_doc,
            )
            logger.info("Valid credential #%d (mdoc)", index)
            return credential, expected_doc, result_json
        return None


    def _fetch_credentials_for_id(
        self,
        credential_id: str,
        nonce_url: str,
        credential_url: str,
        wallet_private_key,
        dpop_bound_access_token: str,
        key_attestation: str,
        issuer_url: str,
    ) -> list:
        """Fetch credentials for given credential_id via nonce+proof+request. Returns list of credential dicts."""

        nonce_resp = request_nonce(url=nonce_url, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains)

        proof_jwt = generate_proof_jwt(
            issuer_private_key=wallet_private_key,
            audience=issuer_url,
            nonce=nonce_resp,
            key_attestation=key_attestation,
        )

        dpop_req = generate_dpop_jwt(
            issuer_private_key=wallet_private_key,
            http_method="POST",
            http_url=credential_url,
            access_token=dpop_bound_access_token,
        )

        cred_resp = request_credential(
            url=credential_url,
            credential_id=credential_id,
            proof_jwt=proof_jwt,
            access_token=dpop_bound_access_token,
            dpop_proof_jwt=dpop_req,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        credentials = cred_resp.get("credentials", [])

        if not credentials:
            raise ValueError("L'issuer non ha restituito l'attestazione.")
        return credentials


    def _credential_issuing_management_v1_3(
        self,
        credential_issuer_url: str,
        credential_issuer_nonce_url: str,
        credential_issuer_credential_url: str,
        credential_issuer_jwks: dict,
        credential_configuration_id: str,
        credential_identifiers: list,
        dpop_bound_access_token: str,
        entity_configuration: dict,
    ) -> str:
        """Request credentials via nonce+proof, decode/validate, store in credential_store. Returns credential_id."""
        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)

        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Generation Key Exception: wallet_private_key or wallet_public_key empty")

        provider_ec = self._wallet_provider_entity()
        pub_core_jwks = extract_claim(provider_ec, f"metadata.{METADATA_TYPE_WALLET_PROVIDER}.jwks.keys")
        _, key_attestation = self._get_or_create_wallet_attestations(provider_ec["iss"], pub_core_jwks)

        issued = self._collect_last_valid_issued_credential(
            credential_identifiers,
            credential_issuer_nonce_url,
            credential_issuer_credential_url,
            wallet_private_key,
            dpop_bound_access_token,
            key_attestation,
            credential_configuration_id,
            credential_issuer_jwks,
            credential_issuer_url,
            entity_configuration,
        )
        if not issued:
            logger.info("❌ Nessuna credenziale valida ricevuta")
            raise ValueError("Nessuna credenziale valida ricevuta")

        credential_id, last_valid_credential, last_valid_credential_vct, last_valid_credential_claims = issued

        app_state.wallet_initialized = True

        app_state.credential_store.add_credential(
            credential_issuer_url,
            credential_id,
            last_valid_credential,
            last_valid_credential_vct,
            last_valid_credential_claims,
            configuration_id=credential_configuration_id,
        )

        # app_state.credential_store.add(
        #     credential_id, last_valid_credential, last_valid_credential_vct, last_valid_credential_claims
        # )

        return credential_id


    def _collect_last_valid_issued_credential(
        self,
        credential_identifiers: list,
        credential_issuer_nonce_url: str,
        credential_issuer_credential_url: str,
        wallet_private_key,
        dpop_bound_access_token: str,
        key_attestation,
        credential_configuration_id: str,
        credential_issuer_jwks: dict,
        credential_issuer_url,
        entity_configuration: dict,
    ):
        last_valid = None
        for credential_id in credential_identifiers:
            credentials = self._fetch_credentials_for_id(
                credential_id,
                credential_issuer_nonce_url,
                credential_issuer_credential_url,
                wallet_private_key,
                dpop_bound_access_token,
                key_attestation,
                credential_issuer_url,
            )
            for index, cred in enumerate(credentials, start=1):
                result = self._decode_and_validate_single_credential(
                    cred, index, credential_configuration_id, credential_issuer_jwks, entity_configuration
                )
                if result:
                    last_valid = (credential_id, *result)
        return last_valid


    def _retrieve_attestations_jws(self, provider_url: str) -> dict[str, str]:
        """This method retrieve a wallet app attestation and a wallet unit attestation from wallet provider endpoint.
        Return: a dict with attestations as signed JWT
        """
        if not self._hw_key_tag or not self._hw_private_jwk:
            raise ValueError("Unable to retrieve instance wallet keys, please initialize instance wallet again")

        provider_url = provider_url[:-1] + provider_url[-1].replace("/", "")
        http_headers = {"Accept": "application/json"}
        nonce_url = provider_url + "/nonce"
        nonce_response = http_request_with_retry("GET", url=nonce_url, headers=http_headers)
        nonce = _parse_json_response(nonce_response, nonce_url).get("nonce")
        hardware_signature = ""  # todo
        integrity_assertion = ""
        attested_key = ""

        req = WaJswRequestIssuer(
            provider_url,
            self._hw_private_jwk,
            self._hw_key_tag,
            nonce,
            hardware_signature,
            integrity_assertion,
            attested_key,
        )
        signed_jwt = req.generate_jws()
        req_att_body = dict(assertion=signed_jwt)

        att_url = provider_url + "/wallet-attestation"
        attestations_resp = http_request_with_retry("POST", url=att_url, headers=http_headers, json_body=req_att_body)
        attestations = _parse_json_response(attestations_resp, att_url).get("wallet_attestations") or []

        res = {}
        supported_attestations = ["wallet_app_attestation", "wallet_unit_attestation"]
        for att in attestations:
            for k, v in att.items():
                if k in supported_attestations:
                    res.update({k: v})
        return res
