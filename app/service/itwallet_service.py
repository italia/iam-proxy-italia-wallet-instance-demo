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

import hashlib
import json
import logging
import os
import re
from app.service import *
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from flask import current_app
from jwcrypto.common import base64url_decode
from pyeudiw.jwt.exceptions import LifetimeException
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.wallet_attestations.issuers.wa_request import WaJswRequestIssuer

from app.models.provider_config import ProviderConfig
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
from app.utils.http_utils import _parse_json_response, http_request_with_retry
from app.utils.itwalletUtils import (
    generate_dpop_jwt,
    generate_par_request_object_jwt,
    generate_proof_jwt,
    generate_request_object_jwt,
    generate_response_uri_request_jwe,
    generate_response_uri_request_jws,
    generate_status_assertion_request_object_jwt,
    generate_wallet_attestation_pop_jwt,
    get_status_description,
    request_as_par,
    request_authorize,
    request_credential,
    request_nonce,
    request_presentation_callback,
    request_request_uri,
    request_response_uri,
    request_status,
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
from settings import (
    AUTH_RESPONSE_MODE_FORM_POST_JWT,
    AUTH_RESPONSE_MODE_QUERY,
    AUTH_RESPONSE_TYPE_CODE,
    CONFIG_DIR,
    ISO_18013_5_NAME,
    ISO_18013_5_VERSION,
    JWT_PREFIX,
    METADATA_TYPE_AUTHORIZATION_SERVER,
    METADATA_TYPE_CREDENTIAL_ISSUER,
    METADATA_TYPE_CREDENTIAL_VERIFIER,
    METADATA_TYPE_FEDERATION_ENTITY,
    MSO_MDOC_PREFIX,
    PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT,
    PRESENTATION_RESPONSE_TYPE_VP_TOKEN,
    SD_JWT_PREFIX,
    WALLET_ATTESTATION_NAME, METADATA_TYPE_WALLET_SOLUTION,
)

logger = logging.getLogger(__name__)


class ItWalletService:
    """Service for IT Wallet credential issuance and presentation flows."""

    def __init__(self, session):
        """Initialize service with Flask session. Loads proxies from config."""
        self.session = session
        self.proxies, self.no_proxy_domains = get_proxies_from_config()
        self.provider_config = ProviderConfig(extract_claim(current_app.config, "wallet_provider"))
        self._hw_private_jwk = None
        self._hw_public_jwk = None
        self._hw_key_tag = None
        self.federation_service = FederationService(current_app.config, self.proxies, self.no_proxy_domains)
        self.provider_service = ProviderService(current_app.config, self.proxies, self.no_proxy_domains)
        self.issuer_service = IssuerService(current_app.config, self.proxies, self.no_proxy_domains)

    def getOnboardedRelyingParties(self):
        """Return list of onboarded Relying Parties (Credential Verifiers) from trust root."""
        logger.info("➡️  Richiesta elenco Relying Parties onboardati")

        # recupero selected_country dalla memoria
        country = app_state.selected_country

        # recupero trust_root_url dalla configurazione
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)

        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")

        # codeql[py/log-injection]
        logger.info(
            "ℹ️  Trust root individuato per il paese %s: %s",
            sanitize_for_logging(country),
            sanitize_for_logging(trust_root_url),
        )

        params = {"entity_type": METADATA_TYPE_CREDENTIAL_VERIFIER}
        list_query_string = f"?{urlencode(params)}"

        oid_fed_list_reponse = oid_fed_list(
            base_url=trust_root_url,
            query_string=list_query_string,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        return {"success": True, "data": oid_fed_list_reponse}

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

        trust_root_url = extract_claim(current_app.config, f"ms_trust_configuration.{country}.trust_root")
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        logger.info(
            "Trust root individuato per il paese %s: %s",
            sanitize_for_logging(country),
            sanitize_for_logging(trust_root_url),
        )

        if not app_state.ec_store.exists(trust_root_url):
            # DEPRECATED
            # trust_root_ec = self._entity_configuration_management(trust_root_url, [METADATA_TYPE_FEDERATION_ENTITY])
            trust_root_entity_configuration = self.federation_service.issuer_ec(trust_root_url)
            self.federation_service.validate_entity_configuration(payload= trust_root_entity_configuration, expected_url= trust_root_url, metadata_types= [METADATA_TYPE_FEDERATION_ENTITY])
            app_state.ec_store.add(trust_root_url, trust_root_entity_configuration)
            logger.info(f"trust_root_url: {trust_root_url}")

        #  DEPRECATED
        # if not (wallet_provider_url := self._retrieve_wallet_provider_ec(trust_root_url)):
        #     raise ValueError("Retrieving wallet_provider entity configuration failed")

        wallet_provider_entity_configuration = self.provider_service.wallet_provider_ec(self.provider_service.wallet_provider_list(trust_root_url),extract_claim(current_app.config, "wallet_provider.public_url"))
        self.provider_service.validate_entity_configuration(expected_url=extract_claim(current_app.config, "wallet_provider.public_url"), payload=wallet_provider_entity_configuration, hint= trust_root_url, metadata_types= [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_WALLET_SOLUTION])
        app_state.ec_store.add(self.provider_service.wallet_provider_url, wallet_provider_entity_configuration)

        credential_issuer_list = self.issuer_service.credential_issuer_list(trust_root_url)
        app_state.ec_store.add("credential_issuer_list", credential_issuer_list)

        # DEPRECATED
        # params = {"entity_type": METADATA_TYPE_CREDENTIAL_ISSUER}
        # oid_fed_list_reponse = oid_fed_list(
        #     base_url=trust_root_url,
        #     query_string=f"?{urlencode(params)}",
        #     proxies=self.proxies,
        #     no_proxy_domains=self.no_proxy_domains,
        # )
        # # codeql[py/log-injection]
        # logger.info("📄 oid_fed_list response: %s", sanitize_for_logging(oid_fed_list_reponse))


        # DEPRECATED
        # pid_provider_ec = self._find_pid_provider_and_process_issuers(
        #     oid_fed_list_reponse, cred_config_id, trust_root_url
        # )

        pid_provider_ec = self._find_pid_provider_and_process_issuers(
            credential_issuer_list, cred_config_id, trust_root_url
        )

        pid_provider_url = self._get_pid_provider_url(pid_provider_ec, cred_config_id)
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

        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        # codeql[py/log-injection]
        logger.debug(
            "Calcolato client id del wallet come thumbprint della sua chiave pvt: %s",
            sanitize_for_logging(wallet_client_id),
        )

        # Generazione Wallet Attestation PoP jwt
        logger.info("Generazione nuova Wallet Attestation PoP JWT per il wallet...")
        client_attestation_pop_jwt = generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key, audience=pid_provider_url
        )
        if not client_attestation_pop_jwt:
            raise ValueError("Fallita generazione Wallet Attestation PoP JWT")

        logger.info("Wallet Attestation PoP JWT generata.")

        if not (provider_ec := app_state.ec_store.get(self.provider_service.wallet_provider_url)): # find 1st wallet_provider
            raise ValueError("The provider wallet is not present in the wallet")
        pub_core_jwks = extract_claim(provider_ec, "metadata.wallet_provider.jwks.keys")
        wallet_attestation_jwt = self._get_or_create_app_attestation(self.provider_service.wallet_provider_url, pub_core_jwks)

        # Generazione PKCE
        pkce = generate_pkce_pair()
        logger.info("🧪 PKCE Info")
        # codeql[py/log-injection]
        logger.info(" 🔐 code_verifier: %s", sanitize_for_logging(pkce.get("code_verifier", "")))
        # codeql[py/log-injection]
        logger.info(" 🧠 code_challenge: %s", sanitize_for_logging(pkce.get("code_challenge", "")))
        # codeql[py/log-injection]
        logger.info(" 🔧 method: %s", sanitize_for_logging(pkce.get("code_challenge_method", "")))

        # Salvataggio in sessione del PKCE code verifier
        self.session["code_verifier"] = pkce["code_verifier"]

        # Generazione Request Object JWT per richiedere il PID
        logger.info("Generazione Request Object JWT per il wallet...")
        authorization_details = [{"type": "openid_credential", "credential_configuration_id": cred_config_id}]

        initialize_flow_response_type = extract_claim(current_app.config, "metadata.initialize_flow.response_type")
        initialize_flow_response_mode = extract_claim(current_app.config, "metadata.initialize_flow.response_mode")
        initialize_flow_redirect_uri = extract_claim(current_app.config, "metadata.initialize_flow.redirect_uri")

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        request_object_jwt = generate_request_object_jwt(
            issuer_private_key=wallet_private_key,
            audience=pid_provider_url,
            state=session_id,
            code_challenge=pkce["code_challenge"],
            code_challenge_method=pkce["code_challenge_method"],
            response_type=initialize_flow_response_type,
            response_mode=initialize_flow_response_mode,
            redirect_uri=initialize_flow_redirect_uri,
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

        # codeql[py/log-injection]
        logger.info("✅ Ricevuta risposta dal PAR endpoint %s", sanitize_for_logging(pid_provider_as_par_url))
        # codeql[py/log-injection]
        logger.info("%s", sanitize_for_logging(as_par_response))

        request_uri = as_par_response.get("request_uri")
        if not request_uri:
            raise ValueError("PAR Response non contiene un claim 'request_uri'")

        initialize_flow_idphint = extract_claim(current_app.config, f"metadata.initialize_flow.idphints.{idp}")
        # codeql[py/log-injection]
        logger.info(
            "ℹ️  Selezionato idp %s: %s",
            sanitize_for_logging(idp),
            sanitize_for_logging(initialize_flow_idphint),
        )

        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.authorization_endpoint"
        pid_provider_authorization_url = extract_claim(pid_provider_ec, query_filter)
        params = {
            "client_id": wallet_client_id,
            "request_uri": request_uri,
        }

        # Aggiungi 'idphint' solo se è valorizzato (non None e non stringa vuota)
        if initialize_flow_idphint:
            params["idphint"] = initialize_flow_idphint

        # Build authorization URL
        authorization_url = f"{pid_provider_authorization_url}?{urlencode(params)}"

        logger.info(
            f"🌐 Apro il browser per inviare un'AUTHORIZE request all'AUTHORIZE endpoint del PID Provider: {authorization_url}"
        )

        # Stampo i dati della sessione
        self._print_session_data()

        return {"success": True, "data": {"redirect_url": authorization_url}}

    def complete_initialize_wallet(self):
        """
        Metodo pubblico per completare l'Inizializzazione dell'IT Wallet.
        """
        logger.info("➡️  Richiesta di completamento dell'Inizializzazione del wallet")

        # Recupera la tipologia di credenziale da richiedere per l'inizializazzione del wallet dalla configurazione
        CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING = extract_claim(
            current_app.config, "metadata.initialize_flow.credential_configuration_id"
        )

        # recupero selected_country dalla memoria
        country = app_state.selected_country

        # recupero trust_root_url dalla configurazione
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)

        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        # recupero code_verifier dalla sessione
        pkce_code_verifier = self.session.get("code_verifier")
        if not pkce_code_verifier:
            raise ValueError("Non trovato il PKCE code verifier nella sessione")

        # recupero l'Authorization Response dalla sessione dove è stato memorizzato dalla callback del wallet
        authorization_response = self.session.get("query_params")
        if not authorization_response:
            raise ValueError("Non trovata l'Authorization Response nella sessione")

        # recupero pid provider url dalla sessione
        pid_provider_url = self.session.get("pid_provider_url")
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

        # recupero dello status assertion endpoint del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.status_assertion_endpoint"
        credential_issuer_status_assertion_url = extract_claim(pid_provider_ec, query_filter)

        # recupero del jwks del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks"
        credential_issuer_jwks = extract_claim(pid_provider_ec, query_filter)

        # recupero redirect_uri dalla configurazione dell'app
        redirect_uri = extract_claim(current_app.config, "metadata.initialize_flow.redirect_uri")

        # gestisco l'Authorization Response
        authorization_response_code, _, _ = self._authorization_response_management(
            authorization_response=authorization_response, state_expected=session_id, iss_expected=pid_provider_url
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
        credential_id = self._credential_issuing_management(
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_status_assertion_url=credential_issuer_status_assertion_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token,
        )

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

        if app_state.credential_store.find_by_prefix_with_key(credential_configuration_id):
            raise ValueError(f"The credential {credential_configuration_id} is already present in the wallet")

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
            raise ValueError("Private or Public key not present in wallet configuration")

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)

        logger.info(f"wallet_client_id: {wallet_client_id}", sanitize_for_logging(wallet_client_id))

        client_attestation_pop_jwt = generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key, audience=eaa_provider_url
        )
        if not client_attestation_pop_jwt:
            raise ValueError("Cant generate the Wallet Attestation PoP JWT")
        logger.info(f"client_attestation_pop_jwt: {client_attestation_pop_jwt}.")

        if not (provider_ec := app_state.ec_store.all_values("metadata.wallet_provider")): # find 1st wallet_provider
            raise ValueError("The provider wallet is not present in the wallet")

        pub_core_jwks = extract_claim(provider_ec[0], "metadata.wallet_provider.jwks.keys")
        wallet_attestation_jwt = self._get_or_create_app_attestation(provider_ec[0]["iss"], pub_core_jwks)

        # Generazione PKCE
        pkce = generate_pkce_pair()
        logger.info(" code_verifier: %s", pkce.get("code_verifier", ""))

        logger.info("code_challenge: %s", pkce.get("code_challenge", ""))

        logger.info("method: %s", pkce.get("code_challenge_method", ""))

        # Salvataggio in sessione del PKCE code verifier
        self.session["code_verifier"] = pkce["code_verifier"]

        logger.info("Generate Request Object JWT ")
        authorization_details = [
            {"type": "openid_credential", "credential_configuration_id": credential_configuration_id}
        ]

        credential_flow_response_type = extract_claim(current_app.config, "metadata.credential_flow.response_type")

        # DEPRECATED
        # credential_flow_response_mode = extract_claim(current_app.config, "metadata.credential_flow.response_mode")

        credential_flow_redirect_uri = extract_claim(current_app.config, "metadata.credential_flow.redirect_uri")

        session_id = require_session_key(self.session, "session_id", "Session not present")

        logger.info(f"session_id: {session_id}")

        request_object_jwt = generate_par_request_object_jwt(
            issuer_private_key=wallet_private_key,
            audience=eaa_provider_url,
            state=session_id,
            code_challenge=pkce["code_challenge"],
            code_challenge_method=pkce["code_challenge_method"],
            response_type=credential_flow_response_type,
            redirect_uri=credential_flow_redirect_uri,
            authorization_details=authorization_details,
        )
        if not request_object_jwt:
            raise ValueError("PAR Request Generate Exception")

        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.pushed_authorization_request_endpoint"

        logger.info(f"query_filter: {query_filter}")

        eaa_provider_as_par_url = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"sanitize_for_logging(eaa_provider_as_par_url): {sanitize_for_logging(eaa_provider_as_par_url)}")

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

        request_uri = as_par_response.get("request_uri")

        if not request_uri:
            raise ValueError("PAR Response from EAA Provider 'request_uri' not present")

        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.authorization_endpoint"

        eaa_provider_authorization_url = extract_claim(eaa_provider_ec, query_filter)
        params = {
            "client_id": wallet_client_id,
            "request_uri": request_uri,
        }
        authorization_query_string = f"?{urlencode(params)}"

        logger.info(f"authorization_query_string: {authorization_query_string}")

        logger.info(f"authorization endpoint: {eaa_provider_authorization_url}")

        authorize_response = request_authorize(
            url=eaa_provider_authorization_url,
            query_string=authorization_query_string,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info(f"authorize_response: {authorize_response}")

        if not is_jwt(authorize_response):
            raise ValueError("Response from Authoriza dont contain JWT")

        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_VERIFIER}.jwks"
        eaa_provider_verifier_jwks = extract_claim(eaa_provider_ec, query_filter)

        if not eaa_provider_verifier_jwks:
            raise ValueError(
                f" JWK key for EAA provider not found in memory for service: {METADATA_TYPE_CREDENTIAL_VERIFIER}"
            )

        logger.info(
            f"eaa_provider_verifier_jwks: {json.dumps(eaa_provider_verifier_jwks, indent=2, ensure_ascii=False)}"
        )

        try:
            jwt_payload = decode_and_verify_jwt(authorize_response, eaa_provider_verifier_jwks)
            credentials_requested, rp_state, rp_nonce, rp_response_uri = parse_rp_authorization_request(
                jwt_payload, eaa_provider_url
            )
            logger.info("📄 Request_uri response JWT payload:")
            logger.info(f"jwt_payload {json.dumps(jwt_payload, indent=2, ensure_ascii=False)}")
        except ValueError as ve:
            raise ValueError(f"Validation JWT failed: {ve}")

        # Memorizzazione in sessione del relying party state, nonce e response_uri
        self.session["rp_state"] = rp_state
        self.session["rp_nonce"] = rp_nonce
        self.session["rp_response_uri"] = rp_response_uri

        return {"success": True, "data": credentials_requested}

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

        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.status_assertion_endpoint"
        credential_issuer_status_assertion_url = extract_claim(eaa_provider_ec, query_filter)

        logger.info(f"credential_issuer_status_assertion_url: {credential_issuer_status_assertion_url}")

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

        credential_id = self._credential_issuing_management(
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_status_assertion_url=credential_issuer_status_assertion_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=credential_configuration_id,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token,
        )

        self._print_session_data()

        return {"success": True, "data": {"credential_id": credential_id}}

    def loginToVerifier(self, clientId: str, requestUri: str, requestUriMethod: str, state: str):
        """
        Metodo pubblico per effettuare il login ad un Relying Party / Verifier, incluso fetch dell'EC del Relying Party / Verifier.
        In sessione vengono salvati:
             self.session["rp_client_id"]
             self.session["rp_nonce"]
             self.session["rp_state"]
             self.session["rp_response_uri"]
        """
        logger.info(
            "➡️  Richiesta di login presso il Relying Party / Verifier %s",
            sanitize_for_logging(clientId),
        )

        session_id = self.session.get("session_id")
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        # recupero del response_mode relativo al presentation flow dalla configurazione e sua validazione
        presentation_response_mode = extract_claim(current_app.config, "metadata.presentation_flow.response_mode")

        presentation_response_mode_supported = [PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT]
        if presentation_response_mode not in presentation_response_mode_supported:
            raise ValueError(
                f"Il response_mode '{presentation_response_mode}' configurato per la presentazione delle credenziali del wallet non è supportato, i valori ammessi sono: {presentation_response_mode_supported}"
            )

        # recupero del response_type relativo al presentation flow dalla configurazione e sua validazione
        presentation_response_type = extract_claim(current_app.config, "metadata.presentation_flow.response_type")

        presentation_response_type_supported = [PRESENTATION_RESPONSE_TYPE_VP_TOKEN]
        if presentation_response_type not in presentation_response_type_supported:
            raise ValueError(
                f"Il response_type '{presentation_response_type}' configurato per l'inizializzazione del wallet non è supportato, i valori ammessi sono: {presentation_response_type_supported}"
            )

        country = app_state.selected_country
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)

        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")

        logger.info(
            "ℹ️  Trust root individuato per il paese %s: %s",
            sanitize_for_logging(country),
            sanitize_for_logging(trust_root_url),
        )

        # recupero EC del verifier
        logger.info(
            "➡️  Entity ID del Relying Party / Verifier: %s",
            sanitize_for_logging(clientId),
        )

        # Richiama il metodo privato per ottenere l'EC, validarlo e recuperne il payload
        external_verifier_ec = self._entity_configuration_management(
            clientId, [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_VERIFIER], trust_root_url
        )

        logger.info(
            f"✅ Scaricato e validato l'Entity Configuration dell'entità {clientId} di tipo {METADATA_TYPE_CREDENTIAL_VERIFIER}"
        )

        # Salvataggio in memoria Flask external_verifier_ec
        app_state.ec_store.add(clientId, external_verifier_ec)
        logger.info(
            f"✅ Salvato in memoria il payload dell'Entity Configuration dell'entità {clientId} di tipo {METADATA_TYPE_CREDENTIAL_VERIFIER}"
        )

        # Build authorization query string
        params = {
            "client_id": clientId,
            "request_uri": requestUri,
            "request_uri_method": requestUriMethod,
            "state": state,
        }
        query_string = f"?{urlencode(params)}"

        logger.info(
            "🚀 Invio Request_uri request al Request_uri endpoint %s",
            sanitize_for_logging(requestUri),
        )
        # Effettua una request_uri request
        request_uri_response = request_request_uri(
            url=requestUri, query_string=query_string, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains
        )

        logger.info(
            "✅ Ricevuta risposta dal Request_uri endpoint %s",
            sanitize_for_logging(requestUri),
        )
        logger.info("%s", sanitize_for_logging(request_uri_response))

        if not is_jwt(request_uri_response):
            raise ValueError("La Request_uri response ricevuta dal Relying Party / Verifier non è un JWT")

        # Recupero JWK da usare per validare il jwt
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_VERIFIER}.jwks"
        verifier_jwks = extract_claim(external_verifier_ec, query_filter)
        if not verifier_jwks:
            raise ValueError(f"Non trovata in memoria alcuna chiave JWK del Relying Party / Verifier {clientId}")

        logger.debug("🔑 JWKs trovato:")
        logger.debug("%s", sanitize_for_logging(json.dumps(verifier_jwks, indent=2, ensure_ascii=False)))

        try:
            request_uri_response_jwt_payload = decode_and_verify_jwt(request_uri_response, verifier_jwks)
            credentialsRequested, rp_state, rp_nonce, rp_response_uri = parse_rp_authorization_request(
                request_uri_response_jwt_payload, clientId
            )

            logger.info(
                f"✅ Validato con successo il JWT contenuto nel Request_uri response del Relying Party / Verifier {clientId}"
            )
            logger.info(
                f"ℹ️  Questo JWT rappresenta la richiesta di autorizzazione che il Relying Party / Verifier {clientId} ha fatto al wallet per accedere a specifiche credenziali del wallet prima di consentirgli di effettuare il login richiesto"
            )
            logger.info("📄 Request_uri response JWT payload:")
            logger.info("%s", sanitize_for_logging(request_uri_response_jwt_payload))
        except ValueError as ve:
            raise ValueError(
                f"Fallita validazione del JWT contenuto nella Request_uri response del Relying Party / Verifier {clientId}: {ve}"
            )

        # Memorizzazione dati in sessione
        self.session["rp_client_id"] = clientId
        self.session["rp_state"] = rp_state
        self.session["rp_nonce"] = rp_nonce
        self.session["rp_response_uri"] = rp_response_uri

        return {"success": True, "data": credentialsRequested}

    def complete_loginToVerifier(self, credentials_presenting: list[dict]):
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

        logger.info(
            f"➡️  Richiesta di completamento dell'operazione di login presso il Relying Party / Verifier {rp_client_id} effettuata dal wallet"
        )

        # codeql[py/log-injection]
        logger.info("➡️  %s", sanitize_for_logging(credentials_presenting))

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

        logger.debug("🔑 JWKs trovato:")
        logger.debug("%s", sanitize_for_logging(json.dumps(rp_jwks, indent=2, ensure_ascii=False)))

        # recupero del response_mode relativo al credentialflow dalla configurazione
        credential_flow_response_mode = extract_claim(current_app.config, "metadata.credential_flow.response_mode")

        authorizationResponse = self._presentation_management(
            enc=True,
            credentials_presenting=credentials_presenting,
            rp_state=rp_state,
            rp_nonce=rp_nonce,
            rp_response_uri=rp_response_uri,
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

    def _authorization_response_management(
        self, authorization_response: dict, state_expected: Optional[str] = None, iss_expected: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """Validate auth response, return (code, state, iss). Raises on error or mismatch."""
        logger.info(
            f"Entering method: _authorization_response_management. Params [authorization_response: {authorization_response}]"
        )

        if not authorization_response:
            raise ValueError("authorization_response empty")

        authorization_response_code = authorization_response.get("code")

        authorization_response_state = authorization_response.get("state")

        authorization_response_iss = authorization_response.get("iss")

        authorization_response_error = authorization_response.get("error")

        authorization_response_error_description = authorization_response.get("error_description")

        logger.info(f"authorization_response_code: {authorization_response_code}")
        logger.info(f"authorization_response_state: {authorization_response_state}")
        logger.info(f"authorization_response_iss: {authorization_response_iss}")
        logger.info(f"authorization_response_error: {authorization_response_error}")
        logger.info(f"authorization_response_error_description: {authorization_response_error_description}")

        if state_expected is not None and authorization_response_state != state_expected:
            raise ValueError(
                f"state_expected: {state_expected}, authorization_response_state: {authorization_response_state}"
            )

        if authorization_response_error:
            raise ValueError(
                f"authorization_response_error: {authorization_response_error}, authorization_response_error_description: {authorization_response_error_description}"
            )
        else:
            if not authorization_response_code:
                raise ValueError("authorization_response_code empty")

            if iss_expected is not None and authorization_response_iss != iss_expected:
                raise ValueError(f"iss_expected: '{iss_expected}'but found: '{authorization_response_iss}'")

        return authorization_response_code, authorization_response_state, authorization_response_iss

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
            raise ValueError("Exception generation wallet key")

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)

        logger.info(f"wallet_client_id: {wallet_client_id}")

        client_attestation_pop_jwt = generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key, audience=authorization_server_url
        )
        logger.info(f"client_attestation_pop_jwt: {client_attestation_pop_jwt}")


        if not (provider_ec := app_state.ec_store.all_values("metadata.wallet_provider")):  # find 1st wallet_provider
            raise ValueError("The provider wallet is not present in the wallet")
        pub_core_jwks = extract_claim(provider_ec[0], "metadata.wallet_provider.jwks.keys")
        wallet_attestation_jwt = self._get_or_create_app_attestation(provider_ec[0]["iss"], pub_core_jwks)

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
            validate_access_token(
                dpop_bound_access_token_claims,
                authorization_server_url,
                wallet_client_id,
                wallet_client_id,
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

        logger.info(f"{credential_configuration_id} len: {len(matching_identifiers)}")

        return dpop_bound_access_token, matching_identifiers

    def _get_or_create_app_attestation(self, provider_url: str, provider_jwks: list[dict]) -> str:
        """Get wallet attestation JWT from store, or create if missing/expired. Returns JWT string."""
        logger.info(f"Entering method: _get_or_create_wallet_attestation. Params [provider_url: {provider_url}]")

        wa_id = JWT_PREFIX + "_" + WALLET_ATTESTATION_NAME
        jwt_val = app_state.ec_store.get(wa_id)

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

        if not jwt_val or not validate_jws(jwt_val):
            attestations = self._retrieve_attestations_jws(provider_url)
            if app_attestation := attestations.get("wallet_app_attestation"):
                app_state.ec_store.add(wa_id, app_attestation)
                jwt_val = app_attestation
        return jwt_val

    def _decode_and_validate_single_credential(
        self, cred: dict, index: int, credential_id: str, credential_configuration_id: str, credential_issuer_jwks: dict
    ) -> tuple | None:
        """Decode and validate a single credential (SD-JWT or mDL). Returns (credential, vct, claims) or None."""
        credential = cred.get("credential")
        if not credential:
            logger.info("⚠️ Contenuto della credenziale %d mancante o non valido.", index)
            return None
        if credential_id.startswith(SD_JWT_PREFIX):
            claims = decode_and_verify_sd_jwt(sd_jwt_compact=credential, jwks=credential_issuer_jwks)
            logger.info("✅ Credenziale #%d valida (SD-JWT)", index)
            return credential, claims.get("vct", ""), claims
        if credential_id.startswith(MSO_MDOC_PREFIX):
            expected_doc = ISO_18013_5_NAME + "." + credential_configuration_id.removeprefix(MSO_MDOC_PREFIX + "_")
            result_json = decode_and_verify_issuer_signed(
                issuer_signed_base64_url=credential,
                expected_namespaces={ISO_18013_5_NAME, ISO_18013_5_NAME + ".IT"},
                expected_version=ISO_18013_5_VERSION,
                expected_doc_type=expected_doc,
            )
            logger.info("✅ Credenziale #%d valida (mDL)", index)
            return credential, expected_doc, result_json
        return None

    def _fetch_credentials_for_id(
        self,
        credential_id: str,
        nonce_url: str,
        credential_url: str,
        wallet_private_key,
        dpop_bound_access_token: str,
    ) -> list:
        """Fetch credentials for given credential_id via nonce+proof+request. Returns list of credential dicts."""
        logger.info(
            f"Entering method: _fetch_credentials_for_id. Params [credential_id: {credential_id}, nonce_url: {nonce_url}, credential_url: {credential_url}]"
        )

        nonce_resp = request_nonce(url=nonce_url, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains)

        proof_jwt = generate_proof_jwt(issuer_private_key=wallet_private_key, audience=credential_url, nonce=nonce_resp)

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
            raise ValueError("credentials empty")
        return credentials

    def _credential_issuing_management(
        self,
        credential_issuer_nonce_url: str,
        credential_issuer_credential_url: str,
        credential_issuer_status_assertion_url: str,
        credential_issuer_jwks: dict,
        credential_configuration_id: str,
        credential_identifiers: list,
        dpop_bound_access_token: str,
    ) -> str:
        """Request credentials via nonce+proof, decode/validate, store in credential_store. Returns credential_id."""
        logger.info(
            f"Entering method: _credential_issuing_management. Params [credential_issuer_nonce_url: {credential_issuer_nonce_url}]"
        )

        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Generation Key Exception: wallet_private_key or wallet_public_key empty")

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)

        logger.debug(f"wallet_client_id: {wallet_client_id}")

        last_valid_credential = None

        last_valid_credential_claims = None

        for credential_id in credential_identifiers:
            credentials = self._fetch_credentials_for_id(
                credential_id,
                credential_issuer_nonce_url,
                credential_issuer_credential_url,
                wallet_private_key,
                dpop_bound_access_token,
            )
            for index, cred in enumerate(credentials, start=1):
                result = self._decode_and_validate_single_credential(
                    cred, index, credential_id, credential_configuration_id, credential_issuer_jwks
                )
                if result:
                    last_valid_credential, last_valid_credential_vct, last_valid_credential_claims = result

        if last_valid_credential and last_valid_credential_claims:
            # Salvataggio credenziale nel credential store presente in memoria Flask
            app_state.wallet_initialized = True
            app_state.credential_store.add(
                credential_id, last_valid_credential, last_valid_credential_vct, last_valid_credential_claims
            )

            logger.info("✅ Salvata in memoria credenziale %s", sanitize_for_logging(credential_id))

            if credential_id.startswith(SD_JWT_PREFIX):
                try:
                    # recupero status assertion
                    self._status_assertion_management(
                        credential_issuer_status_assertion_url,
                        credential_issuer_jwks,
                        credential_id,
                        last_valid_credential,
                    )
                except Exception as e:
                    logger.warning(
                        f"⚠️  Non è stato possibile recuperare la status assertion per la credenziale {credential_id}: {e}"
                    )

            return credential_id
        else:
            logger.info("❌ Nessuna credenziale valida ricevuta")
            raise ValueError("Nessuna credenziale valida ricevuta")

    def _validate_and_get_status_assertion(self, responses: list, jwks: dict) -> tuple[str, dict]:
        """Validate status assertion responses, return (jwt, claims) of last valid. Raises if none valid."""
        last_jwt, last_claims = None, None
        for i, resp in enumerate(responses, 1):
            claims = decode_and_verify_jwt(resp, jwks)
            last_jwt, last_claims = resp, claims
        if not last_jwt or not last_claims:
            raise ValueError("Nessuna Status Assertion Response valida ricevuta")
        return last_jwt, last_claims

    def _status_assertion_management(
        self,
        credential_issuer_status_assertion_url: str,
        credential_issuer_jwks: dict,
        credential_id: str,
        sd_jwt_compact: str,
    ):
        """Fetch status assertion for SD-JWT credential, update credential_store with status."""
        # Generazione/letturia coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Fallita generazione coppia di chiavi pvt e pub del wallet")

        idx = sd_jwt_compact.find("~")
        credential_before_tilde = sd_jwt_compact if idx == -1 else sd_jwt_compact[:idx]

        # Calcolo dell'hash SHA-256 sulla credenziale senza le disclosure
        signature_hash = hashlib.sha256(credential_before_tilde.encode("utf-8")).digest()

        # Generazione Status Assertion Request JWT per richiedere la Status Assertion della credenziale
        logger.info(
            f"Generazione Status Assertion Request JWT per richiedere al Credential Issuer la Status Assertion della credenziale {credential_id}..."
        )
        status_assertion_request_object_jwt = generate_status_assertion_request_object_jwt(
            issuer_private_key=wallet_private_key,
            audience=credential_issuer_status_assertion_url,
            credential_hash=signature_hash.hex(),
            credential_hash_alg="sha-256",
        )

        if not status_assertion_request_object_jwt:
            raise ValueError("Fallita generazione Status Assertion Request JWT")
        logger.info("📄 Status Assertion Request JWT generato.")

        status_assertion_request_object_jwt_list: list[str] = [status_assertion_request_object_jwt]

        logger.info(
            "🚀 Invio STATUS request allo STATUS ASSERTION endpoint %s",
            sanitize_for_logging(credential_issuer_status_assertion_url),
        )
        # Effettua una status request
        status_response = request_status(
            url=credential_issuer_status_assertion_url,
            status_assertion_requests=status_assertion_request_object_jwt_list,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info(
            "✅ Ricevuta risposta dallo STATUS ASSERTION endpoint %s",
            sanitize_for_logging(credential_issuer_status_assertion_url),
        )
        logger.info("%s", sanitize_for_logging(status_response))

        status_assertion_responses = status_response.get("status_assertion_responses")
        if not status_assertion_responses:
            raise ValueError("STATUS Response non contiene un claim 'status_assertion_responses'")
        jwt_resp, claims_resp = self._validate_and_get_status_assertion(
            status_assertion_responses, credential_issuer_jwks
        )
        if claims_resp.get("error"):
            raise ValueError(f"Status Assertion ha rilevato errore: {claims_resp['error']}")
        credential_status = claims_resp.get("credential_status_type", "")

        # Update status della credenziale nel credential store presente in memoria Flask
        app_state.credential_store.update_status(credential_id, jwt_resp, credential_status)

        logger.info(
            "✅ Impostato in memoria lo stato della credenziale %s pari a %s",
            sanitize_for_logging(credential_id),
            sanitize_for_logging(credential_status),
        )

    def _add_credential_presentation_to_vp(
        self,
        item: dict,
        vp_token_claims: dict,
        rp_response_uri: str,
        rp_nonce: str,
        wallet_private_key_jwk_dict: dict,
        presentation_status_assertion_supported: bool,
    ) -> None:
        """Find credential for item, build SD-JWT presentation, add to vp_token_claims if found."""
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
            aud=rp_response_uri,
            nonce=rp_nonce,
            claims_to_reveal=claim_paths_nested,
            holder_private_jwk_dict=wallet_private_key_jwk_dict,
        )
        if presentation:
            vp_token_claims[item["id"]] = presentation
            if presentation_status_assertion_supported and value.get("status_assertion"):
                vp_token_claims[item["id"] + "_status"] = value["status_assertion"]

    def _build_response_uri_request(
        self, enc: bool, vp_token_claims: dict, rp_state: str, rp_jwks: dict, wallet_private_key
    ) -> str:
        """Build JWE or JWS for response_uri request. Raises ValueError on failure."""
        logger.info("Entering method: _build_response_uri_request. Params []")

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

    def _presentation_management(
        self,
        enc: bool,
        credentials_presenting: list[dict],
        rp_state: str,
        rp_nonce: str,
        rp_response_uri: str,
        rp_jwks: dict,
        response_mode: str,
    ) -> dict:
        """Build vp_token from credentials_presenting, send response_uri request, return auth response."""
        # recupero dello status_assertion_supported relativo al presentation flow dalla configurazione
        presentation_status_assertion_supported = extract_claim(
            current_app.config, "metadata.presentation_flow.status_assertion_supported"
        )

        # Lettura coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._retrieve_instance_hw_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Non è stato possibile leggere la coppia di chiavi pvt e pub del wallet")

        # Converti la chiave privata in JWK dict
        wallet_private_key_jwk = priv_ec_key_obj_to_jwk(wallet_private_key)
        wallet_private_key_jwk_dict = wallet_private_key_jwk.export(as_dict=True)

        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        # codeql[py/log-injection]
        logger.debug(
            "ℹ️  Calcolato client id del wallet come thumbprint della sua chiave pvt: %s",
            sanitize_for_logging(wallet_client_id),
        )

        self.session["wallet_client_id"] = wallet_client_id

        vp_token_claims = {}
        for item in credentials_presenting:
            self._add_credential_presentation_to_vp(
                item,
                vp_token_claims,
                rp_response_uri,
                rp_nonce,
                wallet_private_key_jwk_dict,
                presentation_status_assertion_supported,
            )

        if len(vp_token_claims) == 0:
            raise ValueError("vp_token prodotto non presenta alcun claim")

        logger.info("✅ Generato vp_token: %s", sanitize_for_logging(list(vp_token_claims.keys())))

        response_uri_request_jwt = self._build_response_uri_request(
            enc, vp_token_claims, rp_state, rp_jwks, wallet_private_key
        )

        # Effettua una response uri request
        logger.info(
            "🚀 Invio Response_uri request al Response_uri endpoint %s",
            sanitize_for_logging(rp_response_uri),
        )
        response_uri_response = request_response_uri(
            url=rp_response_uri,
            response_uri_request_jwt=response_uri_request_jwt,
            state=rp_state,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )

        logger.info(
            "✅ Ricevuta risposta dal Response_uri endpoint %s",
            sanitize_for_logging(rp_response_uri),
        )
        logger.info("%s", sanitize_for_logging(response_uri_response))

        redirect_uri = response_uri_response.get("redirect_uri")
        if redirect_uri:
            logger.info(
                f"✅  La Response_uri response ricevuta dal Response_uri endpoint {rp_response_uri} del Relying Party / Verifier contiene un redirect_uri pari a: {redirect_uri}"
            )

            # Effettua la richiesta alla callback
            logger.info(
                "🚀 Invio un messaggio di richiesta al redirect_uri %s",
                sanitize_for_logging(redirect_uri),
            )
            callback_response = request_presentation_callback(
                url=redirect_uri, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains
            )

            logger.info(
                "✅ Ricevuta dal redirect_uri %s la seguente risposta:",
                sanitize_for_logging(redirect_uri),
            )
            logger.info("%s", sanitize_for_logging(callback_response))

            return self._parse_presentation_callback(callback_response, response_mode, redirect_uri, rp_jwks)
        else:
            logger.warning(
                f"⚠️  Nessun 'redirect_uri' definito nella Response_uri response ricevuta dal Response_uri endpoint {rp_response_uri} del Relying Party / Verifier"
            )
            logger.info("✅ La fase di presentazione si è conclusa positivamente")

            logger.info("📄 Il risultato è il seguente JSON:")
            logger.info("%s", sanitize_for_logging(json.dumps(response_uri_response, indent=2)))
            return response_uri_response

    def _presentation_management_v133(
        self,
        enc: bool,
        credentials_presenting: list[dict],
        rp_state: str,
        rp_nonce: str,
        rp_response_uri: str,
        rp_jwks: dict,
        response_mode: str,
    ) -> dict:
        """Build vp_token from credentials_presenting, send response_uri request, return auth response."""
        logger.info(
            f"Entering method: _presentation_management_v133. Params [enc: {enc}, credentials_presenting: {credentials_presenting}, rp_state: {rp_state}]"
        )

        presentation_status_assertion_supported = extract_claim(
            current_app.config, "metadata.presentation_flow.status_assertion_supported"
        )

        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)

        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Public and private Key not found for wallet")

        wallet_private_key_jwk = priv_ec_key_obj_to_jwk(wallet_private_key)

        wallet_private_key_jwk_dict = wallet_private_key_jwk.export(as_dict=True)

        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.info(f"wallet_client_id: {wallet_client_id}")

        self.session["wallet_client_id"] = wallet_client_id

        vp_token_claims = {}

        for item in credentials_presenting:
            self._add_credential_presentation_to_vp(
                item,
                vp_token_claims,
                rp_response_uri,
                rp_nonce,
                wallet_private_key_jwk_dict,
                presentation_status_assertion_supported,
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
            state=rp_state,
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

    # V1.3.3
    def __parse_presentation_callback_v133(
        self, callback_response: str, response_mode: str, redirect_uri: str, rp_jwks: dict
    ) -> dict:
        logger.info(
            f"Entering method: _parse_presentation_callback_v133. Params [callback_response: {callback_response}, response_mode: {response_mode}]"
        )

        if response_mode == AUTH_RESPONSE_MODE_FORM_POST_JWT:
            return self.__parse_form_post_jwt_response(callback_response, redirect_uri, rp_jwks)
        elif response_mode == PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT:
            return self.__parse_direct_post_jwt_response(callback_response, redirect_uri, rp_jwks)
        else:
            return self.__parse_query_string_response(callback_response, redirect_uri)

    # V1.3.3
    def __parse_form_post_jwt_response(self, callback_response: str, redirect_uri: str, rp_jwks: dict) -> dict:
        logger.info(
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

    # V1.3.3
    def __parse_direct_post_jwt_response(self, callback_response: str, redirect_uri: str, rp_jwks: dict) -> dict:
        logger.info(
            f"Entering method: __parse_direct_post_jwt_response. Params [callback_response: {callback_response}]"
        )

        response_str = callback_response.strip()

        if not is_jwt(response_str):
            raise ValueError("JWT not valid")

        return self.__validate_authentication_response(response_str, rp_jwks, redirect_uri)

    def __parse_query_string_response(self, callback_response: str, redirect_uri: str) -> dict:
        logger.info(
            f"Entering method: __parse_query_string_response. Params [callback_response: {callback_response}, redirect_uri: {redirect_uri}]"
        )

        parsed = urlparse(callback_response)

        result = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}

        logger.info(f"list(result.keys(): {list(result.keys())}")

        return result

    def __validate_authentication_response(self, jwt_response: str, rp_jwks: dict, redirect_uri: str) -> dict:

        logger.info(
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
        logger.info(
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
        logger.info(
            f"Entering method: __check_auth_response_errors. Params: [payload: {payload}, redirect_uri: {redirect_uri}]"
        )

        error = payload.get("error")
        if error:
            raise ValueError(f"Exception {redirect_uri}: {error}")

    def _entity_configuration_management(
        self, issuer_url: str, expectedMetadataTypes: list[str], expected_hint=None
    ) -> dict:
        """Fetch and validate EC for issuer_url. Returns EC payload. Raises on failure."""
        logger.info(
            "Invio richiesta all'entità %s per scaricare il suo entity configuration",
            sanitize_for_logging(issuer_url),
        )
        # Ottiene l'EC
        ec_jwt = oid_fed_fetch_openid_configuration(
            base_url=issuer_url, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains
        )

        ec_payload = None

        if not ec_jwt:
            raise ValueError(f"Fallito recupero dell'Entity Configuration dell'entità {issuer_url}")

        logger.info(
            "Ricevuto in risposta dall'entità %s il suo Entity Configuration",
            sanitize_for_logging(issuer_url),
        )

        try:
            ec_payload = decode_and_verify_jwt(ec_jwt)
            validate_ec(ec_payload, issuer_url, expectedMetadataTypes, expected_hint)

            logger.info(
                "L'Entity Configuration dell'entità %s è risultato essere valido",
                sanitize_for_logging(issuer_url),
            )

            return ec_payload
        except ValueError as ve:
            raise ValueError(f"Fallita validazione dell'Entity Configuration dell'entità {issuer_url}: {ve}")

    def _retrieve_instance_hw_keys(self, config_dir) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
        Metodo privato per generare le chiavi del wallet e salvarle su config dir.
        Ritorna una tupla: (chiave_privata, chiave_pubblica)
        """
        logger.info(f"Entering method: _inizializza_wallet_keys. Params [config_dir: {config_dir}]")

        if not os.path.exists(config_dir):
            os.makedirs(config_dir)

        private_key_path = os.path.join(config_dir, "pvt_key.pem")

        public_key_path = os.path.join(config_dir, "pub_key.pem")

        if not os.path.isfile(private_key_path) or not os.path.isfile(public_key_path):
            generate_pem_keys(private_key_path, public_key_path, "P-256")
            logger.info("Key generated.")
        else:
            logger.info("Key found, we dont need new generation.")

        wallet_private_key = ec_private_key_from_pem_file(private_key_path)

        wallet_public_key = ec_public_key_from_pem_file(public_key_path)

        self._hw_private_jwk = priv_ec_key_obj_to_jwk(wallet_private_key).export_private(as_dict=True)
        self._hw_public_jwk = pub_ec_key_obj_to_jwk(wallet_public_key).export_public(as_dict=True)
        self._hw_key_tag = base64url_decode(
            get_thumbprint_from_private_key(wallet_private_key)
        ).hex()  # generate fake hw key tag

        # Ritorna la tupla
        return wallet_private_key, wallet_public_key

    def _find_credential_by_dcql_item(self, item: dict) -> dict | None:
        """Find credential matching DCQL item (by format+id or vct). Returns (key, value) or None."""
        if not item["id"]:
            logger.info("❌ Il DCQL non presenta il claim 'id'")
            return None

        if not item["format"]:
            logger.info("❌ Il DCQL non presenta il claim 'format'")
            return None

        logger.info(
            "ℹ️  Il DCQL presenta i claims 'id': %s e 'format': %s",
            sanitize_for_logging(item.get("id", "")),
            sanitize_for_logging(item.get("format", "")),
        )

        # Costruisci l'ID
        raw_id = item["format"] + "_" + item["id"]
        credential_presenting_id = re.sub(r"[+\-\s]", "_", raw_id)
        logger.info(
            f"ℹ️  Uso claims 'format' e 'id' del DCQL per generare la chiave '{credential_presenting_id}' con cui cercare nel wallet la credenziale da presentare"
        )

        result = app_state.credential_store.find_by_prefix_with_key(credential_presenting_id)
        if not result:
            logger.info(
                "❌ La chiave '%s' non ha individuato alcuna credenziale nel wallet",
                sanitize_for_logging(credential_presenting_id),
            )

            # Tento la ricerca con vct
            credential_presenting_vct = None
            meta = item["meta"]
            if not meta:
                logger.info("❌ Il DCQL non presenta il claim 'meta'")
                return None

            logger.info("ℹ️  Il DCQL presenta il claims 'meta': %s", sanitize_for_logging(meta))

            if not isinstance(meta, dict):
                logger.info("❌ Il DCQL presenta il claim 'meta' che non è di tipo JSON Object")
                return None

            vct_values = meta.get("vct_values")

            if not vct_values:
                logger.info("❌ Il DCQL non presenta il claim 'meta.vct_values' né 'meta.vctValues'")
                return None

            if not isinstance(vct_values, list):
                logger.info("❌ Il DCQL presenta il claim 'meta.vct_values' che non è di tipo JSON Array")
                return None

            credential_presenting_vct = vct_values[0]

            logger.info(
                f"ℹ️  Uso del vct '{credential_presenting_vct}' estratto dal DCQL per cercare nel wallet la credenziale da presentare"
            )

            result = app_state.credential_store.find_by_vct(credential_presenting_vct)

            if not result:
                logger.info(
                    "❌ Il vct '%s' non ha individuato alcuna credenziale nel wallet",
                    sanitize_for_logging(credential_presenting_vct),
                )

        return result

    def _print_session_data(self):
        """Log session data for debugging (JSON or key-value fallback)."""
        logger.debug("=== 🌐 Dati in sessione ===")
        try:
            session_json = json.dumps(dict(self.session), indent=2, ensure_ascii=False)
            # codeql[py/log-injection]
            logger.debug("%s", sanitize_for_logging(session_json))
        except TypeError:
            # fallback se qualche valore non è serializzabile
            for key, value in self.session.items():
                # codeql[py/log-injection]
                logger.debug("%s: %s", sanitize_for_logging(key), sanitize_for_logging(value))
        logger.debug("========================")

    def _retrieve_attestations_jws(self, provider_url: str) -> dict[str, str]:
        """This method retrieve a wallet app attestation and a wallet unit attestation from wallet provider endpoint.
        Return: a dict with attestations as signed JWT
        """
        if not self._hw_key_tag or not self._hw_private_jwk:
            raise ValueError("Unable to retrieve instance wallet keys, please initialize instance wallet again")

        provider_url = provider_url[: -1] + provider_url[-1].replace("/", "")
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

    def _retrieve_wallet_provider_ec(self, trust_root_url: str) -> str | None:
        """
        Retrieve the wallet provider url from the trusted root; store it Entity Configuration in-memory
        Returns:
            (str) wallet provider URL or None if error occurred
        """
        params = {"entity_type": METADATA_TYPE_WALLET_SOLUTION}

        founded = oid_fed_list(
            base_url=trust_root_url,
            query_string=f"?{urlencode(params)}",
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )
        if not founded:
            logger.error("No entity of type wallet_provider was found within the federation.")
            return None

        try:
            wallet_provider_url = founded[0]
            ec_payload = self._entity_configuration_management(
                wallet_provider_url,
                [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_WALLET_SOLUTION],
                trust_root_url
            )
        except Exception as e:
            logger.error("Unable to retrieve entity configuration for provider - error: {}".format(e))
            return None
        app_state.ec_store.add(wallet_provider_url, ec_payload)
        return wallet_provider_url