# itwallet_manager.py

import copy
import logging

import jmespath
logger = logging.getLogger(__name__)


import hashlib
import json
import os
import re
from utils.cborUtils import decode_and_verify_issuer_signed
from bs4 import BeautifulSoup
from state import app_state
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from typing import Tuple
from typing import Optional
from flask import current_app
from urllib.parse import parse_qs, urlencode, urlparse

from constants import (
    AAL_VALUE_HIGH,
    CONFIG_DIR,
    MSO_MDOC_PREFIX,
    METADATA_TYPE_FEDERATION_ENTITY,
    METADATA_TYPE_AUTHORIZATION_SERVER,
    METADATA_TYPE_CREDENTIAL_ISSUER,
    METADATA_TYPE_CREDENTIAL_VERIFIER,
    JWT_PREFIX,
    SD_JWT_PREFIX,
    WALLET_ATTESTATION_NAME,
    AUTH_RESPONSE_MODE_QUERY, 
    AUTH_RESPONSE_MODE_FORM_POST_JWT,
    AUTH_RESPONSE_TYPE_CODE,
    PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT,
    PRESENTATION_RESPONSE_TYPE_VP_TOKEN,
    ISO_18013_5_VERSION,
    ISO_18013_5_NAME
)

from utils.oidFedUtils import (
    oid_fed_list,
    oid_fed_fetch_openid_configuration
)

from utils.jwtUtils import (
    extract_key_for_enc,
    decode_and_verify_jwt,
    is_jwt,
    jwk_private_to_public,
    jwk_to_jwks
)

from utils.utils import (
    ec_private_key_from_pem_bytes,
    extract_claim,
    generate_pem_keys,
    ec_private_key_from_pem_file,
    ec_public_key_from_pem_file,
    generate_pkce_pair,
    get_thumbprint_from_private_key,
    pem_private_key_from_jwk_dict,
    priv_ec_key_obj_to_jwk
)

from utils.itwalletUtils import (
    generate_wallet_attestation_sd_jwt,
    get_status_description,
    request_as_par,
    request_authorize,
    request_presentation_callback,
    request_request_uri,
    request_status,
    request_token,
    request_nonce,
    request_credential,
    request_response_uri,
    generate_request_object_jwt,
    generate_proof_jwt,
    generate_dpop_jwt,
    generate_wallet_attestation_pop_jwt,
    generate_wallet_attestation_jwt,
    generate_response_uri_request_jws,
    generate_response_uri_request_jwe,
    generate_status_assertion_request_object_jwt,
)

from utils.sdJwtUtils import (
    decode_and_verify_sd_jwt,
    present_sd_jwt,
    paths_to_nested_dict
)


class ItWalletService:
    
    def __init__(self, session):
        self.session = session
        
        # Leggo una sola volta la configurazione dei proxy
        use_proxy = extract_claim(current_app.config,"metadata.use_proxy")
        logger.info(f"🚨  Use proxy: {use_proxy}")

        if use_proxy:
            logger.info(f"🚨  Configurin proxy...")
            self.proxies = {
                "http": extract_claim(current_app.config,"metadata.http_proxy"),
                "https": extract_claim(current_app.config,"metadata.https_proxy")
            }
            # Leggo e preparo la lista dei domini esclusi dal proxy
            no_proxy_raw = extract_claim(current_app.config, "metadata.no_proxy") or ""
            self.no_proxy_domains = [domain.strip() for domain in no_proxy_raw.split(",") if domain.strip()]
            logger.info(f"🚨  Proxy abilitati: HTTP={self.proxies['http']}, HTTPS={self.proxies['https']}")
            logger.info(f"🚨  No proxy domains: {self.no_proxy_domains}")
        else:
            self.proxies = None
            self.no_proxy_domains = []
            logger.info("🚨  Proxy disabilitati")
        
            
    def getOnboardedRelyingParties(self):
        logger.info(f"➡️  Richiesta elenco Relying Parties onboardati")

        # recupero selected_country dalla memoria
        country = app_state.selected_country

        # recupero trust_root_url dalla configurazione
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)
        
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        
        logger.info(f"ℹ️  Trust root individuato per il paese {country}: {trust_root_url}")

        params = {
            "entity_type": METADATA_TYPE_CREDENTIAL_VERIFIER
        }
        list_query_string = f"?{urlencode(params)}"
        
        oid_fed_list_reponse = oid_fed_list(
            base_url=trust_root_url, 
            query_string=list_query_string,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )

        return {
            "success": True,
            "data": oid_fed_list_reponse
        }
   
    def initialize_wallet(self, idp: str, country: str):
        """
        Metodo pubblico per inizializzare l'IT Wallet per il paese indicato
        In sessione vengono salvati:
             self.session["code_verifier"]
             self.session["pid_provider_url]
        """
        logger.info(f"➡️  Richiesta di Inizializzazione del wallet per il paese: {country}")
           
        # Recupera la tipologia di credenziale da richiedere per l'inizializazzione del wallet dalla configurazione
        CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING = extract_claim(current_app.config,"metadata.initialize_flow.credential_configuration_id")

        # recupero del response_mode relativo all'initialize flow dalla configurazione e sua validazione
        initialize_flow_response_mode = extract_claim(current_app.config,"metadata.initialize_flow.response_mode")

        initialize_flow_response_mode_supported = [AUTH_RESPONSE_MODE_QUERY]
        if not initialize_flow_response_mode in initialize_flow_response_mode_supported:
            raise ValueError(f"Il response_mode '{initialize_flow_response_mode}' configurato per l'inizializzazione del wallet non è supportato, i valori ammessi sono: {initialize_flow_response_mode_supported}")
        
        # recupero del response_type relativo all'initialize flow dalla configurazione e sua validazione
        initialize_flow_response_type = extract_claim(current_app.config,"metadata.initialize_flow.response_type")

        initialize_flow_response_type_supported = [AUTH_RESPONSE_TYPE_CODE]
        if not initialize_flow_response_type in initialize_flow_response_type_supported:
            raise ValueError(f"Il response_type '{initialize_flow_response_type}' configurato per l'inizializzazione del wallet non è supportato, i valori ammessi sono: {initialize_flow_response_type_supported}")
        
        # recupero trust_root_url dalla configurazione
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)
        
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        
        logger.info(f"ℹ️  Trust root individuato per il paese {country}: {trust_root_url}")
       
        # recupero wallet provider url dalla configurazione
        wallet_provider_url = extract_claim(current_app.config, "metadata.wallet_provider.id")
        
        # recupero chiave privata wallet provider JWK dalla configurazione
        wallet_provider_pvt_key_jwk_dict = extract_claim(current_app.config,"metadata.wallet_provider.key")

        # controllo se in memoria ho l'EC del Trust root
        if not app_state.ec_store.exists(trust_root_url):
        
            # Richiama il metodo privato per effettuare il download dell'EC del Trust root, validarlo e recuperne il payload
            trust_root_ec_payload = self._entity_configuration_management(trust_root_url, [METADATA_TYPE_FEDERATION_ENTITY])
        
            logger.info(f"✅ Scaricato e validato l'Entity Configuration del trust root {trust_root_url}")
            
            # Salvataggio in memoria Flask trust_root_ec_payload
            app_state.ec_store.add(trust_root_url, trust_root_ec_payload)
            logger.info(f"✅ Salvato in memoria il payload dell'Entity Configuration del trust root {trust_root_url}")
        
        # Richiama il metodo privato per effettuare il download dal Trust root degli entity types che sono stati onboardati con il ruolo di openid_credential_issuer
        params = {
            "entity_type": METADATA_TYPE_CREDENTIAL_ISSUER
        }
        list_query_string = f"?{urlencode(params)}"
        
        oid_fed_list_reponse = oid_fed_list(
            base_url=trust_root_url, 
            query_string=list_query_string,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"📄 oid_fed_list response: {oid_fed_list_reponse}")

        pid_provider_ec = None
        
        for entity_id in oid_fed_list_reponse:
            logger.info(f"➡️  Entity ID: {entity_id}")

            # Richiama il metodo privato per ottenere l'EC dell'entità oboardata con il ruolo di openid_credential_issuer, validarlo e recuperne il payload
            ec_payload = self._entity_configuration_management(entity_id, [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_ISSUER], trust_root_url)
            
            logger.info(f"✅ Scaricato e validato l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}") 
            
            # Salvataggio in memoria dell'ec_payload usando come chiave entity_id
            app_state.ec_store.add(entity_id, ec_payload)
            logger.info(f"✅ Salvato in memoria il payload dell'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}")

            credential_configurations_supported = ec_payload.get("metadata", {}).get(METADATA_TYPE_CREDENTIAL_ISSUER, {}).get("credential_configurations_supported")

            if CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING in credential_configurations_supported:
                pid_provider_ec = ec_payload

                initializeFlowReplaceOldValue = extract_claim(current_app.config, "metadata.initialize_flow.replace_values.old_value")
                initializeFlowReplaceNewValue = extract_claim(current_app.config, "metadata.initialize_flow.replace_values.new_value")

                if initializeFlowReplaceOldValue is not None and initializeFlowReplaceNewValue is not None:
                    numSostituizioni = app_state.ec_store.replace_in_all_value_fields(initializeFlowReplaceOldValue,initializeFlowReplaceNewValue)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: sostituite tutte le occorrenze di '{initializeFlowReplaceOldValue}' con '{initializeFlowReplaceNewValue}': {numSostituizioni}")
                
                override_credential_issuer_url = extract_claim(current_app.config, "metadata.initialize_flow.override_entity_configuration.openid_credential_issuer.credential_issuer")
                if override_credential_issuer_url:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.credential_issuer",override_credential_issuer_url)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.credential_issuer' è {override_credential_issuer_url}")
                
                override_credential_issuer_credential_endpoint = extract_claim(current_app.config, "metadata.initialize_flow.override_entity_configuration.openid_credential_issuer.credential_endpoint")
                if override_credential_issuer_credential_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.credential_endpoint",override_credential_issuer_credential_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.credential_endpoint' è {override_credential_issuer_credential_endpoint}")

                override_credential_issuer_nonce_endpoint = extract_claim(current_app.config, "metadata.initialize_flow.override_entity_configuration.openid_credential_issuer.nonce_endpoint")
                if override_credential_issuer_nonce_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.nonce_endpoint",override_credential_issuer_nonce_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.nonce_endpoint' è {override_credential_issuer_nonce_endpoint}")

                override_credential_issuer_status_assertion_endpoint = extract_claim(current_app.config, "metadata.initialize_flow.override_entity_configuration.openid_credential_issuer.status_assertion_endpoint")
                if override_credential_issuer_status_assertion_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.status_assertion_endpoint",override_credential_issuer_status_assertion_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.status_assertion_endpoint' è {override_credential_issuer_status_assertion_endpoint}")

                override_credential_issuer_status_attestation_endpoint = extract_claim(current_app.config, "metadata.initialize_flow.override_entity_configuration.openid_credential_issuer.status_attestation_endpoint")
                if override_credential_issuer_status_attestation_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.status_attestation_endpoint",override_credential_issuer_status_attestation_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.status_attestation_endpoint' è {override_credential_issuer_status_attestation_endpoint}")
            else:
                credentialFlowReplaceOldValue = extract_claim(current_app.config, "metadata.credential_flow.replace_values.old_value")
                credentialFlowReplaceNewValue = extract_claim(current_app.config, "metadata.credential_flow.replace_values.new_value")

                if credentialFlowReplaceOldValue is not None and credentialFlowReplaceNewValue is not None:
                    app_state.ec_store.replace_in_all_value_fields(credentialFlowReplaceOldValue,credentialFlowReplaceNewValue)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: sostituite tutte le occorrenze di '{credentialFlowReplaceOldValue}' con '{credentialFlowReplaceNewValue}'")

                override_credential_issuer_url = extract_claim(current_app.config, "metadata.credential_flow.override_entity_configuration.openid_credential_issuer.credential_issuer")
                if override_credential_issuer_url:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.credential_issuer",override_credential_issuer_url)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.credential_issuer' è {override_credential_issuer_url}")
                
                override_credential_issuer_credential_endpoint = extract_claim(current_app.config, "metadata.credential_flow.override_entity_configuration.openid_credential_issuer.credential_endpoint")
                if override_credential_issuer_credential_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.credential_endpoint",override_credential_issuer_credential_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.credential_endpoint' è {override_credential_issuer_credential_endpoint}")

                override_credential_issuer_nonce_endpoint = extract_claim(current_app.config, "metadata.credential_flow.override_entity_configuration.openid_credential_issuer.nonce_endpoint")
                if override_credential_issuer_nonce_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.nonce_endpoint",override_credential_issuer_nonce_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.nonce_endpoint' è {override_credential_issuer_nonce_endpoint}")

                override_credential_issuer_status_assertion_endpoint = extract_claim(current_app.config, "metadata.credential_flow.override_entity_configuration.openid_credential_issuer.status_assertion_endpoint")
                if override_credential_issuer_status_assertion_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.status_assertion_endpoint",override_credential_issuer_status_assertion_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.status_assertion_endpoint' è {override_credential_issuer_status_assertion_endpoint}")

                override_credential_issuer_status_attestation_endpoint = extract_claim(current_app.config, "metadata.credential_flow.override_entity_configuration.openid_credential_issuer.status_attestation_endpoint")
                if override_credential_issuer_status_attestation_endpoint:
                    app_state.ec_store.update_claim_by_path(entity_id, "metadata.openid_credential_issuer.status_attestation_endpoint",override_credential_issuer_status_attestation_endpoint)
                    logger.info(f"✅ Aggiornato in memoria l'Entity Configuration dell'entità {entity_id} di tipo {METADATA_TYPE_CREDENTIAL_ISSUER}: il nuovo valore del claim 'metadata.openid_credential_issuer.status_attestation_endpoint' è {override_credential_issuer_status_attestation_endpoint}")
                       
        if not pid_provider_ec:
            raise ValueError(f"Non trovata alcuna entità che rilascia credenziali di tipo {CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING}")
        
        pid_provider_url = extract_claim(pid_provider_ec, "iss")            
        if not pid_provider_url:
            raise ValueError(f"L'Entity Configuration dell'entità trovata che rilascia credenziali di tipo {CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING} non presenta il claim 'iss'")
            
        logger.info(f"✅ Trovata entità {pid_provider_url} che rilascia credenziali di tipo {CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING}")
        
        # Salvo in sessione il pid_provider_url estratto dall'EC individuato
        self.session["pid_provider_url"] = pid_provider_url
        
        # Generazione coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Fallita generazione coppia di chiavi pvt e pub del wallet")
        logger.debug(f"🔑🔑 Generate coppie di chiavi pvt e pub del wallet in formato PEM")
        
        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(f"ℹ️  Calcolato client id del wallet come thumbprint della sua chiave pvt: {wallet_client_id}")
        
        # Generazione Wallet Attestation PoP jwt
        logger.info("Generazione nuova Wallet Attestation PoP JWT per il wallet...")
        client_attestation_pop_jwt=generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key,
            audience=pid_provider_url
        )
        if not client_attestation_pop_jwt:
            raise ValueError("Fallita generazione Wallet Attestation PoP JWT")
        
        logger.info("📄 Wallet Attestation PoP JWT generata.")
        
        # Recupero wallet attestation JWT dalla memoria e se non presente la creo e la salvo in memoria
        wa_configuration_id = JWT_PREFIX+"_"+WALLET_ATTESTATION_NAME
        wallet_attestation_jwt = app_state.ec_store.get(wa_configuration_id)

        if not wallet_attestation_jwt:
            logger.info(f"⚠️  {wa_configuration_id} non presente nella memoria")
            
            wallet_attestation_jwt,  _ = self._wa_creation_management(trust_root_url, wallet_provider_url, wallet_public_key, wallet_provider_pvt_key_jwk_dict)
        else:
            logger.info(f"✅ {wa_configuration_id} trovata nella memoria")

            # controllo se non è scaduta
            wallet_provider_pub_key_jwk_dict = jwk_private_to_public(wallet_provider_pvt_key_jwk_dict)
            jwks_json = jwk_to_jwks(wallet_provider_pub_key_jwk_dict)
            try:
                wallet_attestation_jwt_claims = decode_and_verify_jwt(wallet_attestation_jwt, jwks_json)
                
                logger.info(f"✅ {wa_configuration_id} è risultata essere valida:")
                logger.info(json.dumps(wallet_attestation_jwt_claims, indent=2, ensure_ascii=False))

            except ValueError as ve:
                logger.error(f"❌ Fallita validazione {wa_configuration_id}: {ve}")
                wallet_attestation_jwt,  _ = self._wa_creation_management(trust_root_url, wallet_provider_url, wallet_public_key, wallet_provider_pvt_key_jwk_dict)

        # Generazione PKCE
        pkce = generate_pkce_pair()
        logger.info("🧪 PKCE Info")
        logger.info(f" 🔐 code_verifier: {pkce["code_verifier"]}")
        logger.info(f" 🧠 code_challenge: {pkce["code_challenge"]}")
        logger.info(f" 🔧 method: {pkce["code_challenge_method"]}")
        
        # Salvataggio in sessione del PKCE code verifier
        self.session["code_verifier"] = pkce["code_verifier"]
        
        # Generazione Request Object JWT per richiedere il PID
        logger.info("Generazione Request Object JWT per il wallet...")
        authorization_details = [
            {
                "type": "openid_credential",
                "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING
            }
        ]
        
        initialize_flow_response_type = extract_claim(current_app.config,"metadata.initialize_flow.response_type")
        initialize_flow_response_mode = extract_claim(current_app.config,"metadata.initialize_flow.response_mode")
        initialize_flow_redirect_uri = extract_claim(current_app.config,"metadata.initialize_flow.redirect_uri")
        
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
            authorization_details=authorization_details
        )
        if not request_object_jwt:
            raise ValueError("Fallita generazione Request Object JWT")
        
        logger.info("📄 Request Object JWT generato.")
        
        # recupero EC del pid provider dalla memoria
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.pushed_authorization_request_endpoint"
        pid_provider_as_par_url = extract_claim(pid_provider_ec, query_filter)
        
        logger.info(f"🚀 Invio PAR request al PAR endpoint {pid_provider_as_par_url}")
        
        # Effettua una par request                      
        as_par_response = request_as_par(
            url=pid_provider_as_par_url,
            wallet_attestation_jwt=wallet_attestation_jwt,
            wallet_attestation_dpop_jwt=client_attestation_pop_jwt,
            request_object_jwt=request_object_jwt,
            client_id=wallet_client_id,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"✅ Ricevuta risposta dal PAR endpoint {pid_provider_as_par_url}")
        logger.info(as_par_response)
        
        request_uri = as_par_response.get("request_uri")
        if not request_uri:
            raise ValueError("PAR Response non contiene un claim 'request_uri'")
        
        initialize_flow_idphint = extract_claim(current_app.config,f"metadata.initialize_flow.idphints.{idp}")
        logger.info(f"ℹ️  Selezionato idp {idp}: {initialize_flow_idphint}")
        
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
        
        logger.info(f"🌐 Apro il browser per inviare un'AUTHORIZE request all'AUTHORIZE endpoint del PID Provider: {authorization_url}")
            
        # Stampo i dati della sessione
        self._print_session_data()
        
        return {
            "success": True,
            "data": {
                "redirect_url": authorization_url
            }
        }
            
    def complete_initialize_wallet(self):
        """
        Metodo pubblico per completare l'Inizializzazione dell'IT Wallet.
        """
        logger.info(f"➡️  Richiesta di completamento dell'Inizializzazione del wallet")
        
        # Recupera la tipologia di credenziale da richiedere per l'inizializazzione del wallet dalla configurazione
        CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING = extract_claim(current_app.config,"metadata.initialize_flow.credential_configuration_id")
        
        # recupero selected_country dalla memoria
        country = app_state.selected_country
        
        # recupero wallet provider url dalla configurazione
        wallet_provider_url = extract_claim(current_app.config, "metadata.wallet_provider.id")
        
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
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_issuer"
        credential_issuer_url = extract_claim(pid_provider_ec, query_filter)

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
        redirect_uri = extract_claim(current_app.config,"metadata.initialize_flow.redirect_uri")

        # gestisco l'Authorization Response 
        authorization_response_code, _, _ = self._authorization_response_management(
            authorization_response=authorization_response, 
            state_expected=session_id, 
            iss_expected=pid_provider_url)

        # gestione rilascio dell'access token
        dpop_bound_access_token, credential_identifiers = self._token_issuing_management(
            wallet_provider_url=wallet_provider_url, 
            trust_root_url=trust_root_url, 
            authorization_server_url=authorization_server_url, 
            authorization_server_jwks=authorization_server_jwks,
            authorization_server_token_url=authorization_server_token_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            pkce_code_verifier=pkce_code_verifier,
            authorization_response_code=authorization_response_code,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING,
            redirect_uri=redirect_uri)

        # gestione rilascio della credenziale
        credential_id = self._credential_issuing_management(
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_status_assertion_url=credential_issuer_status_assertion_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token)   
    
        # Stampo i dati in sessione
        self._print_session_data()
        
        return {
            "success": True,
            "data": {
                "credential_id": credential_id
            }
        }
            
    def delete_credential_wallet(self, credential_id: str):
        """
        Metodo pubblico per rimuovere una credenziale dal proprio wallet.
        """
        logger.info(f"➡️  Richiesta di rimozione dal wallet della credenziale {credential_id} ")
        
        # Recupera la tipologia di credenziale riservata all'inizializazzione del wallet
        CREDENTIAL_CONFIGURATION_ID_FOR_INITIALIZING = extract_claim(current_app.config,"metadata.initialize_flow.credential_configuration_id")

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
        
            logger.info(f"ℹ️  La credenziale {credential_id} è presente nel wallet")
    
            # Rimuove una credenziale se esiste ricercandola per key.
            app_state.credential_store.remove(credential_id)
            
            logger.info(f"✅ Rimmossa dal wallet la credenziale {credential_id}")
        
        return {
            "success": True,
            "data": {
                "credential_id": credential_id,
                "wallet_initialized": app_state.wallet_initialized,
            }
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
        logger.info(f"➡️  Richiesta di aggiunta al wallet di una credenziale di tipo {credential_configuration_id}")
        logger.info(f"ℹ️  Nel wallet hai al momento: {app_state.credential_store.keys_with_vct()}")

        # Controlla se la credenziale richiesta è già presente nel wallet
        result = app_state.credential_store.find_by_prefix_with_key(credential_configuration_id)

        if result:
            raise ValueError(f"La credenziale {credential_configuration_id} è già presente nel wallet")
        
        logger.info(f"✅ La credenziale {credential_configuration_id} non è presente nel wallet")

        # recupero del response_mode relativo al credentialflow dalla configurazione e sua validazione
        credential_flow_response_mode = extract_claim(current_app.config,"metadata.credential_flow.response_mode")

        credential_flow_response_mode_supported = [AUTH_RESPONSE_MODE_QUERY, AUTH_RESPONSE_MODE_FORM_POST_JWT]
        if not credential_flow_response_mode in credential_flow_response_mode_supported:
            raise ValueError(f"Il response_mode '{credential_flow_response_mode}' configurato per il wallet non è supportato, i valori ammessi sono: {credential_flow_response_mode_supported}")
        
        # recupero del response_type relativo al credentialflow dalla configurazione e sua validazione
        credential_flow_response_type = extract_claim(current_app.config,"metadata.credential_flow.response_type")

        credential_flow_response_type_supported = [AUTH_RESPONSE_TYPE_CODE]
        if not credential_flow_response_type in credential_flow_response_type_supported:
            raise ValueError(f"Il response_type '{credential_flow_response_type}' configurato per il wallet non è supportato, i valori ammessi sono: {credential_flow_response_type_supported}")
                       
        # recupero del response_mode relativo al presentation flow dalla configurazione e sua validazione
        presentation_response_mode = extract_claim(current_app.config,"metadata.presentation_flow.response_mode")

        presentation_response_mode_supported = [PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT]
        if not presentation_response_mode in presentation_response_mode_supported:
            raise ValueError(f"Il response_mode '{presentation_response_mode}' configurato per la presentazione delle credenziali del wallet non è supportato, i valori ammessi sono: {presentation_response_mode_supported}")
        
        # recupero del response_type relativo al presentation flow dalla configurazione e sua validazione
        presentation_response_type = extract_claim(current_app.config,"metadata.presentation_flow.response_type")

        presentation_response_type_supported = [PRESENTATION_RESPONSE_TYPE_VP_TOKEN]
        if not presentation_response_type in presentation_response_type_supported:
            raise ValueError(f"Il response_type '{presentation_response_type}' configurato per l'inizializzazione del wallet non è supportato, i valori ammessi sono: {presentation_response_type_supported}")
        
        # recupero selected_country dalla memoria
        country = app_state.selected_country
        
        # recupero trust_root_url dalla configurazione
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)
        
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        
        logger.info(f"ℹ️  Trust root individuato per il paese {country}: {trust_root_url}")
        
        # recupero wallet provider url dalla configurazione
        wallet_provider_url = extract_claim(current_app.config, "metadata.wallet_provider.id")
        
        # Recupera chiave privata wallet JWK dalla configurazione
        wallet_provider_pvt_key_jwk_dict = extract_claim(current_app.config,"metadata.wallet_provider.key")
        
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_configurations_supported.{credential_configuration_id}"
        eaa_provider_ec_list = app_state.ec_store.all_values(query_filter)
        
        if not eaa_provider_ec_list:
            logger.error(f"❌ Nessun {METADATA_TYPE_CREDENTIAL_ISSUER} trovato che rilascia credenziali di tipo {credential_configuration_id}")
            raise ValueError(f"Nessun {METADATA_TYPE_CREDENTIAL_ISSUER} trovato che supporti credenziali di tipo {credential_configuration_id}")
                
        eaa_provider_url = extract_claim(eaa_provider_ec_list[0], "iss")            
        if not eaa_provider_url:
            raise ValueError(f"L'Entity Configuration dell'entità trovata che rilascia credenziali di tipo {credential_configuration_id} non presenta il claim 'iss'")
            
        logger.info(f"✅ Trovata entità {eaa_provider_url} che rilascia credenziali di tipo {credential_configuration_id}")
       
        # Salvo in sessione credential_configuration_id e eaa_provider_url 
        self.session["credential_configuration_id"] = credential_configuration_id
        self.session["eaa_provider_url"] = eaa_provider_url
        
        # Lettura coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Non è stato possibile leggere la coppia di chiavi pvt e pub del wallet")
        logger.debug(f"🔑🔑 Lettura coppie di chiavi pvt e pub del wallet in formato PEM")
        
        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(f"ℹ️  Calcolato client id del wallet come thumbprint della sua chiave pvt: {wallet_client_id}")
        
        # Generazione Wallet Attestation PoP jwt
        logger.info("Generazione nuova Wallet Attestation PoP JWT per il wallet...")
        client_attestation_pop_jwt=generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key,
            audience=eaa_provider_url
        )
        if not client_attestation_pop_jwt:
            raise ValueError("Fallita generazione Wallet Attestation PoP JWT")
        logger.info("📄 Wallet Attestation PoP JWT generata.")
        
        # Recupero wallet attestation JWT dalla memoria e se non presente la creo e la salvo in memoria
        wa_configuration_id = JWT_PREFIX+"_"+WALLET_ATTESTATION_NAME
        wallet_attestation_jwt = app_state.ec_store.get(wa_configuration_id)

        if not wallet_attestation_jwt:
            logger.info(f"⚠️  {wa_configuration_id} non presente nella memoria")
            
            wallet_attestation_jwt,  _ = self._wa_creation_management(trust_root_url, wallet_provider_url, wallet_public_key, wallet_provider_pvt_key_jwk_dict)
        else:
            logger.info(f"✅ {wa_configuration_id} trovata nella memoria")

            # controllo se non è scaduta
            wallet_provider_pub_key_jwk_dict = jwk_private_to_public(wallet_provider_pvt_key_jwk_dict)
            jwks_json = jwk_to_jwks(wallet_provider_pub_key_jwk_dict)
            try:
                wallet_attestation_jwt_claims = decode_and_verify_jwt(wallet_attestation_jwt, jwks_json)
                
                logger.info(f"✅ {wa_configuration_id} è risultata essere valida:")
                logger.info(json.dumps(wallet_attestation_jwt_claims, indent=2, ensure_ascii=False))

            except ValueError as ve:
                logger.error(f"❌ Fallita validazione {wa_configuration_id}: {ve}")
                wallet_attestation_jwt,  _ = self._wa_creation_management(trust_root_url, wallet_provider_url, wallet_public_key, wallet_provider_pvt_key_jwk_dict)
            
        # Generazione PKCE
        pkce = generate_pkce_pair()
        logger.info("🧪 PKCE Info")
        logger.info(f" 🔐 code_verifier: {pkce["code_verifier"]}")
        logger.info(f" 🧠 code_challenge: {pkce["code_challenge"]}")
        logger.info(f" 🔧 method: {pkce["code_challenge_method"]}")
        
        # Salvataggio in sessione del PKCE code verifier
        self.session["code_verifier"] = pkce["code_verifier"]
        
        # Generazione Request Object JWT per richiedere la credenziale
        logger.info("Generazione Request Object JWT per il wallet...")
        authorization_details = [
            {
                "type": "openid_credential",
                "credential_configuration_id": credential_configuration_id
            }
        ]
        
        credential_flow_response_type = extract_claim(current_app.config,"metadata.credential_flow.response_type")
        credential_flow_response_mode = extract_claim(current_app.config,"metadata.credential_flow.response_mode")
        credential_flow_redirect_uri = extract_claim(current_app.config,"metadata.credential_flow.redirect_uri")
        
        session_id = self.session.get("session_id")           
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        request_object_jwt = generate_request_object_jwt(
            issuer_private_key=wallet_private_key, 
            audience=eaa_provider_url,
            state=session_id,
            code_challenge=pkce["code_challenge"],
            code_challenge_method=pkce["code_challenge_method"],
            response_type=credential_flow_response_type,
            response_mode=credential_flow_response_mode,
            redirect_uri=credential_flow_redirect_uri,
            authorization_details=authorization_details
        )
        if not request_object_jwt:
            raise ValueError("Fallita generazione Request Object JWT")
        
        logger.info("📄 Request Object JWT generato.")
        
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.pushed_authorization_request_endpoint"
        eaa_provider_as_par_url = extract_claim(eaa_provider_ec_list[0], query_filter)
        
        logger.info(f"🚀 Invio PAR request al PAR endpoint: {eaa_provider_as_par_url}")
        
        # Effettua una par request                      
        as_par_response = request_as_par(
            url=eaa_provider_as_par_url,
            wallet_attestation_jwt=wallet_attestation_jwt,
            wallet_attestation_dpop_jwt=client_attestation_pop_jwt,
            request_object_jwt=request_object_jwt,
            client_id=wallet_client_id,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"✅ Ricevuta risposta dal PAR endpoint: {eaa_provider_as_par_url}")
        logger.info(as_par_response)
        
        request_uri = as_par_response.get("request_uri")
        if not request_uri:
            raise ValueError("PAR Response ricevuta dall'EAA Provider non contiene un claim 'request_uri'")
        
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.authorization_endpoint"
        eaa_provider_authorization_url = extract_claim(eaa_provider_ec_list[0], query_filter)
        
        # Build authorization query string
        params = {
            "client_id": wallet_client_id,
            "request_uri": request_uri,
        }
        authorization_query_string = f"?{urlencode(params)}"
        
        
        logger.info(f"🚀 Invio AUTHORIZE request all'AUTHORIZE endpoint {eaa_provider_authorization_url}")
        
        # Effettua un'authorize request verso l'authorization server dell'EAA Provider            
        authorize_response = request_authorize(
            url=eaa_provider_authorization_url,
            query_string=authorization_query_string,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"✅ Ricevuta risposta dall'AUTHORIZE endpoint {eaa_provider_authorization_url}")
        logger.info(authorize_response)
        
        # l'authorize response ricevuta l'authorization server dell'EAA Provider è in realtà la
        # Request_uri response trasmessa dal Verifier dell'EAA Provider
        if not is_jwt(authorize_response):
            raise ValueError(f"La Request_uri response del Relying Party / Verifier dell'EAA Provider ricevuta tramite lo stesso EAA Provider non contiene un JWT")
        
        # Recupero JWK da usare per validare il jwt
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_VERIFIER}.jwks"
        eaa_provider_verifier_jwks = extract_claim(eaa_provider_ec_list[0], query_filter)
        if not eaa_provider_verifier_jwks:
            raise ValueError(f"Non trovata in memoria alcuna chiave JWK dell'EAA Provider relativa al servizio {METADATA_TYPE_CREDENTIAL_VERIFIER}")
        
        logger.debug("🔑 JWKs trovato:")
        logger.debug(json.dumps(eaa_provider_verifier_jwks, indent=2, ensure_ascii=False))
        
        try:
            jwt_payload = decode_and_verify_jwt(authorize_response, eaa_provider_verifier_jwks)
            credentialsRequested, rp_state, rp_nonce, rp_response_uri = self._checkRelyingPartyAuthorizationRequest(jwt_payload, eaa_provider_url)

            logger.info("✅ Validato con successo il JWT contenuto nel Request_uri response dell'EAA Provider")
            logger.info(f"ℹ️  Questo JWT rappresenta la richiesta di autorizzazione che l'EAA Provider ha fatto al wallet per accedere a specifiche credenziali del wallet prima di rilasciargli la credenziale {credential_configuration_id} richiesta")            
            logger.info("📄 Request_uri response JWT payload:")
            logger.info(json.dumps(jwt_payload, indent=2, ensure_ascii=False))
        except ValueError as ve:
            raise ValueError(f"Fallita validazione del JWT contenuto nella Request_uri response dell'EAA Provider: {ve}")
        
        # Memorizzazione in sessione del relying party state, nonce e response_uri
        self.session["rp_state"] = rp_state
        self.session["rp_nonce"] = rp_nonce
        self.session["rp_response_uri"] = rp_response_uri
        
        return {
            "success": True,
            "data": credentialsRequested
        }
            
    def complete_add_credential_wallet(self, credentials_presenting: list[dict]):        
        """
        Metodo pubblico per completare l'aggiunta della credenziale
        """
        logger.info(f"➡️  Richiesta di completamento dell'operazione di aggiunta al wallet di una credenziale")
        
        logger.info(f"➡️  {credentials_presenting}")
            
        # recupero selected_country dalla memoria
        country = app_state.selected_country
        
        # recupero wallet provider url dalla configurazione
        wallet_provider_url = extract_claim(current_app.config, "metadata.wallet_provider.id")

        # recupero del response_mode relativo al credentialflow dalla configurazione
        credential_flow_response_mode = extract_claim(current_app.config,"metadata.credential_flow.response_mode")

        # recupero trust_root_url dalla memoria
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)
        
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        
        session_id = self.session.get("session_id")           
        if not session_id:
            raise ValueError("Sessione non inizializzata")
        
        # recupero credential_configuration_id dalla sessione
        credential_configuration_id = self.session.get("credential_configuration_id")
        if not credential_configuration_id:
            raise ValueError("Nessun credential_configuration_id trovato nella memoria") 
        
        # recupero code_verifier dalla sessione
        pkce_code_verifier = self.session.get("code_verifier")
        if not pkce_code_verifier:
            raise ValueError("Non trovato il PKCE code verifier nella sessione") 
        
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
        
        # recupero eaa provider url dalla sessione
        eaa_provider_url = self.session.get("eaa_provider_url")
        if not eaa_provider_url:
            raise ValueError("Non trovato l'URL dell'EAA provider nella sessione")
        
        # recupero EC dell'EAA provider dalla memoria usando come chiave di ricerca l'eaa provider url 
        eaa_provider_ec = app_state.ec_store.get(eaa_provider_url)
        if not eaa_provider_ec:
            raise ValueError(f"Non trovato in memoria l'Entity Configuration dell'entità {eaa_provider_url}")
        
        # recupero della URL dell'Authorization Server dall'EC
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.issuer"
        authorization_server_url = extract_claim(eaa_provider_ec, query_filter)
        
        # recupero del token endpoint dell'Authorization Server dall'EC
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.token_endpoint"
        authorization_server_token_url = extract_claim(eaa_provider_ec, query_filter)
        
        # recupero del jwks dell'Authorization Server dall'EC
        query_filter = f"metadata.{METADATA_TYPE_AUTHORIZATION_SERVER}.jwks"
        authorization_server_jwks = extract_claim(eaa_provider_ec, query_filter)

        # recupero della URL del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_issuer"
        credential_issuer_url = extract_claim(eaa_provider_ec, query_filter)

        # recupero del nonce endpoint del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.nonce_endpoint"
        credential_issuer_nonce_url = extract_claim(eaa_provider_ec, query_filter)

        # recupero del credential endpoint del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.credential_endpoint"
        credential_issuer_credential_url = extract_claim(eaa_provider_ec, query_filter)

        # recupero dello status assertion endpoint del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.status_assertion_endpoint"
        credential_issuer_status_assertion_url = extract_claim(eaa_provider_ec, query_filter)

        # recupero del jwks del Credential Issuer dall'EC
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_ISSUER}.jwks"
        credential_issuer_jwks = extract_claim(eaa_provider_ec, query_filter)
        
        # recupero redirect_uri dalla configurazione dell'app
        redirect_uri = extract_claim(current_app.config,"metadata.credential_flow.redirect_uri")
        
        # gestisco la fase di presentazione
        authorization_response = self._presentation_management(
            enc=False, 
            credentials_presenting=credentials_presenting, 
            rp_state=rp_state, 
            rp_nonce=rp_nonce, 
            rp_response_uri=rp_response_uri, 
            rp_jwks=authorization_server_jwks, 
            response_mode=credential_flow_response_mode) 
        
        # gestisco l'Authorization Response ritornato dalla fase di presentazione
        authorization_response_code, _, _ = self._authorization_response_management(
            authorization_response=authorization_response, 
            state_expected=session_id, 
            iss_expected=authorization_server_url)

        # gestione rilascio dell'access token
        dpop_bound_access_token, credential_identifiers = self._token_issuing_management(
            wallet_provider_url=wallet_provider_url, 
            trust_root_url=trust_root_url, 
            authorization_server_url=authorization_server_url, 
            authorization_server_jwks=authorization_server_jwks,
            authorization_server_token_url=authorization_server_token_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            pkce_code_verifier=pkce_code_verifier,
            authorization_response_code=authorization_response_code,
            credential_configuration_id=credential_configuration_id,
            redirect_uri=redirect_uri)

        # gestione rilascio della credenziale
        credential_id = self._credential_issuing_management(
            credential_issuer_nonce_url=credential_issuer_nonce_url,
            credential_issuer_credential_url=credential_issuer_credential_url,
            credential_issuer_status_assertion_url=credential_issuer_status_assertion_url,
            credential_issuer_jwks=credential_issuer_jwks,
            credential_configuration_id=credential_configuration_id,
            credential_identifiers=credential_identifiers,
            dpop_bound_access_token=dpop_bound_access_token)                                                                
        
        # Stampo i dati in sessione
        self._print_session_data()

        return {
            "success": True,
            "data": {
                "credential_id": credential_id
            }
        }
            
    def loginToVerifier(self, clientId: str, requestUri: str, requestUriMethod: str, state: str):
        """
        Metodo pubblico per effettuare il login ad un Relying Party / Verifier, incluso fetch dell'EC del Relying Party / Verifier.
        In sessione vengono salvati:
             self.session["rp_client_id"]
             self.session["rp_nonce"]
             self.session["rp_state"]
             self.session["rp_response_uri"]
        """
        logger.info(f"➡️  Richiesta di login presso il Relying Party / Verifier {clientId}")

        session_id = self.session.get("session_id")           
        if not session_id:
            raise ValueError("Sessione non inizializzata")

        # recupero del response_mode relativo al presentation flow dalla configurazione e sua validazione
        presentation_response_mode = extract_claim(current_app.config,"metadata.presentation_flow.response_mode")

        presentation_response_mode_supported = [PRESENTATION_RESPONSE_MODE_DIRECT_POST_JWT]
        if not presentation_response_mode in presentation_response_mode_supported:
            raise ValueError(f"Il response_mode '{presentation_response_mode}' configurato per la presentazione delle credenziali del wallet non è supportato, i valori ammessi sono: {presentation_response_mode_supported}")
        
        # recupero del response_type relativo al presentation flow dalla configurazione e sua validazione
        presentation_response_type = extract_claim(current_app.config,"metadata.presentation_flow.response_type")

        presentation_response_type_supported = [PRESENTATION_RESPONSE_TYPE_VP_TOKEN]
        if not presentation_response_type in presentation_response_type_supported:
            raise ValueError(f"Il response_type '{presentation_response_type}' configurato per l'inizializzazione del wallet non è supportato, i valori ammessi sono: {presentation_response_type_supported}")
        
        country = app_state.selected_country
        query_trust_root = f"ms_trust_configuration.{country}.trust_root"
        trust_root_url = extract_claim(current_app.config, query_trust_root)
        
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        
        logger.info(f"ℹ️  Trust root individuato per il paese {country}: {trust_root_url}")
        
        # recupero EC del verifier
        logger.info(f"➡️  Entity ID del Relying Party / Verifier: {clientId}")

        # Richiama il metodo privato per ottenere l'EC, validarlo e recuperne il payload
        external_verifier_ec = self._entity_configuration_management(clientId, [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_VERIFIER], trust_root_url)
                        
        logger.info(f"✅ Scaricato e validato l'Entity Configuration dell'entità {clientId} di tipo {METADATA_TYPE_CREDENTIAL_VERIFIER}")
        
        # Salvataggio in memoria Flask external_verifier_ec
        app_state.ec_store.add(clientId, external_verifier_ec)
        logger.info(f"✅ Salvato in memoria il payload dell'Entity Configuration dell'entità {clientId} di tipo {METADATA_TYPE_CREDENTIAL_VERIFIER}")
        
        # Build authorization query string
        params = {
            "client_id": clientId,
            "request_uri": requestUri,
            "request_uri_method": requestUriMethod,
            "state": state,
        }
        query_string = f"?{urlencode(params)}"
                
        logger.info(f"🚀 Invio Request_uri request al Request_uri endpoint {requestUri}")
        # Effettua una request_uri request                       
        request_uri_response = request_request_uri(
            url=requestUri,
            query_string=query_string,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"✅ Ricevuta risposta dal Request_uri endpoint {requestUri}")
        logger.info(request_uri_response)
        
        if not is_jwt(request_uri_response):
            raise ValueError(f"La Request_uri response ricevuta dal Relying Party / Verifier non è un JWT")
        
        # Recupero JWK da usare per validare il jwt
        query_filter = f"metadata.{METADATA_TYPE_CREDENTIAL_VERIFIER}.jwks"
        verifier_jwks = extract_claim(external_verifier_ec, query_filter)
        if not verifier_jwks:
            raise ValueError(f"Non trovata in memoria alcuna chiave JWK del Relying Party / Verifier {clientId}")
        
        logger.debug("🔑 JWKs trovato:")
        logger.debug(json.dumps(verifier_jwks, indent=2, ensure_ascii=False))
        
        try:
            request_uri_response_jwt_payload = decode_and_verify_jwt(request_uri_response, verifier_jwks)
            credentialsRequested, rp_state, rp_nonce, rp_response_uri = self._checkRelyingPartyAuthorizationRequest(request_uri_response_jwt_payload, clientId)
            
            logger.info(f"✅ Validato con successo il JWT contenuto nel Request_uri response del Relying Party / Verifier {clientId}")
            logger.info(f"ℹ️  Questo JWT rappresenta la richiesta di autorizzazione che il Relying Party / Verifier {clientId} ha fatto al wallet per accedere a specifiche credenziali del wallet prima di consentirgli di effettuare il login richiesto")            
            logger.info("📄 Request_uri response JWT payload:")
            logger.info(request_uri_response_jwt_payload)
        except ValueError as ve:
            raise ValueError(f"Fallita validazione del JWT contenuto nella Request_uri response del Relying Party / Verifier {clientId}: {ve}")
        
        # Memorizzazione dati in sessione
        self.session["rp_client_id"] = clientId
        self.session["rp_state"] = rp_state
        self.session["rp_nonce"] = rp_nonce
        self.session["rp_response_uri"] = rp_response_uri
        
        return {
            "success": True,
            "data": credentialsRequested
        }
            
    def complete_loginToVerifier(self, credentials_presenting: list[dict]):        
        """
        Metodo pubblico per completare il login ad un Verifier
            
        """        
            
        session_id = self.session.get("session_id")           
        if not session_id:
            raise ValueError("Sessione non inizializzata")
        
        # recupero id del Relying Party / Verifier dalla sessione
        rp_client_id  = self.session.get("rp_client_id")
        
        if not rp_client_id:
            raise ValueError("Non trovato l'URL del Relying Party / Verifier nella sessione") 
        
        logger.info(f"➡️  Richiesta di completamento dell'operazione di login presso il Relying Party / Verifier {rp_client_id} effettuata dal wallet")
        
        logger.info(f"➡️  {credentials_presenting}")

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
        logger.debug(json.dumps(rp_jwks, indent=2, ensure_ascii=False))

        # recupero del response_mode relativo al credentialflow dalla configurazione
        credential_flow_response_mode = extract_claim(current_app.config,"metadata.credential_flow.response_mode")
        
        authorizationResponse = self._presentation_management(
            enc=True, 
            credentials_presenting=credentials_presenting, 
            rp_state=rp_state, 
            rp_nonce=rp_nonce, 
            rp_response_uri=rp_response_uri, 
            rp_jwks=rp_jwks, 
            response_mode=credential_flow_response_mode) 
        
        logger.info(f"ℹ️  Prodotto messaggio di risposta per la richiesta di completamento dell'operazione di login presso il Relying Party / Verifiier {rp_client_id} effettuata dal wallet")
        logger.info(json.dumps(authorizationResponse, indent=2, ensure_ascii=False))

        # Stampo i dati in sessione
        self._print_session_data()

        return {
            "success": True
        }
    
    def _authorization_response_management(
            self,
            authorization_response: dict,
            state_expected: Optional[str] = None,
            iss_expected: Optional[str] = None
        ) -> Tuple[str,str,str]:
        if not authorization_response:
            raise ValueError("Nessun Authorization Response ricevuto") 
        
        logger.info(f"✅  Authorization Response ricevuto")

        authorization_response_code = authorization_response.get("code")
        authorization_response_state = authorization_response.get("state")
        authorization_response_iss = authorization_response.get("iss")
        authorization_response_error = authorization_response.get("error")
        authorization_response_error_description = authorization_response.get("error_description")
        
        logger.info(f"- code: {authorization_response_code}")
        logger.info(f"- state: {authorization_response_state}")
        logger.info(f"- iss: {authorization_response_iss}")
        logger.info(f"- error: {authorization_response_error}")
        logger.info(f"- error_description: {authorization_response_error_description}")
        
        if state_expected is not None and authorization_response_state != state_expected:
            raise ValueError(f"Il parametro 'state' dell'Authorization Response ricevuto non è valido: atteso '{state_expected}', trovato '{authorization_response_state}'")

        if authorization_response_error:
            raise ValueError(f"L'Authorization Response ricevuto presenta l'errore: {authorization_response_error} {authorization_response_error_description}")
        else:        
            if not authorization_response_code:
                raise ValueError("L'Authorization Response ricevuto non presenta il parametro 'code")
            
            if iss_expected is not None and authorization_response_iss != iss_expected:
                raise ValueError(f"Il parametro 'iss' dell'Authorization Response ricevuto non è valido: atteso '{iss_expected}', trovato '{authorization_response_iss}'")
            
        return authorization_response_code, authorization_response_state, authorization_response_iss
    
    def _wa_creation_management(self, trust_root_url: str, wallet_provider_url: str, wallet_public_key: EllipticCurvePublicKey, wallet_provider_pvt_key_jwk_dict: dict) -> Tuple[str,str]:
        wallet_provider_pvt_key = ec_private_key_from_pem_bytes(pem_private_key_from_jwk_dict(wallet_provider_pvt_key_jwk_dict))
        if not wallet_provider_pvt_key:
            raise ValueError("Fallita conversione della chiave privata del wallet provider dal formato JWK al formato PEM")
        logger.debug(f"🔑 Covertita la chiave privata del wallet provider dal formato JWK al formato PEM")
        
        # Generazione Wallet Attestation in formato jwt
        wallet_attestation_configuration_id = JWT_PREFIX+"_"+WALLET_ATTESTATION_NAME
        wallet_attestation_vct = None

        logger.info(f"Generazione nuova Wallet Attestation {wallet_attestation_configuration_id} per il wallet...")

        wallet_attestation_jwt=generate_wallet_attestation_jwt(
            issuer_private_key=wallet_provider_pvt_key,
            client_public_key=wallet_public_key,
            issuer=wallet_provider_url,
            aal=AAL_VALUE_HIGH
        )
        if not wallet_attestation_jwt:
            raise ValueError(f"Fallita generazione Wallet Attestation {wallet_attestation_configuration_id}")
        
        # Memorizzazione nella memoria della Wallet Attestation JWT
        app_state.credential_store.add(
            wallet_attestation_configuration_id, 
            wallet_attestation_jwt,
            wallet_attestation_vct
        )

        logger.info(f"✅ Wallet Attestation {wallet_attestation_configuration_id} generata e salvata nella memoria.")
        
        # Generazione Wallet Attestation in formato sd-jwt
        wallet_attestation_configuration_id = SD_JWT_PREFIX+"_"+WALLET_ATTESTATION_NAME

        logger.info(f"Generazione nuova Wallet Attestation {wallet_attestation_configuration_id} per il wallet...")

        spec_version = extract_claim(current_app.config, "metadata.spec_version")
        wallet_attestation_vct = trust_root_url+"/vct/"+spec_version+"/"+WALLET_ATTESTATION_NAME

        wallet_attestation_sd_jwt=generate_wallet_attestation_sd_jwt(
            vct=wallet_attestation_vct,
            issuer_private_key=wallet_provider_pvt_key,
            client_public_key=wallet_public_key,
            issuer=wallet_provider_url,
            aal=AAL_VALUE_HIGH
        )
        if not wallet_attestation_sd_jwt:
            raise ValueError(f"Fallita generazione Wallet Attestation {wallet_attestation_configuration_id}")
        
        # Memorizzazione nella memoria della Wallet Attestation in formato sd-jwt
        app_state.credential_store.add(
            wallet_attestation_configuration_id, 
            wallet_attestation_sd_jwt,
            wallet_attestation_vct
        )
        
        logger.info(f"✅ Wallet Attestation {wallet_attestation_configuration_id} generata e salvata nella memoria.")
        
        return wallet_attestation_jwt, wallet_attestation_sd_jwt

    def _token_issuing_management(self, wallet_provider_url: str, trust_root_url: str, authorization_server_url: str, authorization_server_jwks: dict, authorization_server_token_url: str, credential_issuer_credential_url: str, pkce_code_verifier: str, authorization_response_code: str, credential_configuration_id: str, redirect_uri: str) -> Tuple[str,list]:                
            
        # Generazione/letturia coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Fallita generazione coppia di chiavi pvt e pub del wallet")
        
        logger.debug(f"🔑🔑 Generate coppie di chiavi pvt e pub del wallet in formato PEM")
        
        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(f"ℹ️  Calcolato client id del wallet come thumbprint della sua chiave pvt: {wallet_client_id}")
        
        # Generazione Wallet Attestation PoP jwt
        logger.info("Generazione nuova Wallet Attestation PoP JWT per il wallet...")
        client_attestation_pop_jwt=generate_wallet_attestation_pop_jwt(
            private_key=wallet_private_key,
            audience=authorization_server_url
        )
        logger.info("📄 Wallet Attestation PoP JWT generata.")
        
        # Recupera chiave privata wallet provider dalla configurazione del wallet
        wallet_provider_pvt_key_jwk_dict = extract_claim(current_app.config,"metadata.wallet_provider.key")
        if not wallet_provider_pvt_key_jwk_dict:
            raise ValueError("Fallito recupero della chiave privata JWK del wallet provider")
        logger.debug(f"🔑 Recuperata chiave privata del wallet provider in formato JWK")
            
        # Recupero wallet attestation JWT dalla memoria e se non presente la creo e la salvo in memoria
        wa_configuration_id = JWT_PREFIX+"_"+WALLET_ATTESTATION_NAME
        wallet_attestation_jwt = app_state.ec_store.get(wa_configuration_id)

        if not wallet_attestation_jwt:
            logger.info(f"⚠️  {wa_configuration_id} non presente nella memoria")
            
            wallet_attestation_jwt,  _ = self._wa_creation_management(trust_root_url, wallet_provider_url, wallet_public_key, wallet_provider_pvt_key_jwk_dict)
        else:
            logger.info(f"✅ {wa_configuration_id} trovata nella memoria")

            # controllo se non è scaduta
            wallet_provider_pub_key_jwk_dict = jwk_private_to_public(wallet_provider_pvt_key_jwk_dict)
            wallet_provider_jwks_json = jwk_to_jwks(wallet_provider_pub_key_jwk_dict)
            try:
                wallet_attestation_jwt_claims = decode_and_verify_jwt(wallet_attestation_jwt, wallet_provider_jwks_json)
                                
                logger.info(f"✅ {wa_configuration_id} è risultata essere valida:")
                logger.info(json.dumps(wallet_attestation_jwt_claims, indent=2, ensure_ascii=False))
                
            except ValueError as ve:
                logger.error(f"❌ Fallita validazione {wa_configuration_id}: {ve}")
                wallet_attestation_jwt,  _ = self._wa_creation_management(trust_root_url, wallet_provider_url, wallet_public_key, wallet_provider_pvt_key_jwk_dict)

        # Generazione DPoP for the Token Endpoint 
        logger.info(f"Generazione DPoP JWT per il wallet da presentare al TOKEN endpoint {authorization_server_token_url}...")
        dpop_token_request = generate_dpop_jwt(
            issuer_private_key=wallet_private_key,
            http_method="POST",
            http_url=authorization_server_token_url
        )
        logger.info("📄 DPoP JWT generato.")

        logger.info(f"🚀 Invio TOKEN request al TOKEN endpoint {authorization_server_token_url}")
        # Effettua una token request                    
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
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"✅ Ricevuta risposta dal TOKEN endpoint {authorization_server_token_url}")
        logger.info(token_response)
            
        token_type = token_response.get("token_type")
        if not token_type:
            raise ValueError("TOKEN Response non contiene un claim 'token_type'")
        
        if token_type != "DPoP":
            raise ValueError("TOKEN Response contiene un claim 'token_type' diverso da 'DPoP'")
        
        dpop_bound_access_token = token_response.get("access_token")
        if not dpop_bound_access_token:
            raise ValueError("TOKEN Response non contiene un claim 'access_token'")
        
        authorization_details_claim = token_response.get("authorization_details")
        if not authorization_details_claim:
            raise ValueError("TOKEN Response non contiene un claim 'authorization_details'")
        
        expires_in = token_response.get("expires_in")
        if not expires_in:
            raise ValueError("TOKEN Response non contiene un claim 'expires_in'")
        
        # Controllo Access Token
        try:
            dpop_bound_access_token_claims = decode_and_verify_jwt(dpop_bound_access_token, authorization_server_jwks)            
            self._checkAccessToken(
                jsonContent=dpop_bound_access_token_claims, 
                expected_issuer_url=authorization_server_url, 
                expected_clientId=wallet_client_id, 
                expected_cnf_jkt_value=wallet_client_id)
            
            logger.info(f"✅ L'access token contenuto nella TOKEN Response è risultato essere valido")
            logger.info("📄 Access token payload:")
            logger.info(json.dumps(dpop_bound_access_token_claims, indent=2, ensure_ascii=False))
        except ValueError as ve:
            raise ValueError(f"Fallita validazione dell'access token contenuto nella TOKEN Response: {ve}")

        # Estrai tutti i credential_identifiers da tutti i dettagli
        all_identifiers = [
            identifier
            for detail in authorization_details_claim
            for identifier in detail.get('credential_identifiers', [])
        ]
        
        logger.info(f"ℹ️  L'access token contenuto nella TOKEN Response consente di richiedere i credential identifiers: {all_identifiers}")
            
        # Estrai solo gli identifiers per uno specifico credential_configuration_id
        matching_identifiers = next(
            (
                detail.get('credential_identifiers', [])
                for detail in authorization_details_claim
                if detail.get('credential_configuration_id') == credential_configuration_id
            ),
            []  # default se non trovato
        )
                    
        if not matching_identifiers:
            logger.error(f"❌ Nessun credential identifiers trovato nella TOKEN Response che appartiene al credential configuration id '{credential_configuration_id}' richiesto nella PAR Request")
            raise ValueError(f"L'access token contenuto nella TOKEN Response non consente di richiedere alcun credential identifiers appartenente al credential configuration id '{credential_configuration_id}' richiesto nella PAR Request")

        logger.info(f"ℹ️  Il numero di credential identifiers che appartengono al credential configuration id '{credential_configuration_id}' richiesto nella PAR Request è {len(matching_identifiers)}")
        
        return dpop_bound_access_token, matching_identifiers
    
    def _credential_issuing_management(self, credential_issuer_nonce_url: str, credential_issuer_credential_url: str, credential_issuer_status_assertion_url: str, credential_issuer_jwks: dict, credential_configuration_id: str, credential_identifiers: list, dpop_bound_access_token: str) -> str:                        
        # Generazione/letturia coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Fallita generazione coppia di chiavi pvt e pub del wallet")
        
        logger.debug(f"🔑🔑 Generate coppie di chiavi pvt e pub del wallet in formato PEM")
        
        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(f"ℹ️  Calcolato client id del wallet come thumbprint della sua chiave pvt: {wallet_client_id}")
        
        last_valid_credential = None
        last_valid_credential_claims = None
            
        # Itera su ogni credential_identifiers dentro l'array
        for index, credential_id in enumerate(credential_identifiers, start=1):   
            logger.info(f"🚀 Invio NONCE request al NONCE endpoint {credential_issuer_nonce_url}")
            # Effettua una nonce request                        
            nonce_response = request_nonce(
                url=credential_issuer_nonce_url,
                proxies=self.proxies,
                no_proxy_domains=self.no_proxy_domains
            )
            
            logger.info(f"✅ Ricevuta risposta dal NONCE endpoint {credential_issuer_nonce_url}")
            logger.info(nonce_response)
            
            logger.info("Generazione proof JWT per il walletda da presentare al CREDENTIAL endpoint {credential_issuer_credential_url}...")
            proof_jwt = generate_proof_jwt(
                issuer_private_key=wallet_private_key,
                audience=credential_issuer_credential_url,
                nonce=nonce_response
            )
            logger.info("📄 proof JWT generato.") 
            logger.info(proof_jwt)
            
            # Generazione DPoP for the Token Endpoint 
            logger.info(f"Generazione DPoP JWT per il wallet da presentare al CREDENTIAL endpoint {credential_issuer_credential_url}...")
        
            dpop_credential_request = generate_dpop_jwt(
                issuer_private_key=wallet_private_key,
                http_method="POST",
                http_url=credential_issuer_credential_url,
                access_token=dpop_bound_access_token
            )
            logger.info("📄 DPoP JWT generato.")
            logger.info(dpop_credential_request)
            
            logger.info(f"🚀 Invio CREDENTIAL request al CREDENTIAL endpoint {credential_issuer_credential_url}")
            # Effettua una credential request             
            credential_response = request_credential(
                url=credential_issuer_credential_url,
                credential_id=credential_id,
                proof_jwt=proof_jwt,
                access_token=dpop_bound_access_token,
                dpop_proof_jwt=dpop_credential_request,
                proxies=self.proxies,
                no_proxy_domains=self.no_proxy_domains
            )
            
            credentials = credential_response.get("credentials", [])
            
            if not credentials:
                raise ValueError("Nessuna credenziale rilasciata")

            # Creiamo una lista con le credenziali "accorciate" per il logging
            short_credentials = []

            for c in credentials:
                credential_str = c.get("credential", "")
                short_credential = credential_str[:80] + "..." if len(credential_str) > 80 else credential_str
                short_credentials.append({"credential": short_credential})
            
            logger.info(f"✅ Ricevuta risposta dal CREDENTIAL endpoint {credential_issuer_credential_url}")
            logger.info({
                "credentials": short_credentials
            })
            logger.info(f"📦 Numero di credenziali contenute nella risposta del CREDENTIAL endpoint: {len(short_credentials)}")
            
            # Itera su ogni oggetto JSON dentro l'array
            for index, cred in enumerate(credentials, start=1):
                logger.info(f"🔍 Verifico Credenziale #{index}")
                
                credential = cred.get("credential")
                if not credential:
                    logger.info(f"⚠️ Contenuto della credenziale {index} mancante o non valido.")
                    continue
                    
                if credential_id.startswith(SD_JWT_PREFIX):                
                    # Decodifica e valida la credenziale               
                    claims = decode_and_verify_sd_jwt(
                        sd_jwt_compact=credential, 
                        jwks=credential_issuer_jwks)
                    
                    claims_to_log = copy.deepcopy(claims)
                    
                    portrait = claims_to_log.get("portrait")
                    if portrait and isinstance(portrait, str) and len(portrait) > 80:
                        claims_to_log["portrait"] = portrait[:80] + "..."
                    portrait = claims_to_log.get("portrait")
                    if portrait and isinstance(portrait, str) and len(portrait) > 80:
                        claims_to_log["portrait"] = portrait[:80] + "..."
                    
                    content = claims_to_log.get("content")
                    if content and isinstance(content, str) and len(content) > 80:
                        claims_to_log["content"] = content[:80] + "..."

                    logger.info(f"✅ Credenziale #{index} è risultata essere valida:")
                    logger.info(json.dumps(claims_to_log, indent=2, ensure_ascii=False))
                    
                    # memorizza l'ultima valida decodificata
                    last_valid_credential = credential
                    last_valid_credential_vct = claims.get("vct","")
                    last_valid_credential_claims = claims
                elif credential_id.startswith(MSO_MDOC_PREFIX):
                    # Decodifica e valida la credenziale
                    expected_docType = ISO_18013_5_NAME + "." +credential_configuration_id.removeprefix(MSO_MDOC_PREFIX+"_")
                    expected_namespaces = {ISO_18013_5_NAME, ISO_18013_5_NAME + ".IT"}
                    result_json = decode_and_verify_issuer_signed(
                        issuer_signed_base64_url=credential, 
                        expected_namespaces=expected_namespaces, 
                        expected_version=ISO_18013_5_VERSION, 
                        expected_doc_type=expected_docType)  
                    
                    logger.info(f"✅ Credenziale #{index} è risultata essere valida:")
                    logger.info(json.dumps(result_json, indent=4, ensure_ascii=False))
                    
                    # memorizza l'ultima valida decodificata
                    last_valid_credential = credential
                    last_valid_credential_vct = expected_docType
                    last_valid_credential_claims = result_json
            
        if last_valid_credential and last_valid_credential_claims:
            
            # Salvataggio credenziale nel credential store presente in memoria Flask
            app_state.wallet_initialized = True
            app_state.credential_store.add(
                credential_id, 
                last_valid_credential,
                last_valid_credential_vct,
                last_valid_credential_claims
            )
             
            logger.info(f"✅ Salvata in memoria credenziale {credential_id}")
            
            if credential_id.startswith(SD_JWT_PREFIX):
                try:
                    # recupero status assertion
                    self._status_assertion_management(credential_issuer_status_assertion_url, credential_issuer_jwks, credential_id, credential)
                except Exception as e:
                    logger.warning(f"⚠️  Non è stato possibile recuperare la status assertion per la credenziale {credential_id}: {e}")
                
            return credential_id
        else:
            logger.info(f"❌ Nessuna credenziale valida ricevuta")
            raise ValueError("Nessuna credenziale valida ricevuta")
        
    def _status_assertion_management(self, credential_issuer_status_assertion_url: str, credential_issuer_jwks: dict, credential_id: str, sd_jwt_compact: str):      
        # Generazione/letturia coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Fallita generazione coppia di chiavi pvt e pub del wallet")
        
        logger.debug(f"🔑🔑 Generate coppie di chiavi pvt e pub del wallet in formato PEM")
                       
        idx = sd_jwt_compact.find("~")
        credential_before_tilde = sd_jwt_compact if idx == -1 else sd_jwt_compact[:idx]
    
        # Calcolo dell'hash SHA-256 sulla credenziale senza le disclosure
        signature_hash = hashlib.sha256(credential_before_tilde.encode("utf-8")).digest()
    
        # Generazione Status Assertion Request JWT per richiedere la Status Assertion della credenziale            
        logger.info(f"Generazione Status Assertion Request JWT per richiedere al Credential Issuer la Status Assertion della credenziale {credential_id}...")
        status_assertion_request_object_jwt=generate_status_assertion_request_object_jwt(
            issuer_private_key=wallet_private_key,
            audience=credential_issuer_status_assertion_url,
            credential_hash=signature_hash.hex(),
            credential_hash_alg="sha-256"
        )
        
        if not status_assertion_request_object_jwt:
            raise ValueError("Fallita generazione Status Assertion Request JWT")
        logger.info("📄 Status Assertion Request JWT generato.")
        
        status_assertion_request_object_jwt_list: list[str] = [status_assertion_request_object_jwt]
        
        logger.info(f"🚀 Invio STATUS request allo STATUS ASSERTION endpoint {credential_issuer_status_assertion_url}")
        # Effettua una status request            
        status_response = request_status(
            url=credential_issuer_status_assertion_url,
            status_assertion_requests=status_assertion_request_object_jwt_list,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
    
        logger.info(f"✅ Ricevuta risposta dallo STATUS ASSERTION endpoint {credential_issuer_status_assertion_url}")
        logger.info(status_response)
        
        status_assertion_responses = status_response.get("status_assertion_responses")
        if not status_assertion_responses:
            raise ValueError("STATUS Response non contiene un claim 'status_assertion_responses'")
        
        logger.info(f"📦 Numero di Status Assertion Response ricevute: {len(status_assertion_responses)}")
        
        last_valid_statusAssertionResponse_jwt = None
        last_valid_statusAssertionResponse_claims = None
            
        # Itera su ogni oggetto JSON dentro l'array
        for index, statusAssertionResponse in enumerate(status_assertion_responses, start=1):
            logger.info(f"🔍 Verifico Status Assertion Response #{index}")
            
            try:
                statusAssertionResponse_claims = decode_and_verify_jwt(statusAssertionResponse, credential_issuer_jwks)

                logger.info(f"✅ Lo Status Assertion Response #{index} è risultata essere valido:")
                logger.info(json.dumps(statusAssertionResponse_claims, indent=2, ensure_ascii=False))

                last_valid_statusAssertionResponse_jwt = statusAssertionResponse
                last_valid_statusAssertionResponse_claims = statusAssertionResponse_claims
            except ValueError as ve:
                raise ValueError(f"Fallita validazione dello Status Assertion Response: {ve}")
                
        if last_valid_statusAssertionResponse_jwt and last_valid_statusAssertionResponse_claims:               
            last_valid_statusAssertionResponse_claims_error = last_valid_statusAssertionResponse_claims.get("error","")
            if last_valid_statusAssertionResponse_claims_error:
                raise ValueError(f"La Status Assertion Response ricevuta ha rilevato l'errore: {last_valid_statusAssertionResponse_claims_error}")
        else:
            logger.info(f"❌ Nessuna Status Assertion Response valida ricevuta")
            raise ValueError("Nessuna Status Assertion Response valida ricevuta")
        
        credential_status = last_valid_statusAssertionResponse_claims.get("credential_status_type","")
            
        # Update status della credenziale nel credential store presente in memoria Flask 
        app_state.credential_store.update_status(
            credential_id, 
            last_valid_statusAssertionResponse_jwt,
            credential_status
        )
        
        logger.info(f"✅ Impostato in memoria lo stato della credenziale {credential_id} pari a {credential_status}")
        
    def _presentation_management(self, enc: bool, credentials_presenting: list[dict], rp_state: str, rp_nonce: str, rp_response_uri: str, rp_jwks: dict, response_mode: str) -> dict:                               
                
        # recupero dello status_assertion_supported relativo al presentation flow dalla configurazione
        presentation_status_assertion_supported = extract_claim(current_app.config,"metadata.presentation_flow.status_assertion_supported")
        
        # Lettura coppia di chiavi pvt e pub del wallet
        wallet_private_key, wallet_public_key = self._inizializza_wallet_keys(CONFIG_DIR)
        if not wallet_private_key or not wallet_public_key:
            raise ValueError("Non è stato possibile leggere la coppia di chiavi pvt e pub del wallet")
        logger.debug(f"🔑🔑 Lettura coppie di chiavi pvt e pub del wallet in formato PEM")

        # Converti la chiave privata in JWK dict
        wallet_private_key_jwk = priv_ec_key_obj_to_jwk(wallet_private_key)
        wallet_private_key_jwk_dict = wallet_private_key_jwk.export(as_dict=True)
        
        # Calcola client_id (thumbprint)
        wallet_client_id = get_thumbprint_from_private_key(wallet_private_key)
        logger.debug(f"ℹ️  Calcolato client id del wallet come thumbprint della sua chiave pvt: {wallet_client_id}")
        
        vp_token_claims = {}
        
        # Creo presentazione per ogni credenziale definita in credentials_presenting
        for item in credentials_presenting:
            result = self._find_credential_by_dcql_item(item)
            if result:
                key, value = result
                logger.info(f"✅ Recuperata la credenziale che è stata richiesta al wallet di presentare")
                
                vct = value.get("vct", "")
                status = value.get("status", "")
                statusDecr = get_status_description(status)
                logger.info(f"ℹ️  La credenziale {vct} recuperata è in stato: {status} {statusDecr}")
                
                sd_jwt_credential = value.get("data_row", None)
                
                # Estrai tutti i claim path
                credential_presenting_claim_paths = [claim["path"][0] for claim in item.get("claims", []) if claim.get("path")]
                logger.info(f"ℹ️  Claims richiesti per la presentazione della credenziale {vct} recuperata: {credential_presenting_claim_paths}")
            
                claim_paths_nested = paths_to_nested_dict(credential_presenting_claim_paths)
            
                sd_jwt_credential_presentation = present_sd_jwt(
                    vct=vct,
                    sd_jwt_compact=sd_jwt_credential,
                    aud=rp_response_uri, 
                    nonce=rp_nonce, 
                    claims_to_reveal=claim_paths_nested,
                    holder_private_jwk_dict=wallet_private_key_jwk_dict)
            
                if sd_jwt_credential_presentation:
                    logger.info(f"🧾  Inserito nel vp_token la presentazione prodotta della credenziale {vct} recuperata")
                    vp_token_claims[item['id']] = sd_jwt_credential_presentation
                    
                    if presentation_status_assertion_supported:
                        # controllo se dispongo in memoria anche della status_assertion e in caso positivo l'aggiungo
                        sd_jwt_credential_status_assertion = value.get("status_assertion", None)
                        if sd_jwt_credential_status_assertion:
                            vp_token_claims[item['id']+"_status"] = sd_jwt_credential_status_assertion
                            logger.info(f"🧾  Inserito nel vp_token anche la status assertion della credenziale {vct}")
                        else:
                            logger.info(f"ℹ️  Nel vp_token non è stata inserita la status assertion della credenziale {vct} perchè non presente nel wallet")                    
                    else:
                        logger.info(f"ℹ️  Nel vp_token non è stata inserita la status assertion della credenziale {vct} come indicato nella configurazione del wallet")
        
        if len(vp_token_claims) == 0:
            raise ValueError("vp_token prodotto non presenta alcun claim")

        logger.info("✅ Generato vp_token:")
        logger.info(vp_token_claims)
        
        # Genera response uri request jwt
        response_uri_request_jwt = None
        
        if enc:
            enc_key_jwk = extract_key_for_enc(rp_jwks)
            
            if not enc_key_jwk:
                logger.error("❌ Non trovatave la chiave per firmare il JWE contenente il vp_token")
                raise ValueError("Non trovatave la chiave per firmare il JWE contenente il vp_token")
            
            logger.info("Generazione Response_uri request JWE...")
            
            response_uri_request_jwt = generate_response_uri_request_jwe(
                enc_key_json_str=enc_key_jwk,
                vp_token=vp_token_claims,
                state=rp_state
            )
            
            if not response_uri_request_jwt:
                raise ValueError("Fallita generazione Response_uri request JWE")
            
            logger.info("✅ Generato Response_uri request JWE.")
        else:
            logger.info("Generazione Response_uri request JWS...")
            
            response_uri_request_jwt = generate_response_uri_request_jws(
                private_key=wallet_private_key,
                vp_token=vp_token_claims,
                state=rp_state
            )
            
            if not response_uri_request_jwt:
                raise ValueError("Fallita generazione Response_uri request JWS")
            
            logger.info("✅ Generato Response_uri request JWS.")       
            
        # Effettua una response uri request
        logger.info(f"🚀 Invio Response_uri request al Response_uri endpoint {rp_response_uri}")
        response_uri_response = request_response_uri(
            url=rp_response_uri,
            response_uri_request_jwt=response_uri_request_jwt,
            state=rp_state,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        logger.info(f"✅ Ricevuta risposta dal Response_uri endpoint {rp_response_uri}")   
        logger.info(response_uri_response)
        
        redirect_uri = response_uri_response.get("redirect_uri")
        if redirect_uri:
            logger.info(f"✅  La Response_uri response ricevuta dal Response_uri endpoint {rp_response_uri} del Relying Party / Verifier contiene un redirect_uri pari a: {redirect_uri}")
            
            # Effettua la richiesta alla callback
            logger.info(f"🚀 Invio un messaggio di richiesta al redirect_uri {redirect_uri}")
            callback_response = request_presentation_callback(
                url=redirect_uri,
                proxies=self.proxies,
                no_proxy_domains=self.no_proxy_domains
            )

            logger.info(f"✅ Ricevuta dal redirect_uri {redirect_uri} la seguente risposta:")
            logger.info(callback_response)

            if response_mode == AUTH_RESPONSE_MODE_FORM_POST_JWT:      
                # Parse HTML
                soup = BeautifulSoup(callback_response, "html.parser")
                
                # Trova l'input nascosto con nome 'response'
                response_input = soup.find("input", {"type": "hidden", "name": "response"})
                
                # Estrai il valore
                if response_input and response_input.has_attr("value"):
                    response_input_value = response_input["value"]
                    logger.info(f"🔍 Valore del campo 'response' estratto dalla pagina HTML ricevuta in riposta dal redirect_uri {redirect_uri}: {response_input_value}")
                else:
                    raise ValueError(f"La pagina HTML ricevuta in riposta dal redirect_uri {redirect_uri} non contiene alcun campo 'response'")
            
                if not is_jwt(response_input_value):
                    raise ValueError(f"Il valore del campo 'response' estratto dalla pagina HTML ricevuta in riposta dal redirect_uri {redirect_uri} non è un JWT")

                try:
                    response_value_payload = decode_and_verify_jwt(response_input_value, rp_jwks)

                    logger.info(f"✅ Il JWT estratto dalla pagina HTML ricevuta in riposta dal redirect_uri {redirect_uri} è risultato essere valido")
                    logger.info(f"✅ La fase di presentazione si è conclusa positivamente")
                    logger.info("📄 Il risultato è il payload del JWT estratto:")
                    logger.info(json.dumps(response_value_payload, indent=2, ensure_ascii=False))
                    return response_value_payload
                except ValueError as ve:
                    raise ValueError(f"Fallita validazione del JWT nella pagina HTML contenuta nella redirect_uri {redirect_uri}: {ve}")
            
            else:
                # Converte la query string del redirect_uri in un dizionario
                parsed_callback_response = urlparse(callback_response)
                query_params = parse_qs(parsed_callback_response.query)

                # Converti da lista a singolo valore
                query_params_single = {k: v[0] if v else "" for k, v in query_params.items()}
                
                logger.info(f"✅ La fase di presentazione si è conclusa positivamente")

                logger.info("📄 Il risultato è il seguente JSON:")
                logger.info(json.dumps(query_params_single, indent=2, ensure_ascii=False))
                return query_params_single
        else:
            logger.warning(f"⚠️  Nessun 'redirect_uri' definito nella Response_uri response ricevuta dal Response_uri endpoint {rp_response_uri} del Relying Party / Verifier")
            logger.info(f"✅ La fase di presentazione si è conclusa positivamente")

            logger.info("📄 Il risultato è il seguente JSON:")
            logger.info(json.dumps(response_uri_response, indent=2))
            return response_uri_response
      
    def _entity_configuration_management(self, issuer_url: str, expectedMetadataTypes: list[str], expected_hint=None) -> dict:
                
        logger.info(f"🚀 Invio richiesta all'entità {issuer_url} per scaricare il suo entity configuration") 
        # Ottiene l'EC            
        ec_jwt = oid_fed_fetch_openid_configuration(
            base_url=issuer_url,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains
        )
        
        ec_payload = None
        
        if not ec_jwt:
            raise ValueError(f"Fallito recupero dell'Entity Configuration dell'entità {issuer_url}")
        
        logger.info(f"✅ Ricevuto in risposta dall'entità {issuer_url} il suo Entity Configuration")
        
        try:
            ec_payload = decode_and_verify_jwt(ec_jwt)
            self._checkEC(ec_payload, issuer_url, expectedMetadataTypes, expected_hint)
            
            logger.info(f"✅ L'Entity Configuration dell'entità {issuer_url} è risultato essere valido")

            return ec_payload
        except ValueError as ve:
            raise ValueError(f"Fallita validazione dell'Entity Configuration dell'entità {issuer_url}: {ve}")
    
    def _checkEC(self, ec_payload: str, expected_issuer_url: str, expectedMetadataTypes: list[str], expected_hint: Optional[str] = None):
        """
        Metodo privato per validare i claims opzionali dell'entity statement JWT.
        Args:
            ec_payload (dict): Il payload dell'Entity Configuration.
            expected_issuer_url (str): L'issuer atteso (usato per validare 'iss' e 'sub').
            expectedMetadataTypes (list): Lista dei metadata types attesi nel claim 'metadata'.
            expected_hint (str, optional): Valore opzionale da cercare nei 'authority_hints'.
        """
        if not ec_payload:
            raise ValueError("Entity Configuration non specificato")
        
        ec_payload_iss_value = ec_payload.get("iss")
        if ec_payload_iss_value is None:
            raise ValueError("Claim 'iss' non presente nell'Entity Configuration")
        
        if ec_payload_iss_value != expected_issuer_url:
            raise ValueError(f"L'Entity Configuration presenta un claim 'iss' non valido: atteso '{expected_issuer_url}', trovato {ec_payload_iss_value}")

        ec_payload_sub_value = ec_payload.get("sub")
        if ec_payload_sub_value is None:
            raise ValueError("Claim 'sub' non presente nell'Entity Configuration")
        
        if ec_payload_sub_value != expected_issuer_url:
            raise ValueError(f"L'Entity Configuration presenta un claim 'sub' non valido: atteso '{expected_issuer_url}', trovato {ec_payload_sub_value}")
        
        # Controllo 'authority_hints' solo se expected_hint è specificato
        if expected_hint is not None:            
            hints = ec_payload.get("authority_hints", [])
            if not isinstance(hints, list) or not hints:
                raise ValueError("Claim 'authority_hints' mancante o non valido nell'Entity Configuration")

            if expected_hint not in hints:
                raise ValueError(f"L'Entity Configuration presenta un 'authority_hints' che non contiene il valore atteso: {expected_hint}")
                
        actual_metadata = ec_payload.get("metadata", {})
        missing = [claim for claim in expectedMetadataTypes if claim not in actual_metadata]
        if missing:
            raise ValueError(f"L'Entity Configuration non presenta tutti i metadata types richiesti. Mancano: {missing}")
        
        for metadata_type in expectedMetadataTypes:
            if metadata_type != METADATA_TYPE_FEDERATION_ENTITY:
                try:
                    current_jwks = ec_payload["metadata"][metadata_type]["jwks"]
                except KeyError:
                    raise ValueError(f"Claim 'metadata.{metadata_type}.jwks' mancante o malformato nell'Entity Configuration")
                
    def _checkAccessToken(self, jsonContent: dict, expected_issuer_url: str, expected_clientId: str, expected_cnf_jkt_value: str):
        """
        Metodo privato per validare i claims opzionali dell'access token
        https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuance-low-level.html#low-level-issuance-flow
        """
        if not jsonContent:
            raise ValueError("Access Token non specificato")
        
        at_payload_iss_value = jsonContent.get("iss")
        if at_payload_iss_value is None:
            raise ValueError("Claim 'iss' non presente nell'access token")            
        if at_payload_iss_value != expected_issuer_url:
            raise ValueError(f"Il claim 'iss' dell'access token presenta un valore non valido: atteso '{expected_issuer_url}', trovato {at_payload_iss_value}")

        at_payload_client_id_value = jsonContent.get("client_id")
        if at_payload_client_id_value is None:
            raise ValueError("Claim 'client_id' non presente nell'access token")            
        if at_payload_client_id_value != expected_clientId:
            raise ValueError(f"Il claim 'client_id' dell'access token presenta un valore non valido: atteso '{expected_clientId}', trovato {at_payload_client_id_value}")
                     
        jwt_payload_sub_value = jsonContent.get("sub")
        if jwt_payload_sub_value is None:
            raise ValueError("Claim 'sub' non presente nell'access token")
        
        jwt_payload_cnf_value = jsonContent.get("cnf")
        if jwt_payload_cnf_value is None:
            raise ValueError("Claim 'cnf' non presente nell'access token")
        
        cnf_jkt_value = jwt_payload_cnf_value.get("jkt")
        if cnf_jkt_value is None:
            raise ValueError("Claim 'cnf.jkt' non presente nell'access token")
        if cnf_jkt_value != expected_cnf_jkt_value:
            raise ValueError(f"Il claim 'cnf.jkt' dell'access token presenta un valore non valido: atteso '{expected_cnf_jkt_value}', trovato {cnf_jkt_value}")


    def _checkRelyingPartyAuthorizationRequest(self, jsonContent: dict, clientId: str) -> Tuple[list[dict],str,str, str]:
        """
        Metodo privato per validare i claims opzionali del Relying Party Authorization Request e ritorna le credenziali richieste
        https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/remote-flow.html#request-uri-response
        """
        if not jsonContent:
            raise ValueError("JWT nel Request_uri response non specificato") 

        presentation_response_type = extract_claim(current_app.config,"metadata.presentation_flow.response_type")
        presentation_response_mode = extract_claim(current_app.config,"metadata.presentation_flow.response_mode")
        
        jwt_payload_id_value = jsonContent.get("client_id")
        if jwt_payload_id_value is None:
            raise ValueError("Claim 'client_id' non presente nel JWT contenuto nella Request_uri response")            
        if jwt_payload_id_value != clientId:
            raise ValueError(f"Il JWT contenuto nella Request_uri response presenta un claim 'client_id' non valido: atteso '{clientId}', trovato {jwt_payload_id_value}")

        jwt_payload_iss_value = jsonContent.get("iss")
        if jwt_payload_iss_value is None:
            raise ValueError("Claim 'iss' non presente nel JWT contenuto nella Request_uri response") 
        
        if jwt_payload_iss_value != clientId:
            raise ValueError(f"Il JWT contenuto nella Request_uri response presenta un claim 'iss' non valido: atteso '{clientId}', trovato {jwt_payload_iss_value}")

        jwt_payload_state_value = jsonContent.get("state")
        if jwt_payload_state_value is None:
            raise ValueError("Claim 'state' non presente nel JWT contenuto nella Request_uri response") 
        
        jwt_payload_nonce_value = jsonContent.get("nonce")
        if jwt_payload_nonce_value is None:
            raise ValueError("Claim 'nonce' non presente nel JWT contenuto nella Request_uri response")
        
        jwt_payload_response_uri_value = jsonContent.get("response_uri")
        if jwt_payload_response_uri_value is None:
            raise ValueError("Claim 'response_uri' non presente nel JWT contenuto nella Request_uri response")
        
        jwt_payload_response_type_value  = jsonContent.get("response_type")
        if not jwt_payload_response_type_value:
            raise ValueError("Claim 'response_type' non presente nel JWT contenuto nella Request_uri response")
        if jwt_payload_response_type_value != presentation_response_type:
            raise ValueError(f"Il JWT contenuto nella Request_uri response presenta un claim 'response_type' con il valore '{jwt_payload_response_type_value}' che non è '{presentation_response_type}'")
        
        jwt_payload_response_mode_value  = jsonContent.get("response_mode")
        if not jwt_payload_response_mode_value:
            raise ValueError("Claim 'response_mode' non presente nel JWT contenuto nella Request_uri response")
        if jwt_payload_response_mode_value != presentation_response_mode:
            raise ValueError(f"Il JWT contenuto nella Request_uri response presenta un claim 'response_mode' con il valore '{jwt_payload_response_mode_value}' che non è '{presentation_response_mode}'")
                    
        dcql_query_value = jsonContent.get("dcql_query", {})
        if not dcql_query_value:
            raise ValueError("Claim 'dcql_query' non presente nel JWT contenuto nella Request_uri response")
                
        dcql_query_credentials = dcql_query_value.get("credentials", [])
        
        # Verifica che credentials sia una lista non vuota di dizionari (JSON objects in Python)
        if isinstance(dcql_query_credentials, list) and dcql_query_credentials and all(isinstance(c, dict) for c in dcql_query_credentials):
            dimensione = len(dcql_query_credentials)
            
            if dimensione == 0:
                logger.info(f"ℹ️  Il claim 'dcql_query' estratto dal JWT della Request_uri response non definite alcuna tipologie di credenziali")
            elif dimensione == 1:
                logger.info(f"ℹ️  Il claim 'dcql_query' estratto dal JWT della Request_uri response definisce la seguente tipologia di credenziale:")
            else:
                logger.info(f"ℹ️  Il claim 'dcql_query' estratto dal JWT della Request_uri response definisce le seguenti {dimensione} tipologie di credenziali:")
            
            for idx, credential in enumerate(dcql_query_credentials, 1):
                logger.info(f"Tipologia di credenziale #{idx}")
                for key, value in credential.items():
                    logger.info(f"{key}: {value}")
            return dcql_query_credentials, jwt_payload_state_value, jwt_payload_nonce_value, jwt_payload_response_uri_value        
        else:
            return [], jwt_payload_state_value, jwt_payload_nonce_value, jwt_payload_response_uri_value
        
    def _inizializza_wallet_keys(self, config_dir) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
         Metodo privato per generare le chiavi del wallet e salvarle su config dir.
         Ritorna una tupla: (chiave_privata, chiave_pubblica)
        """
        # Se non esiste la cartella config_dir, la creo
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        private_key_path = os.path.join(config_dir, "pvt_key.pem")
        public_key_path = os.path.join(config_dir, "pub_key.pem")
                   
        # Genera le chiavi della wallet instance se non esistono
        if not os.path.isfile(private_key_path) or not os.path.isfile(public_key_path):
            logger.info("🔐 Generazione nuova coppia di chiavi EC P-256 per il wallet...")
            generate_pem_keys(private_key_path, public_key_path, "P-256")
            logger.info("✅ Chiavi generate.")
        else:
            logger.info("ℹ️  Le chiavi del wallet esistono già. Nessuna generazione necessaria.")

        # Carica chiavi della wallet instance
        wallet_private_key = ec_private_key_from_pem_file(private_key_path)
        wallet_public_key = ec_public_key_from_pem_file(public_key_path)
        
        # Ritorna la tupla
        return wallet_private_key, wallet_public_key
    
    def _recupera_wallet_keys(self, config_dir) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
         Metodo privato per recuperare le chiavi del wallet.
         Ritorna una tupla: (chiave_privata, chiave_pubblica)
        """
        
        # Se non esiste la cartella config_dir, la creo
        if not os.path.exists(config_dir):
            return None, None
        
        private_key_path = os.path.join(config_dir, "pvt_key.pem")
        public_key_path = os.path.join(config_dir, "pub_key.pem")

        # Carica chiavi della wallet instance
        wallet_private_key = ec_private_key_from_pem_file(private_key_path)
        wallet_public_key = ec_public_key_from_pem_file(public_key_path)
        
        # Ritorna la tupla
        return wallet_private_key, wallet_public_key
        
    def _find_credential_by_dcql_item(self, item:dict) -> (dict | None):
        if not item['id']:
            logger.info("❌ Il DCQL non presenta il claim 'id'")
            return None
        
        if not item['format']:
            logger.info("❌ Il DCQL non presenta il claim 'format'")
            return None
        
        logger.info(f"ℹ️  Il DCQL presenta i claims 'id': {item['id']} e 'format': {item['format']}")
             
        # Costruisci l'ID
        raw_id = item['format'] + "_" + item['id']
        credential_presenting_id = re.sub(r"[+\-\s]", "_", raw_id)
        logger.info(f"ℹ️  Uso claims 'format' e 'id' del DCQL per generare la chiave '{credential_presenting_id}' con cui cercare nel wallet la credenziale da presentare")
        
        result = app_state.credential_store.find_by_prefix_with_key(credential_presenting_id)
        if not result:
            logger.info(f"❌ La chiave '{credential_presenting_id}' non ha individuato alcuna credenziale nel wallet")                

            # Tento la ricerca con vct
            credential_presenting_vct = None
            meta = item['meta']
            if not meta:
                logger.info("❌ Il DCQL non presenta il claim 'meta'")
                return None
            
            logger.info(f"ℹ️  Il DCQL presenta il claims 'meta': {meta}")
            
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
            
            logger.info(f"ℹ️  Uso del vct '{credential_presenting_vct}' estratto dal DCQL per cercare nel wallet la credenziale da presentare")
                    
            result = app_state.credential_store.find_by_vct(credential_presenting_vct)
            
            if not result:
                logger.info(f"❌ Il vct '{credential_presenting_vct}' non ha individuato alcuna credenziale nel wallet")
        
        return result

    def _print_session_data(self):
        logger.debug("=== 🌐 Dati in sessione ===")
        try:
            session_json = json.dumps(dict(self.session), indent=2, ensure_ascii=False)
            logger.debug(session_json)
        except TypeError:
            # fallback se qualche valore non è serializzabile
            for key, value in self.session.items():
                logger.debug(f"{key}: {value}")
        logger.debug("========================")

    