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


from app.service.issuance import IssuanceFlow
from app.service.presentation_flow import PresentationFlow

class ItWalletService(IssuanceFlow, PresentationFlow):
    """Service for IT Wallet credential issuance and presentation flows."""

    def __init__(self, session, external_discovery: bool = False):
        """Initialize service with Flask session. Loads proxies from config."""
        self.session = session
        self._app_config: AppConfig = current_app.config[APP_SETTINGS_KEY]  # todo move to params
        self._app_settings: AppSettings = self._app_config.app
        self.proxies, self.no_proxy_domains = get_proxies_from_config(self._app_settings.http_params.get("proxy"))
        self._hw_private_jwk = None
        self._hw_public_jwk = None
        self._hw_key_tag = None
        self.discovery = FederationDiscovery(self.proxies, self.no_proxy_domains)
        self.external_discovery = external_discovery
        self._credentials_config: CredentialsConfig = self._app_config.credentials_config

    def _get_trust_root_url(self, country: str) -> str:
        trust_root_url = extract_claim(current_app.config, f"ms_trust_configuration.{country}.trust_root")
        if not trust_root_url:
            raise ValueError(f"Nessun Trust root per il paese {country}")
        return trust_root_url

    def _ensure_trust_root_ec(self, trust_root_url: str) -> None:
        if app_state.ec_store.exists(trust_root_url):
            return
        trust_root_entity_configuration = self.discovery.entity_configuration(trust_root_url)
        validate_ec(
            trust_root_entity_configuration,
            trust_root_url,
            [METADATA_TYPE_FEDERATION_ENTITY],
        )
        app_state.ec_store.add(trust_root_url, trust_root_entity_configuration)
        logger.info(f"trust_root_url: {trust_root_url}")

    def _wallet_provider_entity(self) -> dict:
        """Return the wallet provider entity configuration, loading it from the trust anchor when missing."""
        query = f"metadata.{METADATA_TYPE_WALLET_PROVIDER}"
        found = app_state.ec_store.all_values(query)
        if found:
            return found[0]

        country = app_state.selected_country or ""
        trust_root_url = extract_claim(current_app.config, f"ms_trust_configuration.{country}.trust_root")
        if not trust_root_url:
            raise ValueError(
                "Non è configurato il trust anchor della demo, quindi non posso identificare il wallet provider."
            )
        try:
            self._load_wallet_provider_ec(trust_root_url)
        except ValueError as exc:
            logger.error("Wallet provider non disponibile: %s", sanitize_for_logging(str(exc)))
            raise ValueError(
                "Non trovo il wallet provider della demo nel trust anchor. Senza di esso il wallet non può ottenere l'attestazione."
            ) from exc

        found = app_state.ec_store.all_values(query)
        if not found:
            raise ValueError("Il wallet provider risponde, ma la sua configurazione non contiene i dati attesi.")
        return found[0]

    def _load_wallet_provider_ec(self, trust_root_url: str) -> None:
        provider_public_url = self._app_config.provider_config.public_url
        wallet_provider_entity_configuration = self.discovery.listed_entity_configuration(
            trust_root_url,
            METADATA_TYPE_WALLET_PROVIDER,
            provider_public_url,
            f"Il trust anchor {trust_root_url} non pubblica alcun wallet provider.",
            "Il wallet provider configurato per questa demo non compare nell'elenco pubblicato dal trust anchor.",
        )
        validate_ec(
            wallet_provider_entity_configuration,
            provider_public_url,
            [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_WALLET_PROVIDER],
            trust_root_url,
        )
        app_state.ec_store.add(provider_public_url, wallet_provider_entity_configuration)

    def _authorization_server_configuration(self, trust_root_url: str, authorization_server_url: str) -> dict:
        return self.discovery.listed_entity_configuration(
            trust_root_url,
            METADATA_TYPE_AUTHORIZATION_SERVER,
            authorization_server_url,
            f"No authorization server was found within the url: {trust_root_url}",
            f"No authorization_server was found into list. {authorization_server_url}",
        )

    def discovery_page(self):
        logger.info("Entering method: discovery_page. Params []")

        trust_anchor_url = extract_claim(current_app.config, "wallet_instance.trust_anchor")

        if not trust_anchor_url:
            raise ValueError("Trust anchor is not configured for the wallet instance")

        logger.info(f"trust_anchor_url: {trust_anchor_url}")

        if not app_state.ec_store.exists(trust_anchor_url):
            trust_root_entity_configuration = self.discovery.entity_configuration(trust_anchor_url)
            validate_ec(
                trust_root_entity_configuration,
                trust_anchor_url,
                [METADATA_TYPE_FEDERATION_ENTITY],
            )
            app_state.ec_store.add(trust_anchor_url, trust_root_entity_configuration)

        authorization_server_url = extract_claim(current_app.config, "wallet_instance.oauth_authorization_server")
        authorization_server_ec = self._authorization_server_configuration(trust_anchor_url, authorization_server_url)

        app_state.ec_store.add(authorization_server_url, authorization_server_ec)

        return (
            authorization_server_ec.get("metadata", {})
            .get(METADATA_TYPE_AUTHORIZATION_SERVER, {})
            .get("authorization_endpoint")
        )

    def _authorization_response_management(
        self, authorization_response: dict, state_expected: Optional[str] = None, iss_expected: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """Validate auth response, return (code, state, iss). Raises on error or mismatch."""
        logger.info(
            f"Entering method: _authorization_response_management. Params [authorization_response: {authorization_response}]"
        )

        if not authorization_response:
            raise ValueError("L'issuer non ha restituito l'autorizzazione.")

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
            raise ValueError("La risposta non appartiene a questa richiesta. Premi di nuovo Ottieni.")

        if authorization_response_error:
            detail = authorization_response_error_description or authorization_response_error
            raise ValueError(gettext("L'issuer ha rifiutato l'accesso: %(detail)s.") % {"detail": detail})
        if not authorization_response_code:
            raise ValueError("L'issuer non ha restituito il codice di autorizzazione.")
        if iss_expected is not None and authorization_response_iss != iss_expected:
            raise ValueError("La risposta arriva da un issuer diverso da quello della richiesta.")

        return authorization_response_code, authorization_response_state, authorization_response_iss

    def _entity_configuration_management(
        self, issuer_url: str, expectedMetadataTypes: list[str], expected_hint=None
    ) -> dict:
        """Fetch and validate EC for issuer_url. Returns EC payload. Raises on failure."""
        logger.debug(f"Entering method: _entity_configuration_management. Params [issuer_url: {issuer_url}]")

        # Ottiene l'EC
        ec_jwt = oid_fed_fetch_openid_configuration(
            base_url=issuer_url, proxies=self.proxies, no_proxy_domains=self.no_proxy_domains
        )

        ec_payload = None

        if not ec_jwt:
            raise ValueError(f"Fallito recupero dell'Entity Configuration dell'entità {issuer_url}")

        logger.info(f"Response ec_jwt: {ec_jwt}")

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
        logger.debug(f"Entering method: _retrieve_instance_hw_keys. Params [config_dir: {config_dir}]")

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

    def _retrieve_wallet_provider_ec(self, trust_root_url: str) -> str | None:
        """
        Retrieve the wallet provider url from the trusted root; store it Entity Configuration in-memory
        Returns:
            (str) wallet provider URL or None if error occurred
        """
        params = {"entity_type": METADATA_TYPE_WALLET_PROVIDER}

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
                wallet_provider_url, [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_WALLET_PROVIDER], trust_root_url
            )
        except Exception as e:
            logger.error("Unable to retrieve entity configuration for provider - error: {}".format(e))
            return None
        app_state.ec_store.add(wallet_provider_url, ec_payload)
        return wallet_provider_url

