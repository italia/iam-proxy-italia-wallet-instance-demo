
import logging
from ..base.base_service import BaseService
from app.store import AppState
from app.utils.utils import extract_claim
from app.utils.oidFedUtils import _parse_entity_statement_jwt
from app.utils.jwtUtils import decode_and_verify_jwt
logger = logging.getLogger(__name__)

class FederationService(BaseService):



    def __init__(self, app_state: AppState, proxy, no_proxy_domains):
        logger.debug("Entering method: init for Federation Service")
        super().__init__(app_state)
        self.trust_anchor_url = extract_claim(current_app.config, f"ms_trust_configuration.{country}.trust_root")
        self.proxy = proxy
        self.no_proxy_domains = no_proxy_domains

    def issuer_presentation_ec(self, url):
        logger.debug(f"Entering method: _trust_root_ec. Params [url: {url}]")
        entity_configuration_jwt = self.call_endpoint(url,self.WELL_KNOWN_FEDERATION_PATH,self._create_header(self.ENTITY_STATEMENT_HEADERS),proxies=self.proxy, no_proxy_domains=self.no_proxy_domains, parse_response= _parse_entity_statement_jwt)
        if not entity_configuration_jwt:
            raise ValueError(f"Exception forEntity Configuration {url}")
        return decode_and_verify_jwt(entity_configuration_jwt)

    def _create_header(self, params: dict):
        logger.debug(f"Entering method: _create_header. Params [params: {params}]")
        return params



