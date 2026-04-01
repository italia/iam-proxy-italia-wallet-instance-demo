import logging
from ..base.base_service import BaseService
from app.store import AppState
from ...utils.json_utils import get_value_from_json, get_json_from_response

logger = logging.getLogger(__name__)

class PresentationService(BaseService):

    # @TODO Define the key into a constant in configuration file
    CREDENTIAL_CONFIGURATION_KEY="credential_configurations_supported"

    def __init__(self, app_state: AppState):
        logger.debug("Entering method: init for Presentation Service")
        super().__init__(app_state)
        self.proxy = proxy
        self.no_proxy_domains = no_proxy_domains

    def credential_list(self, url: str) -> list[str]:
        logger.debug(f"Entering credential_list method. Params [url: {url}]")
        credential_issuer_entity_configuration = self.call_endpoint(url,self.WELL_KNOWN_CREDENTIAL_PATH,self._create_header(self.APPLICATION_JSON_HEADERS),proxies=self.proxy, no_proxy_domains=self.no_proxy_domains, parse_response=get_json_from_response)
        if not credential_issuer_entity_configuration:
            raise ValueError(f"No credential issuer entity configuration was found within the url: {url}")
        credential_list = get_value_from_json(credential_issuer_entity_configuration, self.CREDENTIAL_CONFIGURATION_KEY)
        self.app_state.ec_store.add(url,credential_list)
        return credential_list


    def _create_header(self, params: dict):
        logger.debug(f"Entering method: _create_header. Params [params: {params}]")
        return params