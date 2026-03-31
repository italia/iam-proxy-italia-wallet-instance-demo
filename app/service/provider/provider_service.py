import logging
from ..base.base_service import BaseService
from urllib.parse import urlencode
from app.store import AppState
from settings import METADATA_TYPE_FEDERATION_ENTITY
from app.utils.jwtUtils import decode_and_verify_jwt
from app.utils.oidFedUtils import _parse_oid_fed_list
from app.utils.oidFedUtils import _parse_entity_statement_jwt

logger = logging.getLogger(__name__)

class ProviderService(BaseService):

    QUERY_STRING = {"entity_type": METADATA_TYPE_FEDERATION_ENTITY}

    def __init__(self, app_state: AppState,  proxy, no_proxy_domains):
        logger.info("Entering method: init for Provider Service")
        super().__init__(app_state)
        self.proxy = proxy
        self.no_proxy_domains = no_proxy_domains
        self.wallet_provider_url = None

    def wallet_provider_list(self, url):
        logger.info(f"Entering method: _trust_root_ec. Params [url: {url}]")
        # @Todo Talking with Giuseppe and Team, because we need to understand why in old version we have the query string in the url and now we don't have it. In fact, in old version we have this line:
        # wallet_provider_list = self.call_endpoint(url,self.LIST_ENDPOINT+f"?{urlencode(self.QUERY_STRING)}",self._create_header(self.APPLICATION_JSON_HEADERS),proxies=self.proxy, no_proxy_domains=self.no_proxy_domains, parse_response= _parse_oid_fed_list)

        wallet_provider_list = self.call_endpoint(url, self.LIST_ENDPOINT,
                                                  self._create_header(self.APPLICATION_JSON_HEADERS),
                                                  proxies=self.proxy, no_proxy_domains=self.no_proxy_domains,
                                                  parse_response=_parse_oid_fed_list)
        if not wallet_provider_list:
            raise ValueError(f"No wallet_provider was found within the federation. {url}")
        return wallet_provider_list

    def _create_header(self, params: dict):
        logger.info(f"Entering method: _create_header. Params [params: {params}]")
        return params

    def wallet_provider_ec(self, wallet_provider_list: list[str], url: str) :
        logger.info(f"Entering method: wallet_provider_ec. Params [url: {url}]")
        self.wallet_provider_url = self.__check_wallet_provider(wallet_provider_list, url)
        entity_configuration_jwt = self.call_endpoint(url,self.WELL_KNOWN_FEDERATION_PATH,self._create_header(self.ENTITY_STATEMENT_HEADERS),proxies=self.proxy, no_proxy_domains=self.no_proxy_domains, parse_response= _parse_entity_statement_jwt)
        if not entity_configuration_jwt:
            raise ValueError(f"Exception forEntity Configuration {url}")
        return decode_and_verify_jwt(entity_configuration_jwt)

    def __check_wallet_provider(self, wallet_provider_list: list[str], wallet_provider):
        logger.info(f"Entering method: check_wallet_provider. Params [wallet_provider_list: {wallet_provider_list}, wallet_provider: {wallet_provider}]")
        wallet_provider_url = None
        for wp in wallet_provider_list:
            if wp == wallet_provider:
                wallet_provider_url = wp
                break
        if not wallet_provider_url:
            raise ValueError(f"No wallet_provider was found into list. {wallet_provider_url}")
        return wallet_provider_url


