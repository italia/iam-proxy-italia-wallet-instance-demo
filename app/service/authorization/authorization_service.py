
import logging
from ..base.base_service import BaseService
from app.store import AppState
from app.utils.oidFedUtils import _parse_entity_statement_jwt
from app.utils.jwtUtils import decode_and_verify_jwt
logger = logging.getLogger(__name__)
from settings import METADATA_TYPE_AUTHORIZATION_SERVER
from urllib.parse import urlencode
from app.utils.oidFedUtils import _parse_oid_fed_list

class AuthorizationService(BaseService):

    QUERY_STRING = {"entity_type": METADATA_TYPE_AUTHORIZATION_SERVER}

    def __init__(self, app_state: AppState, proxy, no_proxy_domains):

        logger.debug("Entering method: init for Authorization Service")
        super().__init__(app_state)
        self.proxy = proxy
        self.authorization_server_url = None
        self.no_proxy_domains = no_proxy_domains

    def authorization_list(self, url: str) -> list[str]:
        logger.info(f"Entering authorization_list method. Params [url: {url}]")
        authorization_list = self.call_endpoint(url,self.LIST_ENDPOINT+f"?{urlencode(self.QUERY_STRING)}",
                                                    self._create_header(self.APPLICATION_JSON_HEADERS),
                                                    proxies=self.proxy, no_proxy_domains=self.no_proxy_domains,
                                                    parse_response=_parse_oid_fed_list)
        if not authorization_list:
            raise ValueError(f"No authorization server was found within the url: {url}")
        return authorization_list

    def authorization_ec(self,  authorization_server_list: list[str], url):
        logger.debug(f"Entering method: authorization_ec. Params [authorization_server_list: {authorization_server_list}, url: {url}]")
        self.authorization_server_url = self.__check_authorization_server(authorization_server_list, url)
        entity_configuration_jwt = self.call_endpoint(url,self.WELL_KNOWN_FEDERATION_PATH,self._create_header(self.ENTITY_STATEMENT_HEADERS),proxies=self.proxy, no_proxy_domains=self.no_proxy_domains, parse_response= _parse_entity_statement_jwt)
        if not entity_configuration_jwt:
            raise ValueError(f"Exception for Entity Configuration {url}")
        return decode_and_verify_jwt(entity_configuration_jwt)

    def _create_header(self, params: dict):
        logger.debug(f"Entering method: _create_header. Params [params: {params}]")
        return params

    def __check_authorization_server(self, authorization_server_list: list[str], authorization_server: str):
        logger.info(f"Entering method: __check_authorization_server. Params [authorization_server_list: {authorization_server_list}, authorization_servdr: {authorization_server}]")
        authorization_server_url = None
        for auth_server in authorization_server_list:
            if auth_server == authorization_server:
                authorization_server_url = authorization_server
                break
        if not authorization_server_url:
            raise ValueError(f"No authorization_server was found into list. {authorization_server_url}")
        return authorization_server_url


