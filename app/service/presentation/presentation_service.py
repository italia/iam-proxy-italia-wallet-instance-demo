import logging

from app.store import AppState

from ...utils.json_utils import get_json_from_response, get_value_from_json
from ..base.base_service import BaseService

logger = logging.getLogger(__name__)


class PresentationService(BaseService):
    # @TODO Define the key into a constant in configuration file
    CREDENTIAL_CONFIGURATION_KEY = "credential_configurations_supported"

    def __init__(self, app_state: AppState, proxy, no_proxy_domains):
        logger.debug("Entering method: init for Presentation Service")
        super().__init__(app_state)
        self.proxy = proxy
        self.no_proxy_domains = no_proxy_domains

    def credential_list(self, url: str) -> list[str]:
        logger.debug(f"Entering credential_list method. Params [url: {url}]")
        credential_issuer_entity_configuration = self.call_endpoint(
            url,
            self.WELL_KNOWN_CREDENTIAL_PATH,
            self._create_header(self.APPLICATION_JSON_HEADERS),
            proxies=self.proxy,
            no_proxy_domains=self.no_proxy_domains,
            parse_response=get_json_from_response,
        )
        if not credential_issuer_entity_configuration:
            raise ValueError(f"No credential issuer entity configuration was found within the url: {url}")
        credential_list = get_value_from_json(credential_issuer_entity_configuration, self.CREDENTIAL_CONFIGURATION_KEY)
        self.app_state.ec_store.add(url, credential_list)
        return credential_list

    def get_presentation_from_credential(self, search_type: str, search: str) -> dict:
        logger.debug(
            f"Entering get_presentation_from_credential method. Params [ search_type: {search_type}, search: {search}]"
        )
        if not search_type or not search:
            raise ValueError("Search type and search value cannot be empty.")
        output = {}
        for credential_issuer in self.app_state.ec_store("user_credential"):
            if search_type == "all":
                return self.app_state.ec_store("user_credential")
            elif search_type == "scope":
                output[credential_issuer] = output[credential_issuer] | self.__get_presentation_from_scope(
                    credential_issuer, search
                )
            elif search_type == "format":
                output[credential_issuer] = output[credential_issuer] | self.__get_presentation_from_format(
                    credential_issuer, search
                )
            elif search_type == "credential_issuer":
                output[credential_issuer] = output[credential_issuer] | self.__get_presentation_from_issuer(
                    credential_issuer, search
                )
            elif search_type == "credential_type":
                output[credential_issuer] = output[credential_issuer] | self.__get_presentation_from_type(
                    credential_issuer, search
                )
            elif search_type == "attribute":
                output[credential_issuer] = output[credential_issuer] | self.__get_presentation_from_attribute(
                    credential_issuer, search
                )

        return output

    def __get_presentation_from_scope(self, credential_issuer: str, search: str) -> dict[str, str]:
        logger.debug(
            f"Entering __get_presentation_from_scope method. Params [credential_issuer: {credential_issuer}, search: {search}]"
        )
        if not self.app_state.ec_store(credential_issuer):
            return {}
        output = {}
        for credential in self.app_state.ec_store(credential_issuer):
            if credential.get("scope") == search:
                output[credential_issuer] = output[credential_issuer] | credential
        return output

    def __get_presentation_from_format(self, credential_issuer: str, search: str) -> dict[str, str]:
        logger.debug(
            f"Entering __get_presentation_from_format method. Params [credential_issuer: {credential_issuer}, search: {search}]"
        )
        if not self.app_state.ec_store(credential_issuer):
            return {}
        output = {}
        for credential in self.app_state.ec_store(credential_issuer):
            if credential.get("format") == search:
                output[credential_issuer] = output[credential_issuer] | credential
        return output

    def __get_presentation_from_issuer(self, credential_issuer: str, search: str) -> dict[str, str]:
        logger.debug(
            f"Entering __get_presentation_from_issuer method. Params [credential_issuer: {credential_issuer}, search: {search}]"
        )
        if not self.app_state.ec_store(credential_issuer):
            return {}
        output = {}
        if search == credential_issuer:
            for credential in self.app_state.ec_store(credential_issuer):
                output[credential_issuer] = output[credential_issuer] | credential
        else:
            return output
        return output

    def __get_presentation_from_type(self, credential_issuer: str, search: str) -> dict[str, str]:
        logger.debug(
            f"Entering __get_presentation_from_type method. Params [credential_issuer: {credential_issuer}, search: {search}]"
        )
        # @todo define the search with Giuseppe De Marco
        pass

    def __get_presentation_from_attribute(self, credential_issuer: str, search: str) -> dict[str, str]:
        logger.debug(
            f"Entering __get_presentation_from_attribute method. Params [credential_issuer: {credential_issuer}, search: {search}]"
        )
        # @todo define the search with Giuseppe De Marco
        pass

    def _create_header(self, params: dict):
        logger.debug(f"Entering method: _create_header. Params [params: {params}]")
        return params
