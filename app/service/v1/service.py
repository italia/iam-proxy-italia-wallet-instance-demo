import logging

from app.service.itwallet_helpers import get_proxies_from_config
from app.store import AppState

from .. import PresentationService
from ..itwallet_service import ItWalletService

logger = logging.getLogger(__name__)


class Service(ItWalletService):
    def __init__(self, app_state: AppState):
        logger.debug(f"Entering method: init. Params [app_state: {app_state}]")
        super().__init__(app_state)
        self.proxies, self.no_proxy_domains = get_proxies_from_config()
        self.presentation_service = PresentationService(app_state, self.proxies, self.no_proxy_domains)

    def search(self, search_type: str, search_element: str) -> dict:
        logger.info(f"Entering method: search. Params [search_type: {search_type}, search_element: {search_element}]")
        if not search_type or not search_element:
            raise ValueError("Search type and search element cannot be empty.")
        if search_type not in ["scope", "credential_issuer", "attribute"]:
            raise ValueError("Search type must be either 'scope', 'attribute' or 'credential_issuer'.")
        return self.presentation_service.get_presentation_from_credential(search_type, search_element)
