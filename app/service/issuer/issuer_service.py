import logging
from urllib.parse import urlencode

from app.constants import METADATA_TYPE_CREDENTIAL_ISSUER
from app.store import AppState
from app.utils.oidFedUtils import _parse_oid_fed_list

from ..base.base_service import BaseService

logger = logging.getLogger("issuer")


class IssuerService(BaseService):
    QUERY_STRING = {"entity_type": METADATA_TYPE_CREDENTIAL_ISSUER}

    def __init__(self, app_state: AppState, proxy, no_proxy_domains):
        logger.info("Entering method: init for Issuer Service")
        super().__init__(app_state)
        self.proxy = proxy
        self.no_proxy_domains = no_proxy_domains

    def credential_issuer_list(self, url: str) -> list[str]:
        logger.info(f"Entering credential_issuer_list method. Params [url: {url}]")
        credential_issuer_list = self.call_endpoint(
            url,
            self.LIST_ENDPOINT + f"?{urlencode(self.QUERY_STRING)}",
            self._create_header(self.APPLICATION_JSON_HEADERS),
            proxies=self.proxy,
            no_proxy_domains=self.no_proxy_domains,
            parse_response=_parse_oid_fed_list,
        )
        if not credential_issuer_list:
            raise ValueError(f"No credential issuer was found within the url: {url}")
        return credential_issuer_list

    def _create_header(self, params: dict):
        logger.info(f"Entering method: _create_header. Params [params: {params}]")
        return params
