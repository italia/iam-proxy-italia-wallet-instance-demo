import logging

from app.store import AppState
from app.utils.http_utils import http_request_with_retry

logger = logging.getLogger(__name__)


class BaseService:
    APPLICATION_JSON_HEADERS = {"Accept": "application/json"}
    ENTITY_STATEMENT_HEADERS = {"Accept": "application/entity-statement+jwt"}

    WELL_KNOWN_FEDERATION_PATH = "/.well-known/openid-federation"
    WELL_KNOWN_CREDENTIAL_PATH = "/.well-known/openid-credential-issuer"
    LIST_ENDPOINT = "/list"

    def __init__(self, app_state: AppState):
        logger.debug(f"Entering method: init. Params [app_state: {app_state}]")
        self.app_state = app_state

    @staticmethod
    def call_endpoint(
        url: str = None,
        type_endpoint: str = None,
        headers: dict = None,
        retries: int = 3,
        delay: float = 1.0,
        proxies: dict = None,
        no_proxy_domains: list[str] = None,
        parse_response=None,
    ):
        logger.debug(f"Entering method: __well_known_path. Params [url: {url}, type_endpoint: {type_endpoint}]")
        url = url.rstrip("/") + type_endpoint
        logger.debug(f"url define: {url}")
        return http_request_with_retry(
            "GET",
            url,
            headers=headers,
            max_retries=retries,
            retry_delay=delay,
            proxies=proxies,
            no_proxy_domains=no_proxy_domains,
            parse_response=parse_response,
        )

    def _create_header(self, params: dict):
        pass
