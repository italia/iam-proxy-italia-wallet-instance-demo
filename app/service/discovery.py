import logging
from urllib.parse import urlencode

from app.utils.http_utils import http_request_with_retry
from app.utils.jwtUtils import decode_and_verify_jwt
from app.utils.oidFedUtils import _parse_entity_statement_jwt, oid_fed_list

logger = logging.getLogger(__name__)

_FEDERATION_PATH = "/.well-known/openid-federation"
_ENTITY_STATEMENT_HEADERS = {"Accept": "application/entity-statement+jwt"}


class FederationDiscovery:
    """Fetch OpenID Federation lists and entity configurations for one entity type."""

    def __init__(self, proxies, no_proxy_domains):
        self.proxies = proxies
        self.no_proxy_domains = no_proxy_domains

    def list_entities(self, url: str, entity_type: str, empty_message: str) -> list[str]:
        listed = oid_fed_list(
            url,
            f"?{urlencode({'entity_type': entity_type})}",
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
        )
        if not listed:
            raise ValueError(empty_message)
        return listed

    def entity_configuration(self, url: str) -> dict:
        token = http_request_with_retry(
            "GET",
            url.rstrip("/") + _FEDERATION_PATH,
            headers=_ENTITY_STATEMENT_HEADERS,
            proxies=self.proxies,
            no_proxy_domains=self.no_proxy_domains,
            parse_response=_parse_entity_statement_jwt,
        )
        if not token:
            raise ValueError(f"Exception for Entity Configuration {url}")
        return decode_and_verify_jwt(token)

    def listed_entity_configuration(
        self, trust_root: str, entity_type: str, entity_url: str, empty_message: str, missing_message: str
    ) -> dict:
        listed = self.list_entities(trust_root, entity_type, empty_message)
        if entity_url not in listed:
            raise ValueError(missing_message)
        return self.entity_configuration(entity_url)
