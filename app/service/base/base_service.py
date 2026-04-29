import logging

from app.store import AppState
from app.utils.http_utils import http_request_with_retry
from settings import METADATA_TYPE_FEDERATION_ENTITY

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

    def validate_entity_configuration(
        self, payload: dict, expected_url: str, metadata_types: list, hint: any = None
    ) -> None:
        logger.debug(
            f"Entering method: validate_entity_configuration. Params [payload: {payload}, expected_url: {expected_url}, metadata_types: {metadata_types}, hint:{hint}]"
        )
        if not payload:
            raise ValueError("Entity Configuration empty")
        self._validate_iss_sub(payload, expected_url)
        if hint is not None:
            self._validate_authority_hints(payload, hint)
        self._validate_metadata_and_jwks(payload, metadata_types)

    def _validate_iss_sub(self, payload: dict, expected: str) -> None:
        logger.debug(f"Entering method: _validate_ec_iss_sub. Params [payload: {payload}, expected: {expected}]")
        if payload.get("iss") != expected or payload.get("sub") != expected:
            raise ValueError(f"iss/sub expected: '{expected}'")

    def _validate_authority_hints(self, payload: dict, expected_hint: any) -> None:
        logger.debug(
            f"Entering method: _validate_authority_hints. Params [payload: {payload}, expected_hint: {expected_hint}]"
        )
        hints = payload.get("authority_hints", [])
        if not isinstance(hints, list) or not hints or expected_hint not in hints:
            raise ValueError(f"Authority expected: '{expected_hint}'")

    def _validate_metadata_and_jwks(self, payload: dict, expected_metadata_types: list) -> None:
        logger.debug(
            f"Entering method: _validate_metadata_and_jwks. Params [payload: {payload}, expected_metadata_types: {expected_metadata_types}]"
        )
        actual = payload.get("metadata", {})
        missing = [type for type in expected_metadata_types if type not in actual]
        if missing:
            raise ValueError(f"Metadata missing: {missing}")
        for mtype in expected_metadata_types:
            if mtype == METADATA_TYPE_FEDERATION_ENTITY:
                continue
            try:
                _ = payload["metadata"][mtype]["jwks"]
            except KeyError:
                raise ValueError(f"metadata.{mtype}.jwks missing")
