from enum import StrEnum
from pydantic import HttpUrl

from app.constants import METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_VERIFIER
from app.models.config.app_config import AppSettings
from app.models.openid4vp.authorization_request import AuthorizationRequest, ReqUriHttpMethod, ClientIdPrefix
from app.service.itwallet_helpers import validate_ec, get_proxies_from_config
from app.utils.http_utils import http_request_with_retry
from app.utils.itwalletUtils import _parse_jwt_response
from app.utils.jwtUtils import decode_and_verify_jwt
from app.utils.oidFedUtils import oid_fed_fetch_openid_configuration
from app.utils.utils import base64url_decode, logger
from pyeudiw.jwt.jws_helper import JWSHelper

class NoRequestObjectFound(Exception):
    pass

class OpenID4VPService:
    """Core Engine implementation for OpenID4VP protocol."""

    class ContentTypes(StrEnum):
        REQUEST_OBJECT = "oauth-authz-req+jwt"
        REQUEST_URI_REQ = "application/x-www-form-urlencoded"
        REQUEST_URI_RESP = "application/oauth-authz-req+jwt"
        REQUEST_URI_RESP_ERROR = "application/json"

    def __init__(self, app_settings: AppSettings, trust_anchor_url: str):
        self._app_settings = app_settings
        self._trust_anchor_url = trust_anchor_url
        # self._wallet_metadata_conf = app_config.metadata


    def resolve_authorization_request(self, auth_req_headers: dict, auth_req_body: dict):
        """Validate AuthorizationRequest and fetches Request Object."""

        auth_req: AuthorizationRequest = AuthorizationRequest.model_validate(auth_req_body)

        signed_req_obj_jwt = None
        if auth_req.request_uri: # Request Object by reference
            signed_req_obj_jwt = self._fetch_request_uri(auth_req.request_uri, auth_req.request_uri_method)
        elif auth_req.request:
            signed_req_obj_jwt = base64url_decode(auth_req.request).decode()

        if signed_req_obj_jwt is None:
            raise NoRequestObjectFound

        if auth_req.client_id.startswith(ClientIdPrefix.OPENID_FEDERATION): # federation trust framework
            client_url = auth_req.client_id.removeprefix(ClientIdPrefix.OPENID_FEDERATION + ":")
            client_ec = self._fetch_client_ec(client_url)
            keys = client_ec.get("jwks", {}).get("keys") or []

        elif auth_req.client_id.startswith(ClientIdPrefix.X509_HASH): #x509 trust framework
            client_url = auth_req.client_id.removeprefix(ClientIdPrefix.X509_HASH + ":")
            raise Exception("Unsupported federation framework x5c")
        else:
            raise Exception("Unsupported client_id PREFIX")

        req_obj_payload = JWSHelper(keys).verify(signed_req_obj_jwt)
        ...

    def _fetch_client_ec(self, client_url) -> dict:
        # TODO: create entity configuration pydantic model with validation
        if not (ec_jwt := oid_fed_fetch_openid_configuration(base_url=client_url, **self.__get_default_http_args())):
            raise ValueError(f"An error occurring while Entity Configuration retrieving for {client_url}")

        logger.debug("Response EC from {}: {}".format(client_url, ec_jwt))
        try:
            ec_payload = decode_and_verify_jwt(ec_jwt)
            validate_ec(ec_payload,
                        client_url,
                        [METADATA_TYPE_FEDERATION_ENTITY, METADATA_TYPE_CREDENTIAL_VERIFIER],
                        self._trust_anchor_url)
            return ec_payload
        except ValueError as e:
            raise ValueError(f"Retrieving EC from {METADATA_TYPE_CREDENTIAL_VERIFIER} {client_url} failed: {e}")

    def _fetch_request_uri(self, request_uri: HttpUrl, method: ReqUriHttpMethod|None=ReqUriHttpMethod.GET):
        if method == ReqUriHttpMethod.POST:
            _jwt = http_request_with_retry(
                url=str(request_uri),
                method="POST",
                headers={"Content-Type": self.ContentTypes.REQUEST_URI_REQ},
                parse_response=_parse_jwt_response(self.ContentTypes.REQUEST_URI_RESP)
            )
        elif method == ReqUriHttpMethod.GET:
            ...

        return None


    def __get_default_http_args(self) -> dict:
        defaults = dict()
        defaults["proxies"], defaults["no_proxy_domains"] = get_proxies_from_config(self._app_settings.http_params.get("proxy"))
        return defaults
