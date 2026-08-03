from enum import StrEnum

from pydantic import HttpUrl

from app import AppConfig
from app.models.openid4vp.authorization_request import AuthorizationRequest, ReqUriHttpMethod, ClientIdPrefix
from app.utils.utils import base64url_decode
from pyeudiw.jwt.jws_helper import JWSHelper



class OpenID4VPService:
    """Core Engine implementation for OpenID4VP protocol."""

    class ContentTypes(StrEnum):
        REQUEST_OBJECT = "oauth-authz-req+jwt"
        REQUEST_URI_REQ = "application/x-www-form-urlencoded"


    def __init__(self, app_config: AppConfig, trust_anchor_url: str):
        self.trust_anchor_url = trust_anchor_url
        self._wallet_metadata_conf = app_config.metadata
        self.http_client = ...


    def resolve_authorization_request(self, auth_req_headers: dict, auth_req_body: dict):
        """Validate AuthorizationRequest and fetches Request Object."""

        auth_req: AuthorizationRequest = AuthorizationRequest.model_validate(auth_req_body)

        if auth_req.request_uri: # Request Object by reference
            signed_req_obj_jwt = self._fetch_request_uri(auth_req.request_uri, auth_req.request_uri_method)
        elif auth_req.request:
            signed_req_obj_jwt = base64url_decode(auth_req.request).decode()
        else:
            raise ValueError("Invalid Request Object")


        if auth_req.client_id.startswith(ClientIdPrefix.OPENID_FEDERATION):
            client_url = auth_req.client_id.removeprefix(ClientIdPrefix.OPENID_FEDERATION + ":")
            client_ec = self._fetch_client_ec(client_url)

        elif auth_req.client_id.startswith(ClientIdPrefix.X509_HASH):
            client_url = auth_req.client_id.removeprefix(ClientIdPrefix.X509_HASH + ":")
            #...

        req_obj_payload = JWSHelper(self._fetch_client_jwks(client_ec)).verify(client_ec)


    def _fetch_client_ec(self, client_url):
        ...

    def _fetch_client_jwks(self, client_ec: dict) -> list[dict]:
        ...

    def _fetch_request_uri(self, request_uri: HttpUrl, method: ReqUriHttpMethod|None=ReqUriHttpMethod.GET):
        ...
        req_headers = None #todo
        if not req_headers.get("Content-Type") == self.ContentTypes.REQUEST_URI_REQ:
            ...