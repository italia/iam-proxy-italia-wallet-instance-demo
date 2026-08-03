from enum import StrEnum
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, HttpUrl, model_validator


class ClientIdPrefix(StrEnum):
    """Client Identifier Prefixes (as defined in OpenID4VP, Section 5.9)
    Reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an
    """
    OPENID_FEDERATION = "openid_federation"
    X509_HASH = "x509_hash"


class ReqUriHttpMethod(StrEnum):
    """
    HTTP methods to obtain the Request Object from the request_uri
    Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.4.5/en/remote-flow.html#authorization-request
    """
    GET = "get"
    POST = "post"


class AuthorizationRequest(BaseModel):
    """
    Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.4.5/en/remote-flow.html#authorization-request
    """
    client_id: str = Field(description="Unique identifier of the Relying Party. Must use ClientIdPrefix.")
    request: Optional[str] = Field(None, description="Contains the base64url-encoded and signed Req Obj")
    request_uri: Optional[HttpUrl] = Field(None, description="The HTTP URL where the Relying Party provides the signed Request Object")
    request_uri_method: Optional[ReqUriHttpMethod] = Field(None, description="HTTP method to obtain the Request Object from the request_uri")

    @model_validator(mode="after")
    def validate_conditional_parameters(self) -> "AuthorizationRequest":
        if not (self.client_id.startswith(ClientIdPrefix.OPENID_FEDERATION) or
                self.client_id.startswith(ClientIdPrefix.X509_HASH)):
            raise ValueError(
                f"client_id MUST use one of the following prefixes: "
                f"'{ClientIdPrefix.OPENID_FEDERATION}' or '{ClientIdPrefix.X509_HASH}'"
            )

        if self.request is None and self.request_uri is None:
            raise ValueError("Either 'request' or 'request_uri' MUST be specified.")

        elif self.request is not None and self.request_uri is not None:
            raise ValueError("Parameters 'request' and 'request_uri' are mutually exclusive. Cannot present both.")

        elif self.request_uri_method is not None and self.request_uri is None:
            raise ValueError("client_uri_method MUST NOT be present if 'request_uri' is absent.")

        return self

    @classmethod
    def from_query_params(cls, params: Dict[str, List[str]]):
        """Helper to safely instantiate the model from raw URL query parameters strings."""
        if not params:
            raise ValueError("No supported params founded")

        raw_client_id = params.get("client_id", [None])[0]
        raw_request = params.get("request", [None])[0]
        raw_request_uri = params.get("request_uri", [None])[0]
        raw_method = params.get("request_uri_method", [None])[0]

        return cls(
            client_id=raw_client_id,
            request=raw_request,
            request_uri=raw_request_uri,
            request_uri_method=raw_method.lower() if raw_method else None
        )