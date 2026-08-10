from typing import Literal, Optional, List, Any
from pydantic import BaseModel, Field, HttpUrl

#todo add validations

class RequestUriErrorResponse(BaseModel):
    """
    Request URI Endpoint Response
    Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.4.5/en/remote-flow.html#request-uri-endpoint-errors
    """
    error: Literal["invalid_request", "server_error", "temporarily_unavailable"]
    error_description: str


class ClientMetadata(BaseModel):
    vp_formats_supported: dict[str, Any] = Field(description="Supported Verifiable Presentation formats")
    encrypted_response_enc_values_supported: Optional[List[str]] = Field(None, description="Supported JWE enc algorithms for encrypted Authorization Responses")
    jwks: Optional[dict] = Field(None, description="Web Key Set used by the Wallet Instance for encrypting the Authorization Response")
    client_name: Optional[str] = Field(None, description="Used for user consent display and to show the Relying Party identity")
    logo_uri: Optional[str]= Field(None, description="Used for user consent display and to show the Relying Party identity")


class RequestObjectJwtHeader(BaseModel):
    """
    IT-Wallet Request Object header claims (Remote Flow - Request Uri Response).
    Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.4.5/en/remote-flow.html#request-object
    """
    alg: str
    typ: Literal["oauth-authz-req+jwt"]
    kid: str
    trust_chain: Optional[List[str]]
    x5c: Optional[List[str]] = Field(description="REQUIRED when client_id uses an x509_hash prefix scheme. OPTIONAL otherwise")


class RequestObjectJwtPayload(BaseModel):
    """
    IT-Wallet Request Object claims (Remote Flow - Request Uri Response).
    Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.4.5/en/remote-flow.html#request-object
    """

    client_id: str = Field(description="Unique identifier of the RP / Wallet Provider.")
    client_metadata: ClientMetadata = Field(description="Object containing the Relying Party metadata values")
    response_mode: Literal["direct_post.jwt"] = Field(description="MUST be set to direct_post.jwt in both Same Device and Cross Device flow")
    dcql_query: dict = Field(description="Representing a request for a presentation of Credentials, according to the DCQL query language")
    transaction_data: Optional[List[dict]] = Field(description="Each obj describing a transaction that the Relying Party requests the User to authorize")
    transaction_data_hashes_alg: Optional[List[str]]
    response_type: Literal["vp_token"] = Field(description="Must be exactly 'vp_token'.")
    wallet_nonce: Optional[str] = Field(description="REQUIRED if previously provided by Wallet Instance, used to mitigate replay attacks of the response")
    response_uri: HttpUrl = Field(..., description="Response URI to which the Wallet Instance MUST send the Authorization Response")
    nonce: str = Field(min_length=1, description="Random value to mitigate replay attacks.")
    state: str = Field(description="Unique identifier of the Authorization Request")

    # todo move to a jwt common class
    iss: str
    iat: int
    exp: int


