from typing import Literal, Optional, Any

from pydantic import BaseModel, Field


class WalletMetadata(BaseModel):
    vp_formats_supported: dict[str, Any]
    client_id_prefixes_supported: Literal["openid_federation", "x509_hash"] = Field(default="pre-registered")
    authorization_endpoint: str # universal link or custom scheme
    response_types_supported: Optional[Literal["vp_token"]]
    request_object_signing_alg_values_supported: list[str]

class RequestUriReq(BaseModel):
    wallet_metadata: WalletMetadata
    wallet_nonce: str
