from typing import Any, Optional

from pydantic import BaseModel, HttpUrl, model_validator
from pydantic_core.core_schema import ValidationInfo
from pyeudiw.jwk.schemas.public import JwksSchema


class WalletMetadata(BaseModel):
    wallet_name: str
    credential_offer_endpoint: HttpUrl
    authorization_endpoint: HttpUrl
    vp_formats_supported: dict  # ... #todo check value
    client_id_prefixes_supported: Optional[list] = None  # ... #todo check value
    response_types_supported: Optional[list] = None  # ... #todo check value
    response_modes_supported: Optional[list] = None  # ... #todo check value
    request_object_signing_alg_values_supported: Optional[list] = None  # ... #todo check value


class WalletProvider(BaseModel):
    logo_uri: HttpUrl
    jwks: JwksSchema
    wallet_metadata: WalletMetadata

    @model_validator(mode="before")
    @classmethod
    def inject_jwks_from_context(cls, data: Any, info: ValidationInfo) -> Any:
        if isinstance(data, dict) and data.get("jwks"):
            return data
        context = info.context
        if not context or "public_core_jwks" not in context:
            return data

        public_key_data = context.get("public_core_jwks") if context else None

        if not public_key_data:
            raise ValueError("jwks is mandatory but missing in config and context")

        data["jwks"] = dict(keys=public_key_data)
        return data
