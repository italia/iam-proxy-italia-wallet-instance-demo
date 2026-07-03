from typing import Any
from pydantic import BaseModel, Field

#TODO: validations to be implemented
class DocumentIdentifier(BaseModel):
    type: str
    value: str

class DocumentFormat(BaseModel):
    id: str
    specs: dict[str, Any] | None = Field(default_factory=dict)


class Credential(BaseModel):
    proto_version: str
    valid_for_wallet_activation: bool
    internal_mapping_ref: str
    document_identifier: DocumentIdentifier
    document_format: DocumentFormat

class CredentialsConfig(BaseModel):
    supported_credentials: dict[str, Credential]
    internal_attributes_mappings: dict[str, Any]