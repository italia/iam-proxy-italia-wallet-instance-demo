from pydantic import BaseModel

from .federation_entity import FederationEntity
from .wallet_provider import WalletProvider


class MetadataGroup(BaseModel):
    federation_entity: FederationEntity
    wallet_provider: WalletProvider
