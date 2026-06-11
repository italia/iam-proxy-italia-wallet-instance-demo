from pydantic import BaseModel

from .federation_entity import FederationEntity
from .wallet_solution import WalletSolution


class MetadataGroup(BaseModel):
    federation_entity: FederationEntity
    wallet_solution: WalletSolution
