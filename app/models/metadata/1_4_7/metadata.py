import importlib

from pydantic import BaseModel

_federation = importlib.import_module("..1_3_3.federation_entity", package=__package__)
_wallet = importlib.import_module("..1_3_3.wallet_solution", package=__package__)


class MetadataGroup(BaseModel):
    federation_entity: _federation.FederationEntity
    openid_wallet_provider: _wallet.WalletSolution
