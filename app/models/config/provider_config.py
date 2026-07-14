from cryptojwt.jwk.jwk import key_from_jwk_dict
from typing import Dict, Any
from pydantic import PrivateAttr, computed_field, model_validator, BaseModel


class ProviderConfig(BaseModel):

    #TODO: refactoring: remove model_config and computed_field -> create plain BaseModel + validations to be implemented
    model_config = {"extra": "allow"} #temporary workaround
    _config: Dict[str, Any] = PrivateAttr()


    def __init__(self, **kwargs):
        if not kwargs:
            raise Exception("Invalid provider config")
        super().__init__(**kwargs)
        self._config = kwargs


    @model_validator(mode="before")
    @classmethod
    def check_config_present(cls, data: Any) -> Any:
        if data is None:
            raise Exception("Invalid provider config")
        return data


    @computed_field
    @property
    def spec_version(self) -> str:
        return self._config.get("spec_version") or "0"

    @computed_field
    @property
    def public_url(self) -> str:
        return self._config.get("public_url") or ""

    @computed_field
    @property
    def wallet_name(self) -> str | None:
        return (
            self._config.get("metadata_group", {})
            .get("wallet_provider", {})
            .get("wallet_metadata", {})
            .get("wallet_name")
        ) or None

    @computed_field
    @property
    def wallet_link(self) -> str | None:
        return self._config.get("wallet_link") or None

    @computed_field
    @property
    def nbf_attestation(self) -> int | None:
        """
        Set 'nbf' (Not Before) app attestation claim, it identifies the time before which the JWT must not be accepted
        References:
            * RFC 7519: https://tools.ietf.org/html/rfc7519#section-4.1.5
        """
        return self._config.get("nbf_attestation") or None

    @computed_field
    @property
    def private_fed_jwks(self) -> list[dict]:
        """Return federated private keys in JWKs"""
        return self._config.get("federation_jwks") or []

    @computed_field
    @property
    def private_core_jwks(self) -> list:
        """Return core private key in JWK"""
        return self._config.get("core_jwks") or []

    @computed_field
    @property
    def public_fed_jwks(self) -> list[dict]:
        """Return federated public keys in JWKs"""
        keys = self._config.get("federation_jwks") or []
        return [self.private_to_pub_jwk(k) for k in keys]

    @computed_field
    @property
    def public_core_jwks(self) -> list:
        """Return core public key in JWKs"""
        keys = self._config.get("core_jwks") or []
        return [self.private_to_pub_jwk(k) for k in keys]

    @computed_field
    @property
    def authority_hints(self) -> list[str]:
        return self._config.get("authority_hints") or []

    @computed_field
    @property
    def metadata_group(self) -> dict[str, dict]:
        return self._config.get("metadata_group") or {}

    @computed_field
    @property
    def ec_duration_seconds(self) -> int:
        return self._config.get("ec_duration_seconds") or 0

    @computed_field
    @staticmethod
    def private_to_pub_jwk(private_jwk: dict) -> dict[str, dict] | None:
        if not private_jwk:
            return None
        _key = key_from_jwk_dict(private_jwk)
        return _key.serialize(private=False)

    def get_federation_x5c_by_kid(self, kid) -> list | None:
        for k in self.private_fed_jwks:
            if kid == k.get("kid"):
                return k.get("x5c")
        return None

    def get_core_x5c_by_kid(self, kid) -> list | None:
        for k in self.private_core_jwks:
            if kid == k.get("kid"):
                return k.get("x5c")
        return None
