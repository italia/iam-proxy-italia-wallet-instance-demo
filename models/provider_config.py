from cryptojwt.jwk.jwk import key_from_jwk_dict


class ProviderConfig:

    def __init__(self, provider_config: dict):
        self._config = provider_config
        if provider_config is None:
            raise Exception('Invalid provider config')

    @property
    def spec_version(self) -> str:
        return self._config.get('spec_version') or '0'

    @property
    def public_url(self) -> str:
        return self._config.get('public_url') or ''

    @property
    def wallet_name(self) -> str|None:
        return (self._config.get('metadata_group', {})
                .get("wallet_solution", {}) .get("wallet_metadata", {}).get("wallet_name")) or None

    @property
    def wallet_link(self) -> str|None:
        return self._config.get('wallet_link') or None

    @property
    def nbf_attestation(self) -> int|None:
        """
        Set 'nbf' (Not Before) app attestation claim, it identifies the time before which the JWT must not be accepted
        References:
            * RFC 7519: https://tools.ietf.org/html/rfc7519#section-4.1.5
            """
        return self._config.get('nbf_attestation') or None

    @property
    def private_fed_jwks(self) -> list[dict]:
        """Return federated private keys in JWKs"""
        return self._config.get('federation_jwks') or []

    @property
    def private_core_jwks(self) -> list:
        """Return core private key in JWK"""
        return self._config.get('core_jwks') or []

    @property
    def public_fed_jwks(self) -> list[dict]:
        """Return federated public keys in JWKs"""
        keys = self._config.get('federation_jwks') or []
        return [self.private_to_pub_jwk(k) for k in keys]

    @property
    def public_core_jwks(self) -> list:
        """Return core public key in JWKs"""
        keys = self._config.get('core_jwks') or []
        return [self.private_to_pub_jwk(k) for k in keys]

    @property
    def authority_hints(self) -> list[str]:
        return self._config.get('authority_hints') or []

    @property
    def metadata_group(self) -> dict[str, dict]:
        return self._config.get('metadata_group') or {}

    @property
    def ec_duration_seconds(self) -> int:
        return self._config.get('ec_duration_seconds') or 0

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