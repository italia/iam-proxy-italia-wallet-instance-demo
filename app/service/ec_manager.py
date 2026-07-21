import datetime
import logging

from pydantic import BaseModel
from pyeudiw.jwt.jws_helper import JWSHelper

from app.models.config.provider_config import ProviderConfig
from app.models.metadata import MetadataFactory

logger = logging.getLogger(__name__)


class ECBaseManager:
    _DEFAULT_EXPIRATION_SECS = 33 * 60  # todo check right default value

    def __init__(self, provider_config: ProviderConfig):
        self._provider_config = provider_config
        self._private_jwks = self._provider_config.private_fed_jwks
        self._metadata_cls = MetadataFactory.get_model_instance(self._provider_config.spec_version)
        self._expiration = self._provider_config.ec_duration_seconds or self._DEFAULT_EXPIRATION_SECS
        self._metadata = None
        self._validity = self._generate_validity()

    @property
    def sub(self) -> str:
        return self._provider_config.public_url  # Public URL of the Wallet Solution.  #todo validate and check it

    @property
    def iss(self) -> str:
        return self._provider_config.public_url  # Public URL of the Wallet Solution. #todo validate and check it

    @property
    def iat(self) -> int:
        """Issuance datetime in Unix Timestamp format."""
        return self._validity["iat"]

    @property
    def exp(self) -> int:
        """Expiration datetime in Unix Timestamp format."""
        return self._validity["exp"]

    @property
    def jwks(self) -> dict[str, list[dict]]:
        """
        A JSON Web Key Set (JWKS) representing the public part of the Federation Entity signing keys.
        The corresponding private key is used by the Wallet Solution to sign the Entity Configuration about itself.
        """
        return dict(keys=self._provider_config.public_fed_jwks)

    @property
    def metadata(self) -> dict:
        _metadata_cls: BaseModel = self._metadata_cls
        if _metadata_cls is None:
            raise Exception("No Metadata Class provided")

        metadata_obj = _metadata_cls.model_validate(
            self._provider_config.metadata_group, context={"public_core_jwks": self._provider_config.public_core_jwks}
        )
        return metadata_obj.model_dump(mode="json", exclude_unset=True)

    @property
    def authority_hints(self) -> list[str]:
        """
        Array of URLs (String) containing the list of URLs of the immediate superior Entities,
        such as the Trust Anchor or an Intermediate, that MAY issue an Entity Statement related to the Wallet Solution.
        """
        return self._provider_config.authority_hints  # todo validate and check it

    def dump_as_dict(self):
        _ret = dict()
        _ret["iss"] = self.iss
        _ret["sub"] = self.sub
        _ret["iat"] = self.iat
        _ret["exp"] = self.exp
        _ret["jwks"] = self.jwks
        _ret["metadata"] = self.metadata
        _ret["authority_hints"] = self.authority_hints
        return _ret

    def dump_as_jwt(self):
        payload = self.dump_as_dict()
        header = dict()
        header["typ"] = "entity-statement+jwt"

        if len(self._private_jwks) == 1:
            sign_key = self._private_jwks[0]
        else:
            for k in self._private_jwks:
                if k.get("use") == "sig":
                    sign_key = k
                    break
            else:
                return None

        header["alg"] = self._alg_from_jwk(sign_key)
        jws_helper = JWSHelper([sign_key])
        return jws_helper.sign(plain_dict=payload, protected=header)

    def _generate_validity(self):
        val = dict()
        iat = datetime.datetime.now(datetime.timezone.utc)
        val["iat"] = int(iat.timestamp())
        val["exp"] = int((iat + datetime.timedelta(minutes=self._expiration)).timestamp())
        return val

    @staticmethod
    def _alg_from_jwk(jwk_key: dict) -> str | None:
        ec_mapping = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}

        kty = jwk_key.get("kty")
        if kty == "RSA":
            return "RS256"

        if kty == "EC":
            _crv = jwk_key.get("crv")
            return ec_mapping.get(jwk_key.get("crv"))
        return None
