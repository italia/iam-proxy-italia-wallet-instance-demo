import json
import logging
import os
import secrets
import time

from flask import Blueprint, Response, jsonify, request, session
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.wallet_attestations.issuers.wia import WiaJswIssuer
from pyeudiw.wallet_attestations.issuers.wua import WuaJswIssuer

from app.constants import APP_SETTINGS_KEY
from app.models.config.provider_config import ProviderConfig
from app.service.ec_manager import ECBaseManager
from app.utils.utils import ec_public_key_from_pem_file, pub_ec_key_obj_to_jwk

logger = logging.getLogger(__name__)

provider_bp = Blueprint("provider_bp", __name__, url_prefix="/provider")
provider_config: ProviderConfig = None
instance_conf: dict = None

NONCE_TTL = 300

valid_nonces = {}


@provider_bp.record_once
def on_load(state):
    global provider_config
    provider_config = state.app.config[APP_SETTINGS_KEY].provider_config
    global instance_conf
    instance_conf = state.app.config.get("wallet_instance")


@provider_bp.route("/.well-known/openid-federation", methods=["GET"], strict_slashes=False)
def wallet_provider_entity_configuration():
    _format = request.args.get("format", default="jwt")

    data = None
    status = 500
    mimetype = "text/plain"

    try:
        entity_config = ECBaseManager(provider_config)
        if _format == "json":
            data = json.dumps(entity_config.dump_as_dict())
            status = 200
            mimetype = "application/json"
        elif _format == "jwt":
            data = entity_config.dump_as_jwt()
            status = 200
            mimetype = "application/entity-statement+jwt"
    except Exception as e:
        exc_info = logger.getEffectiveLevel() == logging.DEBUG
        logger.error(f"An error occurred while generating entity configuration. Error: {e}", exc_info=exc_info)
        pass
    return Response(response=data, status=status, mimetype=mimetype)


@provider_bp.route("/nonce", methods=["GET"], strict_slashes=False)
def wallet_nonce():
    nonce = secrets.token_hex(16)
    data = json.dumps(dict(nonce=nonce))
    status = 200
    mimetype = "application/json"
    session["active_nonce"] = nonce
    valid_nonces[nonce] = time.time() + NONCE_TTL
    return Response(response=data, status=status, mimetype=mimetype)


@provider_bp.route("/instance-initialization", methods=["POST"], strict_slashes=False)
def init_wallet_instance(): ...  # todo


@provider_bp.route("/wallet-attestation", methods=["POST"], strict_slashes=False)
def wallet_attestations():
    body = request.get_json()
    assertion_jwt = body.get("assertion")
    payload = None
    data = dict(error="server_error", error_description="The server encountered an unexpected error.")
    status_code = 500

    if not assertion_jwt:
        data["error"] = "bad_request"
        data["error_description"] = "The provided body was malformed"
        return jsonify(data), 400

    try:
        instance_pub_key = get_wallet_instance_pubkey()
        payload = JWSHelper([instance_pub_key]).verify(assertion_jwt)
    except JWSVerificationError:
        logger.error("JWT verification failed: The request for wallet attestations has expired.")
    except Exception:
        data["error"] = "invalid_request"
        data["error_description"] = "Unable to verify signature"
        logger.error("JWT verification failed: invalid key for signing verification")
        return jsonify(data), 400

    if verify_attestation_req_payload(payload):
        try:
            data = dict(wallet_attestations=[])
            data["wallet_attestations"].append(dict(wallet_app_attestation=generate_wia()))
            data["wallet_attestations"].append(dict(wallet_unit_attestation=generate_wua()))
            status_code = 200
        except Exception as e:
            logger.error("An error occurred while generating attestations. Error: %s", e)
    return jsonify(data), status_code


def generate_wia() -> str:
    """
     Generates the IT Wallet App Attestation.

    This function creates a signed attestation object to verify the app's
    integrity and device security against the IT Wallet infrastructure.

    Returns:
            str: Encoded attestation object (JWT).
    References:
        * IT Wallet Technical Specifications v1.3.3: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/wallet-provider-endpoint.html#wallet-app-attestation-jwt
    """
    x5c = provider_config.get_core_x5c_by_kid(provider_config.private_core_jwks[0].get("kid"))
    wia_issuer = WiaJswIssuer(
        provider_config.public_url, provider_config.private_core_jwks[0], get_wallet_instance_pubkey(), x5c
    )

    if provider_config.wallet_name:
        wia_issuer.set_wallet_name(provider_config.wallet_name)
    if provider_config.wallet_link:
        wia_issuer.set_wallet_link(provider_config.wallet_link)
    if provider_config.nbf_attestation:
        wia_issuer.set_nbf(provider_config.nbf_attestation)

    # todo [optional]
    # wia_issuer.set_status(...)
    # wia_issuer.set_trust_chain(...)
    return wia_issuer.generate_jws()


def generate_wua() -> str:
    """
    Generates the IT Wallet Unit Attestation.

    Produces a signed attestation to verify the specific Wallet Instance binding to the hardware-backed security module of the device.

    Returns:
        str: Encoded Unit Attestation (JWT).

    References:
        * IT Wallet Technical Specifications v1.3.3: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/wallet-provider-endpoint.html#wallet-unit-attestation-jwt
    """
    x5c = provider_config.get_core_x5c_by_kid(provider_config.private_core_jwks[0].get("kid"))
    wua_issuer = WuaJswIssuer(
        provider_config.public_url, provider_config.private_core_jwks[0], get_wallet_instance_pubkey(), x5c
    )

    # fake instance data
    wua_issuer.set_user_authentication(instance_conf.get("user_authentication"))
    wua_issuer.set_key_storage(instance_conf.get("key_storage"))
    wua_issuer.set_certification(instance_conf.get("certification"))
    wua_issuer.set_attested_keys([get_wallet_instance_pubkey()])
    wua_issuer.set_status({"status_list": {}})

    # wua_issuer.set_trust_chain(...) #todo [optional]
    return wua_issuer.generate_jws()


def verify_attestation_req_payload(payload) -> bool:
    nonce = payload.get("nonce")
    if validate_nonce(nonce) != 0:
        return False
    ...  # todo verify wallet-instance claims
    return True


def validate_nonce(nonce) -> int:
    """
    Simulate nonce validation
    Returns integer: -1 expired nonce; 1 already consumed; 0 valid nonce
    """
    if nonce not in valid_nonces:
        logger.info("Nonce expired")
        return -1
    now = time.time()
    if now > valid_nonces[nonce]:
        del valid_nonces[nonce]
        logger.info("Invalid nonce or already consumed")
        return 1
    del valid_nonces[nonce]
    logger.info("Nonce validated")
    return 0


def get_wallet_instance_pubkey() -> dict:  # todo remove and use init_wallet_instance() endpoint
    """Retrieve wallet instance hardware public key"""
    public_key_path = os.path.join("config", "pub_key.pem")
    wallet_public_key = ec_public_key_from_pem_file(public_key_path)
    hw_public_jwk = pub_ec_key_obj_to_jwk(wallet_public_key).export_public(as_dict=True)
    return hw_public_jwk
