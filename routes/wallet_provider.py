import json
import logging
import os
import secrets
import time

from flask import Blueprint, Response, request, session, jsonify

from models.provider_config import ProviderConfig
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.wallet_instance_attestations.issuers.wia import WiaJswIssuer
from pyeudiw.wallet_instance_attestations.issuers.wua import WuaJswIssuer
from service.ec_manager import ECBaseManager
from utils.utils import ec_public_key_from_pem_file, pub_ec_key_obj_to_jwk

logger = logging.getLogger(__name__)

provider_bp = Blueprint("provider_bp", __name__, url_prefix='/provider')
provider_config: ProviderConfig = None
instance_conf = None

NONCE_TTL = 300

valid_nonces = {}

@provider_bp.record_once
def on_load(state):
    global provider_config
    provider_config = ProviderConfig(state.app.config.get("wallet_provider"))


@provider_bp.route('/.well-known/openid-federation', methods=['GET'], strict_slashes=False)
def wallet_provider_entity_configuration():
    _format = request.args.get('format', default='jwt')

    data = None
    status = 500
    mimetype = 'text/plain'

    try:
        entity_config = ECBaseManager(provider_config)
        if _format == "json":
            data = json.dumps(entity_config.dump_as_dict())
            status = 200
            mimetype = 'application/json'
        elif _format == "jwt":
            data = entity_config.dump_as_jwt()
            status = 200
            mimetype = 'application/entity-statement+jwt'
    except Exception as e:
        exc_info = logger.getEffectiveLevel() == logging.DEBUG
        logger.error(f"An error occurred while generating entity configuration. Error: {e}", exc_info=exc_info)
        pass

    return Response(response=data, status=status, mimetype=mimetype)

@provider_bp.route('/nonce', methods=['GET'], strict_slashes=False)
def wallet_nonce():
    nonce = secrets.token_hex(16)
    data = json.dumps(dict(nonce=nonce))
    status = 200
    mimetype = 'application/json'
    session['active_nonce'] = nonce
    valid_nonces[nonce] = time.time() + NONCE_TTL
    return Response(response=data, status=status, mimetype=mimetype)

@provider_bp.route('/instance-initialization', methods=['POST'], strict_slashes=False)
def init_wallet_instance():
    ... #todo

@provider_bp.route('/wallet-attestation', methods=['POST'], strict_slashes=False)
def wallet_attestations():
    body = request.get_json()
    assertion_jwt = body.get('assertion')
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
    except JWSVerificationError as e:
        logger.error("JWT verification failed: The request for wallet attestations has expired.")
    except Exception as e:
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

def generate_wia():
    x5c = provider_config.get_x5c_federation_by_kid(provider_config.private_fed_jwks[0].get("kid"))
    wia_issuer = WiaJswIssuer(provider_config.public_url, provider_config.private_fed_jwks[0], get_wallet_instance_pubkey(), x5c)

    # todo
    wia_issuer.set_wallet_link(...)
    wia_issuer.set_wallet_name(...)
    wia_issuer.set_status(...)
    wia_issuer.set_nbf(...)
    wia_issuer.set_trust_chain(...)

    return wia_issuer.generate_jws()

def generate_wua():
    x5c = provider_config.get_x5c_federation_by_kid(provider_config.private_fed_jwks[0].get("kid"))
    wua_issuer = WuaJswIssuer(provider_config.public_url, provider_config.private_fed_jwks[0], get_wallet_instance_pubkey(), x5c)

    # todo
    wua_issuer.set_trust_chain(...)
    wua_issuer.set_certification(...)
    wua_issuer.set_status(...)
    wua_issuer.set_user_authentication(...)
    wua_issuer.set_key_storage(...)
    wua_issuer.set_attested_keys(...)

    return wua_issuer.generate_jws()

def verify_attestation_req_payload(payload) -> bool:
    nonce = payload.get('nonce')
    if validate_nonce(nonce) != 0:
        return False
    ... #todo
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


def get_wallet_instance_pubkey() -> dict: #todo remove and use init_wallet_instance() endpoint
    """Retrieve wallet instance hardware public key"""
    public_key_path = os.path.join("config", "pub_key.pem")
    wallet_public_key = ec_public_key_from_pem_file(public_key_path)
    hw_public_jwk = pub_ec_key_obj_to_jwk(wallet_public_key).export_public(as_dict=True)
    return hw_public_jwk