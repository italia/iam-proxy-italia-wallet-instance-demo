import json
import logging
import secrets

from flask import Blueprint, Response, request

from models.provider_config import ProviderConfig
from service.ec_manager import ECBaseManager

logger = logging.getLogger(__name__)

provider_routes = Blueprint("provider_routes", __name__, url_prefix='/provider')
provider_config = None
instance_conf = None


@provider_routes.record_once
def on_load(state):
    global provider_config
    provider_config = ProviderConfig(state.app.config.get("wallet_provider"))
    instance_conf = ProviderConfig(state.app.config.get("wallet_instance"))


@provider_routes.route('/.well-known/openid-federation', methods=['GET'], strict_slashes=False)
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

@provider_routes.route('/nonce', methods=['GET'], strict_slashes=False)
def wallet_nonce():
    nonce = secrets.token_hex(16)
    data = json.dumps(dict(nonce=nonce))
    status = 200
    mimetype = 'application/json'
    return Response(response=data, status=status, mimetype=mimetype)

@provider_routes.route('/instance-initialization', methods=['POST'], strict_slashes=False)
def init_wallet_instance():
    ...

@provider_routes.route('/wallet-attestation', methods=['POST'], strict_slashes=False)
def wallet_attestations():
    data = None
    status = 500
    mimetype = 'text/plain'

    data = request.get_json()
    assertion_jwt = data.get('assertion')
    if not assertion_jwt:
        code = 400



    return Response(response=data, status=status, mimetype=mimetype)

