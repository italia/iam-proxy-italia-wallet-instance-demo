import json
import logging.config
import os

from flask import Flask, g, has_app_context

from app.routes.itwallet_routes import wallet_api_bp
from app.routes.main_routes import main_routes
from app.routes.wallet_provider import provider_bp
from app.routes.wallet_routes import wallet_routes
from app.utils.utils import remove_str_prefix, sanitize_for_logging
from settings import CONFIG_DIR, CORRELATION_ID_FALLBACK, SECRET_KEY


# Definizione del filtro per correlation_id
class CorrelationIdFilter(logging.Filter):
    """Il filtro CorrelationIdFilter prende la correlation_id dalla request corrente di Flask tramite g.correlation_id.
    g è un oggetto globale di Flask valido solo per la richiesta corrente.
    Prima che arrivi ogni richiesta, il middleware @app.before_request imposta g.correlation_id con il valore
    dell'header HTTP X-Correlation-ID. Se la request non ha quell'header, mette "N/A"."""

    def filter(self, record):
        # Prova a leggere la correlation_id dalla request, altrimenti None
        if has_app_context():
            record.correlation_id = getattr(g, "correlation_id", CORRELATION_ID_FALLBACK)
        else:
            record.correlation_id = CORRELATION_ID_FALLBACK
        return True


def load_config(app):
    """
    Loads application settings from a JSON configuration file.

    Initializes the logging system using the provided configuration or
    falls back to a default INFO level. Sanitizes error outputs to
    prevent log injection.
    """
    config_path = os.path.join(os.getcwd(), CONFIG_DIR, "config.json")
    try:
        with open(config_path) as f:
            config_data = json.load(f)
            app.config.update(config_data)

        if "logging" in config_data:  # Configure logging
            logging.config.dictConfig(config_data["logging"])
            logger = logging.getLogger(__name__)
            logger.info("Logging system initialized from config.json.")
        else:  # fallback logging base
            logging.basicConfig(level=logging.INFO)
            logger = logging.getLogger(__name__)
            logger.warning("No logging configuration found; using default settings.")

    except Exception as e:
        # Fallback logging if file read or JSON parsing fails
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        logger.error("Failed to load configuration: %s", sanitize_for_logging(str(e)))


def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    load_config(app)

    # Register blueprints
    app.register_blueprint(provider_bp)
    app.register_blueprint(main_routes)
    app.register_blueprint(wallet_routes)
    app.register_blueprint(wallet_api_bp)
    return app
