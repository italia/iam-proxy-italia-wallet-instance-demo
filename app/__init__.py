import logging
import logging.config
import os
import sys
from logging.handlers import RotatingFileHandler

import yaml
from flask import Flask, g, has_app_context

from app.constants import APP_SETTINGS_KEY, CONFIG_DIR, CORRELATION_ID_FALLBACK
from app.models import AppConfig
from app.routes.itwallet_routes import wallet_api_bp
from app.routes.main_routes import main_routes
from app.routes.wallet_provider import provider_bp
from app.routes.wallet_routes import wallet_routes
from app.utils.utils import remove_str_prefix, sanitize_for_logging

DEBUG_LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(short_logger_name)-10.15s | %(levelname)-8s | %(correlation_id)s | %(filename)s:%(lineno)d | %(message)s"
LOG_FORMAT = (
    "%(asctime)s.%(msecs)03d | %(short_logger_name)-10.15s | %(levelname)-8s | %(correlation_id)s | %(message)s"
)


class PackageOnlyFilter(logging.Filter):
    """
    Logging filter that allows only log records originating from this application package.
    """

    def filter(self, record):
        return record.name.startswith(__name__)


class LogFormatFilter(logging.Filter):
    """
    Logging filter that enriches each log record with the current request's correlation ID and other.

    The correlation ID is read from Flask's application context via
    ``g.correlation_id``, set by the ``X-Correlation-ID`` HTTP header.
    """

    def filter(self, record):
        record.correlation_id = (
            getattr(g, "correlation_id", CORRELATION_ID_FALLBACK) if has_app_context() else CORRELATION_ID_FALLBACK
        )
        record.short_logger_name = record.name.split(".")[0]  # extract main module name
        return True


def _loader_include(loader, node):
    nome_file = os.path.join(os.path.dirname(loader.name), loader.construct_scalar(node))
    with open(nome_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _loader_env_var(loader, node):
    """
    Extracts the environment variable from the node's value.
    :param yaml.Loader loader: the yaml loader
    :param node: the current node in the yaml
    :return: value of the environment variable
    """
    raw_value = loader.construct_scalar(node)
    new_value = os.environ.get(raw_value)
    if new_value is None:
        msg = "Cannot construct value from {node}: {value}".format(node=node, value=new_value)
        raise yaml.YAMLError(msg)
    return new_value


yaml.SafeLoader.add_constructor("!INCLUDE", _loader_include)
yaml.SafeLoader.add_constructor("!ENV", _loader_env_var)


def setup_logging(app):
    settings = app.config[APP_SETTINGS_KEY].app.logging
    _level = getattr(logging, settings.level, logging.INFO)

    logging.captureWarnings(True)

    if _level == logging.DEBUG:
        fmt = logging.Formatter(DEBUG_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    else:
        fmt = logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

    if settings.filename and settings.filepath:
        _handler = RotatingFileHandler(
            os.path.join(settings.filepath, settings.filename),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
    else:
        _handler = logging.StreamHandler(sys.stdout)

    _handler.setLevel(_level)
    _handler.setFormatter(fmt)
    _handler.addFilter(LogFormatFilter())

    # configure ROOT logger
    root_logger = logging.getLogger()
    root_logger.setLevel(_level)
    root_logger.handlers.clear()
    root_logger.addHandler(_handler)

    app.logger.setLevel(_level)  # flask

    if not settings.libs_enabled:  # disable lib logger
        _handler.addFilter(PackageOnlyFilter())
    else:
        logging.getLogger("werkzeug")  # init a lazy logger otherwise not in loggerDict
        for logger_name in logging.Logger.manager.loggerDict:
            if logger_name.startswith(__name__):  # skip app module
                continue
            logging.getLogger(logger_name).setLevel(settings.libs_level)


def load_config(app):

    config_path = os.path.join(os.getcwd(), CONFIG_DIR)
    if not os.path.exists(config_path):
        raise ValueError(f"Failed to load configuration: The folder {config_path} does not exist.")

    try:
        with open(os.path.join(config_path, "app_config.yaml"), "r", encoding="utf-8") as f:
            _config = yaml.safe_load(f)
            config = AppConfig.model_validate(_config)
            app.config.update(dict(SETTINGS=config))

            config_data = {
                nome: getattr(config, nome) for nome, field in config.model_fields.items() if field.annotation is dict
            }
            app.config.update(config_data)
    except Exception as e:
        raise ValueError("Failed to load configuration") from e


def create_app():
    # setup app
    app = Flask(__name__)
    load_config(app)
    app.secret_key = app.config[APP_SETTINGS_KEY].app.secret_key
    setup_logging(app)

    # Register blueprints
    app.register_blueprint(provider_bp)
    app.register_blueprint(main_routes)
    app.register_blueprint(wallet_routes)
    app.register_blueprint(wallet_api_bp)
    return app
