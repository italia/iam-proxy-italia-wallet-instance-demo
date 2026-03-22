import importlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


class MetadataFactory:
    @staticmethod
    def get_model_instance(spec_version: str) -> Any:
        """
        Dynamically imports the 'metadata.py' from the version folder and validates data.

        :param spec_version: String like '1.0.0' or '1.3.3' represent specification version of IT-Wallet
        :return: An instance of the version-specific MetadataModel
        """
        v_folder = spec_version.replace(".", "_")
        relative_path = f".{v_folder}.metadata"

        try:
            logger.info(f"Attempting to load metadata version: {spec_version}")
            module = importlib.import_module(relative_path, package=__package__)
            return getattr(module, "MetadataGroup")

        except ImportError as e:
            logger.error(f"Version folder '{v_folder}' not found at {relative_path}. Error: {e}")

        except AttributeError as e:
            logger.error(f"Module {relative_path} does not define 'MetadataGroup'. Error: {e}")
        return None
