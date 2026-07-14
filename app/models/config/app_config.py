from typing import Literal, Optional

from pydantic import BaseModel

from app.models.config.credentials_config import CredentialsConfig
from app.models.config.provider_config import ProviderConfig

#TODO: validations to be implemented

class LogSetting(BaseModel):
    filepath: Optional[str] = None
    filename: Optional[str] = None
    level: Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
    libs_enabled: bool
    libs_level: Optional[Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]] = "INFO"

class Settings(BaseModel):
    logging: LogSetting

class AppConfig(BaseModel):
    provider_config: ProviderConfig
    credentials_config: CredentialsConfig
    settings: Settings

    # TODO: remove workaround when will be dismiss old config.json management
    app: dict
    wallet_instance: dict
    ms_trust_configuration: dict
    metadata: dict
