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

class AppSettings(BaseModel):
    secret_key: str
    logging: LogSetting
    host: str
    port: int
    debug_mode: bool
    favicon_subpath: str
    static_folder: str

class AppConfig(BaseModel):
    provider_config: ProviderConfig
    credentials_config: CredentialsConfig
    app: AppSettings
    wallet_instance: dict
    ms_trust_configuration: dict
    metadata: dict
