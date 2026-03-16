import logging

from store.credential_store import CredentialStore
from store.entity_config_store import EntityConfigurationStore

logger = logging.getLogger(__name__)


class AppState:
    def __init__(self):
        self.stored_hashed_pin = None
        self.wallet_initialized = False
        self.selected_country = ""
        self.selected_idp = ""
        self.credential_store = CredentialStore()
        self.ec_store = EntityConfigurationStore()

    def get_store_types(self) -> list[str]:
        """
        Restituisce solo i tipi di oggetti 'store' presenti in memoria.
        """
        types = []
        for attr_value in self.__dict__.values():
            if isinstance(attr_value, (CredentialStore, EntityConfigurationStore)):
                types.append(type(attr_value).__name__)
        return types

    def get_store(self, name: str):
        """
        Restituisce il contenuto dello store richiesto (lista di valori).

        Args:
            name (str): Nome dello store. Può essere "CredentialStore" o "EntityConfigurationStore".

        Returns:
            list: Contenuto dello store, oppure [] se non trovato.
        """
        if name == "CredentialStore":
            return self.credential_store.all()
        elif name == "EntityConfigurationStore":
            return self.ec_store.all()
        else:
            return []

# Creazione istanza globale dello stato
app_state = AppState()
