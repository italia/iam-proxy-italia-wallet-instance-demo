# state.py
import logging
from typing import Optional, Tuple

import jmespath

logger = logging.getLogger(__name__)

class CredentialStore:
    def __init__(self):
        self._store = {}

    def add(self, key, data_row, vct, claims=None, status_assertion=None, status=None) -> None:
        """
        Aggiunge o aggiorna una credenziale.
        Salva un dizionario strutturato come valore.
        """

        entry = {
            "data_row": data_row,
            "vct": vct
        }

        if claims is not None:
            entry["claims"] = claims

        if status_assertion is not None:
            entry["status_assertion"] = status_assertion

        if status is not None:
            entry["status"] = status

        self._store[key] = entry

    def get(self, key) -> dict:
        """
        Cerca una credenziale per key.
        Restituisce il dizionario {"data_row": ..., "vct": ..., "claims": ..., "status_assertion": ..., "status": ... } o None.
        """
        return self._store.get(key)

    def remove(self, key) -> None:
        """
        Rimuove una credenziale se esiste ricercandola per key.
        Elimina il dizionario {'data_row': ..., "vct": ..., 'claims': ..., "status_assertion": ..., "status": ... }.
        """
        if key in self._store:
            del self._store[key]

    def exists(self, key) -> bool:
        """Verifica se una credenziale è presente."""
        return key in self._store

    def keys(self) -> list[str]:
        """Restituisce una lista di tutte le chiavi presenti nello store."""
        return list(self._store.keys())

    def keys_with_vct(self) -> list[str]:
        """
        Restituisce una lista di stringhe del tipo "chiave:vct".
        Se il vct non è presente, usa stringa vuota dopo i due punti.
        """
        result = []
        for k, entry in self._store.items():
            vct = entry.get("vct", "")
            result.append(f"{k}:{vct}")
        return result

    def all_values(self) -> list[dict]:
        """
        Restituisce tutti i valori dello store.
        """
        return list(self._store.values())

    def all(self) -> list[dict]:
        """
        Restituisce tutti gli elementi dello store come lista di dizionari,
        includendo sia le chiavi che i valori.
        """
        return [{"key": k, "value": v} for k, v in self._store.items()]

    def clear(self) -> None:
        """Pulisce completamente lo store."""
        self._store.clear()

    def find_by_prefix(self, prefix: str) -> Optional[dict]:
        """
        Restituisce la prima credenziale trovata la cui chiave inizia con il prefisso dato (case insensitive),
        oppure None se non ne trova.
        Restituisce il dizionario {"data_row": ..., "vct": ..., "claims": ..., "status_assertion": ..., "status": ... } o None.
        """
        prefix_lower = prefix.lower()
        logger.debug(f"🔍 Ricerca nel wallet crededenziale la cui chiave ha come prefisso: {repr(prefix_lower)}")
        for k, v in self._store.items():
            if isinstance(k, str) and k.lower().startswith(prefix_lower):
                return v
        return None

    def find_by_prefix_with_key(self, prefix: str) -> Optional[Tuple[str, dict]]:
        """
        Restituisce la prima credenziale trovata la cui chiave inizia con il prefisso dato (case insensitive),
        oppure None se non ne trova.
        Restituisce una tupla (chiave, valore) o None.
        Valore è il dizionario {"data_row": ..., "vct": ..., "claims": ..., "status_assertion": ..., "status": ... } o None.
        """
        prefix_lower = prefix.lower()
        for k, v in self._store.items():
            if isinstance(k, str) and k.lower().startswith(prefix_lower):
                return (k, v)
        return None

    def find_by_vct(self, vct: str) -> Optional[Tuple[str, dict]]:
        """
        Cerca una credenziale per vct (restituisce la prima che trova)
        Restituisce una tupla (chiave, valore) o None.
        Valore è il dizionario {"data_row": ..., "vct": ..., "claims": ..., "status_assertion": ..., "status": ... } o None.
        """
        logger.debug(f"🔍 Ricerca nel wallet crededenziale il cui vct è: {vct}")
        for k, entry in self._store.items():
            if entry.get("vct") == vct:
                return (k, entry)
        return None

    def update_status(self, key: str, new_status_assertion: str, new_status: str) -> bool:
        """
        Aggiorna lo status della credenziale identificata dalla chiave.

        Args:
            key: La chiave della credenziale da aggiornare.
            new_status_assertion: La nuova status assertion
            new_status: Il nuovo valore dello status.

        Returns:
            True se l'aggiornamento è avvenuto, False se la chiave non esiste.
        """
        if key in self._store:
            self._store[key]["status_assertion"] = new_status_assertion
            self._store[key]["status"] = new_status
            return True
        return False

class EntityConfigurationStore:
    def __init__(self):
        self._store = {}

    def add(self, key, value) -> None:
        """
        Aggiunge o aggiorna un EntityConfiguration.
        """
        self._store[key] = value

    def get(self, key) -> dict:
        """
        Cerca un EntityConfiguration.
        """
        return self._store.get(key)

    def remove(self, key) -> None:
        """
        Rimuove un EntityConfiguration se esiste ricercandolo per key.
        """
        if key in self._store:
            del self._store[key]

    def exists(self, key) -> bool:
        """Verifica se un EntityConfiguration è presente."""
        return key in self._store

    def keys(self) -> list[str]:
        """Restituisce una lista di tutte le chiavi presenti nello store."""
        return list(self._store.keys())

    def clear(self) -> None:
        """Pulisce completamente lo store."""
        self._store.clear()

    def all_values(self, jmes_query: str = None) -> list[dict]:
        """
        Restituisce tutti i valori dello store.
        Se `jmes_query` è fornito, ritorna solo quelli per cui il filtro restituisce un valore non None.
        """
        if not jmes_query:
            return list(self._store.values())

        filtered_values = []
        for v in self._store.values():
            if not isinstance(v, dict):
                continue
            result = jmespath.search(jmes_query, v)
            if result:
                filtered_values.append(v)
        return filtered_values

    def all(self) -> list[dict]:
        """
        Restituisce tutti gli elementi dello store come lista di dizionari,
        includendo sia le chiavi che i valori.
        """
        return [{"key": k, "value": v} for k, v in self._store.items()]

    def update_claim_by_path(self, key: str, json_path: str, new_value) -> bool:
        """
        Aggiorna il valore individuato da un json_path dentro l'oggetto JSON
        salvato sotto la chiave `key`.

        Esempio:
            json_path="claims.role"
        """
        value = self._store.get(key)
        if not isinstance(value, dict):
            return False

        path_parts = json_path.split(".")
        target = value
        for part in path_parts[:-1]:
            if part not in target or not isinstance(target[part], dict):
                return False
            target = target[part]

        last_key = path_parts[-1]
        target[last_key] = new_value
        return True

    def _replace_recursive(self, obj, old: str, new: str) -> int:
        """
        Ricorsivamente sostituisce old->new in tutte le stringhe di dict/list.
        Ritorna il numero totale di sostituzioni effettuate.
        """
        count = 0
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    new_v = v.replace(old, new)
                    if new_v != v:
                        obj[k] = new_v
                        count += 1
                else:
                    count += self._replace_recursive(v, old, new)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    new_item = item.replace(old, new)
                    if new_item != item:
                        obj[i] = new_item
                        count += 1
                else:
                    count += self._replace_recursive(item, old, new)
        return count

    def replace_in_all_value_fields(self, old: str, new: str) -> int:
        """
        Sostituisce old->new **ovunque** all'interno dei valori delle entità dello store.
        Ritorna il numero totale di sostituzioni effettuate.
        """
        total = 0
        for v in self._store.values():
            total += self._replace_recursive(v, old, new)
        return total


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
