import logging
from typing import Optional, Tuple

from app.utils.utils import sanitize_for_logging

logger = logging.getLogger(__name__)


class CredentialStore:
    def __init__(self):
        self._store = {}

    def count(self):
        """
        Return the number of credentials stored in the store.
        @return int
        """
        count = 0
        if not self._store:
            return 0
        stack = [self._store]
        stack_pop = stack.pop
        stack_append = stack.append
        while stack:
            current = stack_pop()
            for k, v in current.items():
                if type(v) is dict:
                    stack_append(v)
                else:
                    count += 1
        return count

    def add_credential(self, issuer: str, key, data_row, vct, claims=None, status_assertion=None, status=None):
        logger.debug(
            f"Entering method: add_credential_from_issuer. Params [issuer: {issuer}, key: {key}, data_row: {data_row}, vct: {vct}, claims: {claims}, status_assertion: {status_assertion}, status: {status}]"
        )
        if not self._store.get(issuer):
            # Issuer is not present, i can add the credential directly
            self.__add_credential_into_store(issuer, key, data_row, vct, claims, status_assertion, status)
        else:
            # Issuer is already present, i need to check if the credential is already present or not
            if key not in self._store[issuer]:
                # Credential is not present, i need to update it
                self.__update_credential_into_store(issuer, key, data_row, vct, claims, status_assertion, status)
            else:
                # The credential is already present, @TODO to decide if update it or not, need to talking with Giuseppe
                logger.debug(f"Credential with key {key} already present for issuer {issuer}! Update not performed.")

    def __add_credential_into_store(
        self, issuer: str, key, data_row, vct, claims=None, status_assertion=None, status=None
    ):
        logger.debug(
            f"Entering method: add_credential_into_store. Params [issuer: {issuer}, key: {key}, data_row: {data_row}, vct: {vct}, claims: {claims}, status_assertion: {status_assertion}, status: {status}]"
        )

        entry = self.__get_entity_store(data_row, vct, claims, status_assertion, status)

        self._store[issuer] = {key: entry}

    def __update_credential_into_store(
        self, issuer: str, key, data_row, vct, claims=None, status_assertion=None, status=None
    ):
        logger.debug(
            f"Entering method: __update_credential_into_store. Params [issuer: {issuer}, key: {key}, data_row: {data_row}, vct: {vct}, claims: {claims}, status_assertion: {status_assertion}, status: {status}]"
        )

        entry = self.__get_entity_store(data_row, vct, claims, status_assertion, status)

        self._store[issuer][key] = entry

    def _get_credential_into_store(self, issuer: str, key: str) -> Optional[dict]:
        """
        Return the credential entry for the given issuer and key, or None if not found.
        """
        logger.debug(f"Entering method: _get_credential_into_store. Params [issuer: {issuer}, key: {key}]")
        return self._store.get(issuer, {}).get(key)

    def __get_entity_store(self, data_row, vct, claims=None, status_assertion=None, status=None) -> dict:
        """
        Return the credential entry
        """
        logger.debug(
            f"Entering method: __get_entity_store. Params [data_row: {data_row}, vct: {vct}, claims: {claims}, status_assertion: {status_assertion}, status: {status}]"
        )

        entry = {"data_row": data_row, "vct": vct}

        if claims is not None:
            entry["claims"] = claims

        if status_assertion is not None:
            entry["status_assertion"] = status_assertion

        if status is not None:
            entry["status"] = status

        return entry

    # @TODO DEPRECATED - to remove after refactor of add_credential method
    def add(self, key, data_row, vct, claims=None, status_assertion=None, status=None) -> None:
        """
        Aggiunge o aggiorna una credenziale.
        Salva un dizionario strutturato come valore.
        """

        entry = {"data_row": data_row, "vct": vct}

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

    def get_store(self):
        """
        Return all dictionary of the store.
        @return dict
        """
        return self._store

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
        # codeql[py/log-injection]
        logger.debug(
            "🔍 Ricerca nel wallet crededenziale la cui chiave ha come prefisso: %s",
            sanitize_for_logging(repr(prefix_lower)),
        )
        for k, v in self._store.items():
            if isinstance(k, str) and k.lower().startswith(prefix_lower):
                return v
        return None

    # @TODO DEPRECATED - to remove after refactor of find_by_prefix method
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
        # codeql[py/log-injection]
        logger.debug("🔍 Ricerca nel wallet crededenziale il cui vct è: %s", sanitize_for_logging(vct))
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
