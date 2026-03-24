import jmespath


class EntityConfigurationStore:
    def __init__(self):
        self._store = {}

    def add(self, key, value) -> None:
        """
        Aggiunge o aggiorna un EntityConfiguration.
        """
        self._store[key] = value

    def get(self, key) -> dict|None:
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
