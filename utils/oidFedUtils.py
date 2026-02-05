import json
import logging
import time
from urllib.parse import urlparse

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)


def oid_fed_list(
    base_url: str,
    query_string: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> list[str]:
    """
    Invia una richiesta GET /list con retry in caso di errore di connessione.

    Args:
        base_url: URL base dell'issuer (es. http://localhost:8080)
        query_string: query string da usare nella richiesta
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Una lista di stringhe (federation entity identifier) ottenute da un JSON array.
        In caso di errore, rilancia un'eccezione.
    """
    url = base_url.rstrip("/") + "/list" + query_string
    parsed = urlparse(url)
    host = parsed.hostname

    use_proxy = False

    if proxies:
        use_proxy = True

        if no_proxy_domains:
            for domain in no_proxy_domains:
                if host == domain or host.endswith(f".{domain}"):
                    use_proxy = False
                    break

    headers = {
        "Accept": "application/json",
    }

    logger.debug(f">>>> Invio GET {url} (use_proxy={use_proxy})")
    logger.debug("Headers:")
    logger.debug(json.dumps(headers, indent=2))

    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.get(url, headers=headers, verify=False, proxies=proxies)
            else:
                response = requests.get(url, headers=headers, verify=False)

            logger.debug(f">>>> HTTP {response.status_code}")
            if response.ok:
                content_type = response.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    json_array = response.json()
                    if isinstance(json_array, list) and all(isinstance(item, str) for item in json_array):
                        logger.debug("✅ Array ricevuto:")
                        logger.debug(json.dumps(json_array, indent=2))
                        return json_array
                    else:
                        logger.error("❌ Risposta JSON non è un array di stringhe")
                        return []
                else:
                    logger.error("❌ Risposta non application/json")
                    return []
            else:
                # HTTP error, come 400 Bad Request
                logger.error(f"❌ Errore HTTP {response.status_code}")
                logger.error(f"Contenuto risposta: {response.text}")
                raise RuntimeError(f"Errore HTTP {response.status_code}: {response.text}")
        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            last_exception = ce
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            # Altri errori di richiesta, rilancio subito
            logger.error(f"❌ Internal error: {re}")
            raise
        except ValueError as ve:
            logger.error(f"❌ Internal error: {ve}")
            raise
        except Exception as e:
            logger.error(f"❌ Internal error: {e}")
            raise

    # Se siamo qui, tutti i tentativi sono falliti per motivi di connessione
    if last_exception:
        raise last_exception
    else:
        raise RuntimeError("Richiesta fallita, ma senza eccezioni di rete.")


def oid_fed_fetch_openid_configuration(
    base_url: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> str:
    """
    Invia una richiesta GET /.well-known/openid-federation con retry in caso di errore di connessione.

    Args:
        base_url: URL base dell'issuer (es. http://localhost:8080)
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Il JWT rappresentnte l'entity statement.
        In caso di errore, rilancia un'eccezione.
    """
    url = base_url.rstrip("/") + "/.well-known/openid-federation"
    parsed = urlparse(url)
    host = parsed.hostname

    use_proxy = False

    if proxies:
        use_proxy = True

        if no_proxy_domains:
            for domain in no_proxy_domains:
                if host == domain or host.endswith(f".{domain}"):
                    use_proxy = False
                    break

    headers = {
        "Accept": "application/entity-statement+jwt",
    }

    logger.debug(f">>>> Invio GET {url} (use_proxy={use_proxy})")
    logger.debug("Headers:")
    logger.debug(json.dumps(headers, indent=2))

    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.get(url, headers=headers, verify=False, proxies=proxies)
            else:
                response = requests.get(url, headers=headers, verify=False)

            logger.debug(f">>>> HTTP {response.status_code}")
            if response.ok:
                content_type = response.headers.get("Content-Type", "")
                if "application/entity-statement+jwt" in content_type:
                    jwt_text = response.text.strip()
                    logger.debug("✅ JWT ricevuto:")
                    logger.debug(jwt_text)
                    return jwt_text
                else:
                    logger.error(f"❌ Risposta non application/entity-statement+jwt ma {content_type}")
                    raise RuntimeError(f"Risposta non application/entity-statement+jwt ma {content_type}")
            else:
                # HTTP error, come 400 Bad Request
                logger.error(f"❌ Errore HTTP {response.status_code}")
                logger.error(f"Contenuto risposta: {response.text}")
                raise RuntimeError(f"Errore HTTP {response.status_code}: {response.text}")
        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            last_exception = ce
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            # Altri errori di richiesta, rilancio subito
            logger.error(f"❌ Internal error: {re}")
            raise
        except ValueError as ve:
            logger.error(f"❌ Internal error: {ve}")
            raise
        except Exception as e:
            logger.error(f"❌ Internal error: {e}")
            raise

    # Se siamo qui, tutti i tentativi sono falliti per motivi di connessione
    if last_exception:
        raise last_exception
    else:
        raise RuntimeError("Richiesta fallita, ma senza eccezioni di rete.")
