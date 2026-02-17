import json
import logging

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from utils.http_utils import http_request_with_retry
from utils.utils import sanitize_for_logging

logger = logging.getLogger(__name__)


def _parse_oid_fed_list(response: requests.Response) -> list[str]:
    """Parse JSON array of strings from oid_fed_list response."""
    ct = response.headers.get("Content-Type", "")
    if "application/json" not in ct:
        logger.error("❌ Risposta non application/json")
        return []
    data = response.json()
    if isinstance(data, list) and all(isinstance(x, str) for x in data):
        # codeql[py/log-injection]
        logger.debug("✅ Array ricevuto: %s", sanitize_for_logging(json.dumps(data, indent=2)))
        return data
    logger.error("❌ Risposta JSON non è un array di stringhe")
    return []


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
    headers = {"Accept": "application/json"}
    # codeql[py/log-injection]
    logger.debug(">>>> Invio GET %s", sanitize_for_logging(url))
    result = http_request_with_retry(
        "GET",
        url,
        headers=headers,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_oid_fed_list,
    )
    if not result:
        return []
    return result


def _parse_entity_statement_jwt(response: requests.Response) -> str:
    """Parse JWT from entity-statement response."""
    ct = response.headers.get("Content-Type", "")
    if "application/entity-statement+jwt" not in ct:
        raise RuntimeError(f"Risposta non application/entity-statement+jwt ma {ct}")
    return response.text.strip()


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
    headers = {"Accept": "application/entity-statement+jwt"}
    # codeql[py/log-injection]
    logger.debug(">>>> Invio GET %s", sanitize_for_logging(url))
    return http_request_with_retry(
        "GET",
        url,
        headers=headers,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_entity_statement_jwt,
    )
