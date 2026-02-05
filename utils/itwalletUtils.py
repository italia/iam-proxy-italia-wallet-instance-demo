import hashlib
import json
import logging
import time
import uuid
from typing import Tuple
from urllib.parse import urlparse

import jwt
import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from flask import current_app
from jwcrypto import jwe, jwk

from constants import (
    CREDENTIAL_INVALID,
    CREDENTIAL_SUSPENDED,
    CREDENTIAL_VALID,
)
from utils.sdJwtUtils import issue_sd_jwt
from utils.utils import base64url_encode, priv_ec_key_obj_to_jwk, pub_ec_key_obj_to_jwk

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def request_as_par(
    url: str,
    wallet_attestation_jwt: str,
    wallet_attestation_dpop_jwt: str,
    request_object_jwt: str,
    client_id: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> dict:
    """
    Invia una richiesta POST /as/par con retry in caso di errore di connessione.
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuer-endpoint.html#pushed-authorization-request-par-request

    Args:
        url: endpoint URL
        wallet_attestation_jwt: attestazione del client firmata da inserire nell'header OAuth-Client-Attestation della richiesta
        wallet_attestation_dpop_jwt: DPoP JWT firmato da inserire nell'header OAuth-Client-Attestation-PoP della richiesta
        request_object_jwt: JWT firmato da fornire nel paylod della richiesta
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Dizionario JSON della risposta, o eccezione in caso di errore.
    """

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
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json; charset=utf-8",
        "OAuth-Client-Attestation": wallet_attestation_jwt,
        "OAuth-Client-Attestation-PoP": wallet_attestation_dpop_jwt,
    }

    data = {"client_id": client_id, "request": request_object_jwt}

    logger.info(f">>>> Invio POST a {url} (use_proxy={use_proxy})")
    logger.info("📦 Header:")
    logger.info(json.dumps(headers, indent=2))
    logger.info("📦 Payload:")
    logger.info(json.dumps(data, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.post(url, headers=headers, data=data, verify=False, proxies=proxies)
            else:
                response = requests.post(url, headers=headers, data=data, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")

                if not content_type:
                    logger.error("❌ Risposta non valida: Content-Type non indicato")
                    raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")

                if "application/json" in content_type:
                    try:
                        json_response = response.json()
                        logger.info("✅ Risposta OK:")
                        logger.info(json.dumps(json_response, indent=2))
                        return json_response
                    except ValueError as ve:
                        logger.error("❌ Errore nel parsing JSON:", ve)
                        logger.error(f"Contenuto risposta: {response.text}")
                        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}")
                else:
                    logger.error(f"❌ Risposta non valida: Content-Type non è application/json, ma {content_type}")
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
                    )

            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )

        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_authorize(
    url: str,
    query_string: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> str:
    """
    Invia una richiesta GET /authorize con retry in caso di errore di connessione.
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuer-endpoint.html#authorization-request

    Args:
        url: endpoint URL
        query_string: query string da usare nella richiesta
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Il JWT rappresentnte l'entity statement.
        In caso di errore, rilancia un'eccezione.
    """
    url = url + query_string

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

    logger.info(f">>>> Invio GET {url} (use_proxy={use_proxy})")

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.get(url, verify=False, proxies=proxies)
            else:
                response = requests.get(url, verify=False)

            if response.ok:
                response_authorize = response.text.strip()
                logger.info("✅ Risposta:")
                logger.info(response_authorize)
                return response_authorize
            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            # Altri errori di richiesta, rilancio subito
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_token(
    url: str,
    wallet_attestation_jwt: str,
    wallet_attestation_dpop_jwt: str,
    dpop_proof_jwt: str,
    grant_type: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> dict:
    """
    Invia una richiesta POST /token con retry in caso di errore di connessione.
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuer-endpoint.html#token-request

    Args:
        url: endpoint URL
        wallet_attestation_jwt: attestazione del client firmata da inserire nell'header OAuth-Client-Attestation della richiesta
        wallet_attestation_dpop_jwt: DPoP JWT firmato da inserire nell'header OAuth-Client-Attestation-PoP della richiesta
        dpop_proof_jwt: DPoP JWT firmato da inserire nell'header DPoP
        grant_type: tipologia di grant richiesto (es. authorization_code)
        code: authorization code resttuito nell'Authentication Response al termine del processo di autorizzazione iniziato con la par request
        redirect_uri: deve coincidere con il redirect_uri definito nel Request Object della par request
        code_verifier: il code verifier PKCE,
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Dizionario JSON della risposta, o eccezione in caso di errore.
    """

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
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json; charset=utf-8",
        "OAuth-Client-Attestation": wallet_attestation_jwt,
        "OAuth-Client-Attestation-PoP": wallet_attestation_dpop_jwt,
        "DPoP": dpop_proof_jwt,
    }

    data = {"grant_type": grant_type, "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier}

    logger.info(f">>>> Invio POST a {url} (use_proxy={use_proxy})")
    logger.info("📦 Header:")
    logger.info(json.dumps(headers, indent=2))
    logger.info("📦 Payload:")
    logger.info(json.dumps(data, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.post(url, headers=headers, data=data, verify=False, proxies=proxies)
            else:
                response = requests.post(url, headers=headers, data=data, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")

                if not content_type:
                    logger.error("❌ Risposta non valida: Content-Type non indicato")
                    raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")

                if "application/json" in content_type:
                    try:
                        json_response = response.json()
                        logger.info("✅ Risposta OK:")
                        logger.info(json.dumps(json_response, indent=2))
                        return json_response
                    except ValueError as ve:
                        logger.error("❌ Errore nel parsing JSON:", ve)
                        logger.error(f"Contenuto risposta: {response.text}")
                        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}")
                else:
                    logger.error(f"❌ Risposta non valida: Content-Type non è application/json, ma {content_type}")
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
                    )
            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )

        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_credential(
    url: str,
    credential_id: str,
    proof_jwt: str,
    access_token: str,
    dpop_proof_jwt: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> dict:
    """
    Invia una richiesta POST /credential con retry in caso di errore di connessione.
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuer-endpoint.html#credential-request

    Args:
        url: endpoint URL
        credential_id: Identificatore della credenziale (es: DisabilityCard)
        proof_jwt: JWT di tipo 'openid4vci-proof+jwt'
        access_token: Access token firmato (DPoP-bound) da inserire nell'header Authorization
        dpop_proof_jwt: DPoP JWT firmato da inserire nell'header DPoP
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Dizionario JSON della risposta, o eccezione in caso di errore.
    """

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
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; charset=UTF-8",
        "Authorization": f"DPoP {access_token}",
        "DPoP": dpop_proof_jwt,
    }

    data = {"credential_identifier": credential_id, "proof": {"proof_type": "jwt", "jwt": proof_jwt}}

    logger.info(f">>>> Invio POST a {url} (use_proxy={use_proxy})")
    logger.info("📦 Header:")
    logger.info(json.dumps(headers, indent=2))
    logger.info("📦 Payload:")
    logger.info(json.dumps(data, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.post(url, headers=headers, json=data, verify=False, proxies=proxies)
            else:
                response = requests.post(url, headers=headers, json=data, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")

                if not content_type:
                    logger.error("❌ Risposta non valida: Content-Type non indicato")
                    raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")

                if "application/json" in content_type:
                    try:
                        json_response = response.json()
                        logger.info("✅ Risposta OK:")
                        logger.info(json.dumps(json_response, indent=2))
                        return json_response
                    except ValueError as ve:
                        logger.error("❌ Errore nel parsing JSON:", ve)
                        logger.error(f"Contenuto risposta: {response.text}")
                        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}")
                else:
                    logger.error(f"❌ Risposta non valida: Content-Type non è application/json, ma {content_type}")
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
                    )

            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            # Altri errori di richiesta, rilancio subito
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_nonce(
    url: str, max_retries: int = 3, retry_delay: float = 1.0, proxies: dict = None, no_proxy_domains: list[str] = None
) -> str:
    """
    Invia una richiesta POST /nonce con retry in caso di errore di connessione.
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuer-endpoint.html#nonce-endpoint

    Args:
        url: endpoint URL
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Il valore di c_nonce estratto dalla risposta JSON in caso di successo.
        In caso di errore, rilancia un'eccezione.
    """

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
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; charset=UTF-8",
    }

    logger.info(f">>>> Invio POST a {url} (use_proxy={use_proxy})")
    logger.info("📦 Header:")
    logger.info(json.dumps(headers, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.post(url, headers=headers, verify=False, proxies=proxies)
            else:
                response = requests.post(url, headers=headers, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")

                if not content_type:
                    logger.error("❌ Risposta non valida: Content-Type non indicato")
                    raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")

                if "application/json" in content_type:
                    try:
                        json_response = response.json()
                        logger.info("✅ Risposta OK:")
                        logger.info(json.dumps(json_response, indent=2))

                        if json_response:
                            c_nonce = json_response.get("c_nonce")
                            if c_nonce is not None:
                                logger.info(f"✅ c_nonce estratto: {c_nonce}")
                                return c_nonce
                            else:
                                raise ValueError("Il JSON ricevuto non contiene la chiave 'c_nonce'")
                        else:
                            raise ValueError("Il JSON ricevuto non contiene alcun dato")
                    except ValueError as ve:
                        logger.error("❌ Errore nel parsing JSON:", ve)
                        logger.error(f"Contenuto risposta: {response.text}")
                        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}")
                else:
                    logger.error(f"❌ Risposta non valida: Content-Type non è application/json, ma {content_type}")
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
                    )
            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            # Altri errori di richiesta, rilancio subito
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_request_uri(
    url: str,
    query_string: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> str:
    """
    Invio request uri request ad un Relying Party per trasmettere via GET una richiesta di login.
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/remote-flow.html#request-uri-request

    Args:
        url: URL del request uri endpoint del Relying Party
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Dizionario JSON della risposta, o eccezione in caso di errore.
    """
    url = url + query_string

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

    logger.info(f">>>> Invio GET {url} (use_proxy={use_proxy})")

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.get(url, verify=False, proxies=proxies)
            else:
                response = requests.get(url, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")
                if "application/oauth-authz-req+jwt" in content_type:
                    jwt_text = response.text.strip()
                    logger.info("✅ JWT ricevuto:")
                    logger.info(jwt_text)
                    return jwt_text
                else:
                    logger.error(
                        f"❌ Risposta non valida: Content-Type non è application/oauth-authz-req+jwt, ma {content_type}"
                    )
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/oauth-authz-req+jwt, ma {content_type}"
                    )
            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )

        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_response_uri(
    url: str,
    response_uri_request_jwt: str,
    state: str,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> dict:
    """
    Invio response uri request ad un Relying Party per trasmettere via POST le presentazioni delle credenziali richieste e
    lo state precedentemente fornito dal Relying Party nella richiesta di presentazione delle credenziali
    Spec di riferimento: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/remote-flow.html#authorization-response

    Args:
        url: URL del response_uri endpoint del Relying Party
        response_uri_request_jwt: JWT reppresentante la response uri request
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Dizionario JSON della risposta, o eccezione in caso di errore.
    """

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

    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json; charset=utf-8"}

    data = {"response": response_uri_request_jwt, "state": state}

    logger.info(f">>>> Invio POST a {url} (use_proxy={use_proxy})")
    logger.info("📦 Header:")
    logger.info(json.dumps(headers, indent=2))
    logger.info("📦 Payload:")
    logger.info(json.dumps(data, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.post(url, headers=headers, data=data, verify=False, proxies=proxies)
            else:
                response = requests.post(url, headers=headers, data=data, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")

                if not content_type:
                    logger.error("❌ Risposta non valida: Content-Type non indicato")
                    raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")

                if "application/json" in content_type:
                    try:
                        json_response = response.json()
                        logger.info("✅ Risposta OK:")
                        logger.info(json.dumps(json_response, indent=2))
                        return json_response
                    except ValueError as ve:
                        logger.error("❌ Errore nel parsing JSON:", ve)
                        logger.error(f"Contenuto risposta: {response.text}")
                        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}")
                else:
                    logger.error(f"❌ Risposta non valida: Content-Type non è application/json, ma {content_type}")
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
                    )

            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )

        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_presentation_callback(
    url: str, max_retries: int = 3, retry_delay: float = 1.0, proxies: dict = None, no_proxy_domains: list[str] = None
) -> str:
    """
    Invia una richiesta GET alla callback URL fornita in fase di presentazione,

    Args:
        url: Callback URL da contattare
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro
        proxies: Dizionario proxy da passare a requests
        no_proxy_domains: Lista di domini per i quali il proxy non deve essere usato

    Returns:
        Contenuto della risposta finale come stringa

    Raises:
        ConnectionError: se la connessione fallisce dopo max_retries tentativi
        RuntimeError: se la risposta non è OK
    """
    parsed = urlparse(url)
    host = parsed.hostname

    # Determina se usare il proxy
    use_proxy = False
    if proxies:
        use_proxy = True
        if no_proxy_domains:
            for domain in no_proxy_domains:
                if host == domain or host.endswith(f".{domain}"):
                    use_proxy = False
                    break

    logger.info(f">>>> Invio GET {url} (use_proxy={use_proxy})")

    for attempt in range(1, max_retries + 1):
        try:
            current_url = url
            if use_proxy:
                resp = requests.get(current_url, verify=False, proxies=proxies, allow_redirects=False)
            else:
                resp = requests.get(current_url, verify=False, allow_redirects=False)

            logger.info(f"📍 Risposta: {resp.status_code}")
            logger.info(f"📍 Headers: {resp.headers}")
            logger.info(
                f"📍 Body: {resp.text[:500]}{'...' if len(resp.text) > 500 else ''}"
            )  # Limita a 500 caratteri per il log

            if 300 <= resp.status_code < 400 and "Location" in resp.headers:
                redirect_url = resp.headers["Location"]
                logger.info(f"➡️  Redirect verso: {redirect_url}")

                # Creo una "risposta finta" con status 200 e contenuto = redirect_url
                fake_resp = requests.Response()
                fake_resp.encoding = "utf-8"
                fake_resp.headers["Content-Type"] = "text/plain; charset=utf-8"
                fake_resp.status_code = 200
                fake_resp._content = redirect_url.encode("utf-8")  # serve bytes
                response = fake_resp
            else:
                response = resp

            if response.ok:
                response_content = response.text.strip()
                logger.info("✅ Risposta finale:")
                logger.info(response_content)
                return response_content
            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )

        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def request_status(
    url: str,
    status_assertion_requests: list[str],
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict = None,
    no_proxy_domains: list[str] = None,
) -> dict:
    """
    Invia una richiesta POST /status con retry in caso di errore di connessione
    per richiedere la status assertion di una credenziale nel rispetto della
    spec: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-revocation.html#http-status-assertion-request

    Args:
        url: endpoint URL
        status_assertion_requests: Lista di stringhe da includere nel claim "status_assertion_requests"
        max_retries: Numero massimo di tentativi in caso di errore di connessione
        retry_delay: Secondi di attesa tra un tentativo e l'altro

    Returns:
        Status Assertion object in caso di successo.
        In caso di errore, rilancia un'eccezione.
    """
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; charset=UTF-8",
    }

    data = {"status_assertion_requests": status_assertion_requests}

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

    logger.info(f">>>> Invio POST a {url} (use_proxy={use_proxy})")
    logger.info("📦 Header:")
    logger.info(json.dumps(headers, indent=2))
    logger.info("📦 Payload:")
    logger.info(json.dumps(data, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            if use_proxy:
                response = requests.get(url, headers=headers, json=data, verify=False, proxies=proxies)
            else:
                response = requests.post(url, headers=headers, json=data, verify=False)

            if response.ok:
                content_type = response.headers.get("Content-Type", "")

                if not content_type:
                    logger.error("❌ Risposta non valida: Content-Type non indicato")
                    raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")

                if "application/json" in content_type:
                    try:
                        json_response = response.json()
                        logger.info("✅ Risposta OK:")
                        logger.info(json.dumps(json_response, indent=2))
                        return json_response
                    except ValueError as ve:
                        logger.error("❌ Errore nel parsing JSON:", ve)
                        logger.error(f"Contenuto risposta: {response.text}")
                        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}")
                else:
                    logger.error(f"❌ Risposta non valida: Content-Type non è application/json, ma {content_type}")
                    raise RuntimeError(
                        f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
                    )
            else:
                try:
                    # provo a fare parsing JSON
                    parsed = response.json()
                    # lo "flattizzo" in stringa leggibile
                    err = parsed.get("error", "")
                    desc = parsed.get("error_description", "")
                    error_str = f"{err} - {desc}".strip(" -")
                except ValueError:
                    # non è JSON → prendo così com'è
                    error_str = " ".join(response.text.split())

                logger.error(
                    f"❌ Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
                raise RuntimeError(
                    f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
                )
        except requests.ConnectionError as ce:
            logger.error(f"❌ Tentativo {attempt} - Errore di connessione: {ce}")
            if attempt < max_retries:
                time.sleep(retry_delay)
            else:
                logger.error("<<<< ❌ Numero massimo di tentativi raggiunto, abortisco.")
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
        except requests.RequestException as re:
            # Altri errori di richiesta, rilancio subito
            logger.error(f"<<<< ❌ Restituito in risposta: {re}")
            raise
        except ValueError as ve:
            logger.error(f"<<<< ❌ Restituito in risposta: {ve}")
            raise
        except Exception as e:
            logger.error(f"<<<< ❌ Restituito in risposta: {e}")
            raise


def get_status_description(status):
    if status == CREDENTIAL_VALID:
        return "Valido"
    elif status == CREDENTIAL_INVALID:
        return "Non valido"
    elif status == CREDENTIAL_SUSPENDED:
        return "Sospeso"
    else:
        return "Indefinito"


def generate_wallet_attestation_pop_jwt(
    private_key: EllipticCurvePrivateKey, audience: str, lifetime: int = 300
) -> str:
    """
    Genera un client attestation pop JWT firmato con chiave EC nel rispetto
    della specifica https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-03.txt

    Args:
        private_key: Chiave privata EC usata per la firma del JWT.
        audience: audience del jwt
        lifetime: durata del jwt in secondi (default 300 secondi, cioè 5 minuti = 5 x 60 secondi)

    Returns:
        Stringa JWT rappresentante il client attestation pop JWT
    """
    # Estrae chiave pubblica da quella privata
    public_key = private_key.public_key()

    # Converti la chiave pubblica in formato JWK
    public_jwk = jwk.JWK.from_pem(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Estrai il thumbprint come KID (RFC 7638)
    kid = public_jwk.thumbprint()

    # Determina l'algoritmo in base alla curva
    crv = public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Crea il payload JWT
    now = int(time.time())

    payload = {"iss": kid, "aud": audience, "iat": now, "exp": now + int(lifetime), "jti": str(uuid.uuid4())}

    headers = {"typ": "oauth-client-attestation-pop+jwt", "alg": alg, "kid": kid}

    # Serializza la chiave privata per PyJWT
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pop_jwt = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return pop_jwt


def generate_wallet_attestation_jwt(
    issuer_private_key: EllipticCurvePrivateKey,
    client_public_key: EllipticCurvePublicKey,
    issuer: str,
    aal: str,
    lifetime: int = 86400,
) -> str:
    """
    Genera un client attestation JWT firmato con chiave EC nel rispetto
    delle specifiche https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/wallet-provider-endpoint.html#wallet-attestation-jwt

    Args:
        issuer_private_key: Chiave privata EC del wallet provider usata per la firma del JWT,
        client_public_key: Chiave pubblica EC dell'app mobile a cui deve essere collegata l'attestazione,
        issuer: URL dell'issuer del jwt
        aal: livello di sicurezza dell'app mobile
        lifetime: durata dell'access token in secondi (default 86400 secondi, cioè 24 ore)

    Returns:
        Stringa rappresentante il client attestation SD-JWT
    """
    # Converti la chiave privata dell'issuer in formato JWK
    issuer_private_jwk = priv_ec_key_obj_to_jwk(issuer_private_key)

    # Determina l'algoritmo di firma in base alla curva della chiave privata dell'issuer in formato JWK
    crv = issuer_private_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva della chiave privata del wallet provider non supportata: {crv}")

    # Estrai la chiave pubblica di firma da quella privata, convertila in formato JWK ed estrai il thumbprint come KID (RFC 7638)
    issuer_public_key = issuer_private_key.public_key()
    issuer_public_jwk = pub_ec_key_obj_to_jwk(issuer_public_key)
    issuer_public_jwk_kid = issuer_public_jwk.thumbprint()

    # Converti la chiave pubblica dell'app mobile a cui deve essere collegata l'attestazione in formato JWK ed estrai il thumbprint come KID (RFC 7638)
    cnf_public_jwk = pub_ec_key_obj_to_jwk(client_public_key)
    cnf_public_jwk_kid = cnf_public_jwk.thumbprint()

    # Controlla l'algoritmo di firma della chiave pubblica dell'app mobile a cui deve essere collegata l'attestazionein
    cnf_crv = cnf_public_jwk.get("crv")
    cnf_alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    cnf_alg = cnf_alg_map.get(crv)
    if not cnf_alg:
        raise ValueError(f"Curva della chiave pubblica del wallet non supportata: {cnf_crv}")

    now = int(time.time())

    headers = {"typ": "oauth-client-attestation+jwt", "alg": alg, "kid": issuer_public_jwk_kid}

    payload = {
        "iss": issuer,
        "sub": cnf_public_jwk_kid,
        "wallet_name": "IT Wallet",
        "wallet_link": issuer + "/wallet/detail_info.html",
        "aal": aal,
        "iat": now,
        "exp": now + int(lifetime),
        "cnf": {"jwk": cnf_public_jwk},
    }

    # Serializza chiave privata in PEM
    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    signed_jwt = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return signed_jwt


def generate_wallet_attestation_sd_jwt(
    vct: str,
    issuer_private_key: EllipticCurvePrivateKey,
    client_public_key: EllipticCurvePublicKey,
    issuer: str,
    aal: str,
    lifetime: int = 86400,
) -> str:
    """
    Genera un client attestation SD-JWT firmato con chiave EC nel rispetto
    delle specifiche https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/wallet-provider-endpoint.html#wallet-attestation-sd-jwt

    Args:
        vct: id della tipologia di attestazione
        issuer_private_key: Chiave privata EC del wallet provider usata per la firma dell'attestazione JWT,
        client_public_key: Chiave pubblica EC dell'app mobile a cui deve essere collegata l'attestazione,
        issuer: URL dell'issuer del jwt
        aal: livello di sicurezza dell'app mobile
        lifetime: durata dell'access token in secondi (default 86400 secondi, cioè 24 ore)

    Returns:
        Stringa rappresentante il client attestation SD-JWT
    """

    # Converti la chiave privata dell'issuer in formato JWK
    issuer_private_jwk = priv_ec_key_obj_to_jwk(issuer_private_key)
    issuer_private_jwk_dict = issuer_private_jwk.export(as_dict=True)

    # Determina l'algoritmo di firma in base alla curva della chiave privata dell'issuer in formato JWK
    crv = issuer_private_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva della chiave privata del wallet provider non supportata: {crv}")

    # Estrai la chiave pubblica di firma da quella privata, convertila in formato JWK ed estrai il thumbprint come KID (RFC 7638)
    issuer_public_key = issuer_private_key.public_key()
    issuer_public_jwk = pub_ec_key_obj_to_jwk(issuer_public_key)
    issuer_public_jwk_kid = issuer_public_jwk.thumbprint()

    # Converti la chiave pubblica dell'app mobile a cui deve essere collegata l'attestazione in formato JWK ed estrai il thumbprint come KID (RFC 7638)
    cnf_public_jwk = pub_ec_key_obj_to_jwk(client_public_key)
    cnf_public_jwk_kid = cnf_public_jwk.thumbprint()

    # Controlla l'algoritmo di firma della chiave pubblica dell'app mobile a cui deve essere collegata l'attestazionein
    cnf_crv = cnf_public_jwk.get("crv")
    cnf_alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    cnf_alg = cnf_alg_map.get(crv)
    if not cnf_alg:
        raise ValueError(f"Curva della chiave pubblica del wallet non supportata: {cnf_crv}")

    now = int(time.time())

    headers = {"typ": "dc+sd-jwt", "kid": issuer_public_jwk_kid}

    claims = {
        "iss": issuer,
        "sub": cnf_public_jwk_kid,
        "vct": vct,
        "wallet_name": "IT Wallet",
        "wallet_link": issuer + "/wallet/detail_info.html",
        "aal": aal,
        "iat": now,
        "exp": now + int(lifetime),
        "cnf": {"jwk": cnf_public_jwk},
    }

    # Claim che devono essere rivelati selettivamente
    selectively_disclosable_claims = ["wallet_name", "wallet_link"]

    # Genera la SD-JWT
    sd_jwt = issue_sd_jwt(
        vct=claims.get("vct"),
        issuer_private_jwk_dict=issuer_private_jwk_dict,
        claims=claims,
        selectively_disclosable_claims=selectively_disclosable_claims,
        extra_header_parameters=headers,
        holder_public_jwk_dict=cnf_public_jwk,
    )

    return sd_jwt


def generate_request_object_jwt(
    issuer_private_key: EllipticCurvePrivateKey,
    audience: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    response_type: str,
    response_mode: str,
    redirect_uri: str,
    scope: str = None,
    authorization_details: list = None,
    lifetime: int = 3600,
) -> str:
    """
    Genera un Request Object JWT firmato con chiave EC.

    Args:
        issuer_private_key: Chiave privata del wallet per firmare il request object JWT.
        audience: audience del JWT (l'URL del destintario del request object JWT),
        state: session id del wallet,
        code_challenge: il challenge PKCE derivato dal code verifier PKCE prodotto dal wallet,
        code_challenge_method: il metodo di hash usato per generare il challeng PKCE,
        response_type: response type richiesto dal wallet al destintario del request object JWT,
        response_mode: response mode richiesto dal wallet al destintario del request object JWT,
        redirect_uri: redirect_uri wallet,
        scope: scopo della credenziale che si vuol richiedere
        authorization_details: elenco di credential_configuration_id delle credenziali che si vogliono richiedere
        lifetime: durata del del request object JWT in secondi (default 3600 secondi, cioè 1 ora = 60 minuti x 60 secondi)

    Returns:
        Stringa rappresentante il request object JWT da inviare nell'header DPoP.
    """
    # Estrae chiave pubblica da quella privata
    issuer_public_key = issuer_private_key.public_key()

    # Converti la chiave pubblica in formato JWK
    public_jwk = jwk.JWK.from_pem(
        issuer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Estrai il thumbprint come KID (RFC 7638)
    kid = public_jwk.thumbprint()

    # Determina l'algoritmo in base alla curva
    crv = public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Crea il payload JWT
    now = int(time.time())

    payload = {
        "iss": kid,
        "aud": audience,
        "client_id": kid,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "response_type": response_type,
        "response_mode": response_mode,
        "redirect_uri": redirect_uri,
        "iat": now,
        "exp": now + int(lifetime),
        "jti": str(uuid.uuid4()),
    }

    if scope:
        payload["scope"] = scope

    if authorization_details:
        payload["authorization_details"] = authorization_details

    # Crea header JWT

    headers = {"typ": "jwt", "alg": alg, "kid": kid}

    # Serializza la chiave privata per firmare con PyJWT
    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Firma il JWT
    jwt_token = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return jwt_token


def generate_dpop_jwt(
    issuer_private_key: EllipticCurvePrivateKey,
    http_method: str,
    http_url: str,
    access_token: str = None,  # parametro opzionale
) -> str:
    """
    Genera un DPoP proof JWT firmato con chiave EC.

    Args:
        issuer_private_key: Chiave privata EC usata per la firma del JWT.
        http_method: Metodo HTTP della richiesta (es. 'GET', 'POST').
        http_url: URL completo della risorsa (es. 'https://api.example.com/token').
        alg: Algoritmo di firma (ES256, ES384, ES512).
        access_token: (Opzionale) Access token associato, per calcolare il claim 'ath'.

    Returns:
        Stringa rappresentante il DPoP proof JWT genrato e
    """
    # Estrae chiave pubblica da quella privata
    issuer_public_key = issuer_private_key.public_key()

    # Converti la chiave pubblica in formato JWK
    public_jwk = jwk.JWK.from_pem(
        issuer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Determina l'algoritmo in base alla curva
    crv = public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    now = int(time.time())

    payload = {"htu": http_url, "htm": http_method.upper(), "iat": now, "jti": str(uuid.uuid4())}

    # Aggiunta della claim 'ath' se l'access token è fornito
    if access_token:
        token_bytes = access_token.encode("ascii")
        thumbprint = hashlib.sha256(token_bytes).digest()
        payload["ath"] = base64url_encode(thumbprint)

    headers = {"typ": "dpop+jwt", "alg": alg, "jwk": json.loads(public_jwk.export(private_key=False))}

    # Serializza la chiave privata per PyJWT
    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    dpop_jwt = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return dpop_jwt


def generate_dpop_bound_access_token(
    issuer_private_key: EllipticCurvePrivateKey,
    cnf_public_key: EllipticCurvePublicKey,
    issuer: str,
    subject: str,
    audience: str,
    lifetime: int = 3600,
) -> str:
    """
    Genera un access token JWT firmato e legato a una DPoP key tramite 'cnf.jkt',
    con supporto a curve parametrizzate.

    Args:
    issuer_private_key: Chiave privata EC usata per la firma dell'access token,
    cnf_public_key: Chiave pubblica EC a cui deve essere vincolato l'access token (quella corrispondente a quella privata usata per firmare il DPoP),
    issuer: issuer dell'access token,
    subject: subject dell'access token,
    audience: audience dell'access token,
    lifetime: durata dell'access token in secondi (default 3600 secondi, cioè 1 ora = 60 minuti x 60 secondi)

    Returns:
        Stringa JWT rappresentante l'access token
    """
    # Estrae chiave pubblica da quella privata
    issuer_public_key = issuer_private_key.public_key()

    # Converti la chiave pubblica dell'issuer in formato JWK
    issuer_public_jwk = jwk.JWK.from_pem(
        issuer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Estrai il thumbprint come KID (RFC 7638)
    issuer_public_jwk_kid = issuer_public_jwk.thumbprint()

    # Determina l'algoritmo in base alla curva
    crv = issuer_public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Converti la chiave pubblica in formato JWK
    cnf_public_jwk = jwk.JWK.from_pem(
        cnf_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Estrai il thumbprint come KID (RFC 7638)
    cnf_public_jwk_kid = cnf_public_jwk.thumbprint()

    now = int(time.time())

    headers = {"typ": "at+jwt", "alg": alg, "kid": issuer_public_jwk_kid}

    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "client_id": cnf_public_jwk_kid,
        "iat": now,
        "exp": now + int(lifetime),
        "cnf": {"jkt": cnf_public_jwk_kid},
    }

    # Serializza chiave privata in PEM
    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return token


def generate_proof_jwt(issuer_private_key: EllipticCurvePrivateKey, audience: str, nonce: str) -> str:
    """
    Genera un JWT proof firmato con una chiave privata EC
    Il JWT include la chiave pubblica JWK in header.
    """
    # Estrae chiave pubblica da quella privata
    public_key = issuer_private_key.public_key()

    # Converti la chiave pubblica in formato JWK
    public_jwk = jwk.JWK.from_pem(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Determina l'algoritmo in base alla curva
    crv = public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Estrai il thumbprint come KID (RFC 7638)
    kid = public_jwk.thumbprint()

    now = int(time.time())
    exp = now + 300  # 5 minuti

    payload = {"iss": kid, "aud": audience, "iat": now, "exp": exp, "nonce": nonce}

    headers = {"typ": "openid4vci-proof+jwt", "alg": alg, "jwk": json.loads(public_jwk.export(private_key=False))}

    # Firma e genera JWT
    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    proof_jwt = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return proof_jwt


def generate_response_uri_request_jws(private_key: EllipticCurvePrivateKey, vp_token: dict, state: str) -> str:
    """
    Genera un JWT firmato (JWS) reppresentante una response uri request nel rispetto
    della specifica https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/remote-flow.html#authorization-response

    Args:
        private_key: Chiave privata EC usata per la firma del JWS.
        vp_token: stringa rappresentante un JSON Object contenente le presentazioni delle credenziali richieste
        state: identificativo fornito precedentemente dal Relying Party nella richiesta di presentazione delle credenziali

    Returns:
        Stringa rappresentante il JWS
    """

    if not isinstance(vp_token, dict):
        raise ValueError("vp_token deve essere un dizionario valido")

    # Estrae chiave pubblica da quella privata
    public_key = private_key.public_key()

    # Converti la chiave pubblica in formato JWK
    public_jwk = jwk.JWK.from_pem(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Estrai il thumbprint come KID (RFC 7638)
    kid = public_jwk.thumbprint()

    # Determina l'algoritmo in base alla curva
    crv = public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Crea il payload JWT
    payload = {"vp_token": vp_token, "state": state}

    headers = {"typ": "jwt", "alg": alg, "kid": kid}

    # Serializza la chiave privata per PyJWT
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    response_uri_request_jws = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return response_uri_request_jws


def generate_response_uri_request_jwe(
    enc_key_json_str: str,
    vp_token: dict,
    state: str,
) -> str:
    """
    Genera un JWE reppresentante una response uri request nel rispetto
    della specifica https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/remote-flow.html#authorization-response

    Args:
        public_key: Chiave pubblica per la cifrtur del JWE.
        vp_token: dict rappresentante un JSON Object contenente le presentazioni delle credenziali richieste
        state: identificativo fornito precedentemente dal Relying Party nella richiesta di presentazione delle credenziali

    Returns:
        Stringa rappresentante il JWE
    """

    enc_key = json.loads(enc_key_json_str)

    kid = enc_key.get("kid")
    kty = enc_key.get("kty")

    if not kid:
        logger.error("❌ La chiave per cifrare il JWE non presenta il claim 'kid'")
        return None

    if not kty:
        logger.error("❌ La chiave per cifrare il JWE non presenta il claim 'kty'")
        return None

    logger.debug(f"🗝️  Chiave per cifrare il JWE (kid={kid}, kty={kty}):")
    logger.debug(json.dumps(enc_key, indent=2))

    # Seleziona algoritmi in base a kty
    if kty == "EC":
        crv = enc_key.get("crv")
        if not crv:
            logger.error("❌ La chiave per cifrare il JWE non presenta il claim 'crv'")
            return None

        content_encryption_alg = "A256GCM"
        key_encryption_alg_map = {"P-256": "ECDH-ES", "P-384": "ECDH-ES", "P-521": "ECDH-ES"}
        key_encryption_alg = key_encryption_alg_map.get(crv)
        if not key_encryption_alg:
            logger.error(
                f"❌ La chiave per cifrare il JWE presenta nel claim 'crv' il valore '{crv}' che non è supportato dal wallet"
            )
            return None
    elif kty == "RSA":
        content_encryption_alg = "A256CBC-HS512"
        key_encryption_alg = "RSA-OAEP-256"
    else:
        logger.error(
            f"❌ La chiave per cifrare il JWE presenta nel claim 'kty' il valore '{kty}' che non è supportata dal wallet"
        )
        return None

    logger.debug(f"🔑 Algoritmo di cifratura chiave: {key_encryption_alg}")
    logger.debug(f"🛡  Algoritmo di cifratura contenuto: {content_encryption_alg}")

    # Converte la JWK in oggetto JWK per jose
    pub_key = jwk.JWK.from_json(enc_key_json_str)

    if pub_key:
        logger.debug("🔑 Creato ogetto jwk.JWK che rappresenta chiave JWK per cifrare il JWE")

    # Prepara l'header protetto
    protected_header = {
        "alg": key_encryption_alg,  # ✅ Algoritmo di cifratura della chiave
        "enc": content_encryption_alg,  # ✅ Algoritmo di cifratura del contenuto
        "kid": kid,
        # "cty": "application/json"       # il payload non è un JWT, se era JWT allora cty: "JWT"
    }

    # Crea il payload JWE
    payload = {"vp_token": vp_token, "state": state}

    logger.debug(f"🔓 Payload JWT prima della cifratura:\n{json.dumps(payload, indent=2)}")

    # Payload JWT claims
    jwe_payload = json.dumps(payload, separators=(",", ":"))

    # ✅ Cifra come JWE
    jwetoken = jwe.JWE(plaintext=jwe_payload.encode("utf-8"), protected=protected_header)
    jwetoken.add_recipient(pub_key)

    # Serializza in formato compatto
    encrypted = jwetoken.serialize(compact=True)

    logger.debug(f"✅ JWE prodotto compatto: {encrypted}")

    response_uri_request_jwe = encrypted

    return response_uri_request_jwe


def generate_status_assertion_request_object_jwt(
    issuer_private_key: EllipticCurvePrivateKey,
    audience: str,
    credential_hash: str,
    credential_hash_alg: str,
    lifetime: int = 3600,
) -> str:
    """
    Genera un Request Object JWT firmato con chiave EC da usare per richiedere la status assertion di una credenziale

    Args:
        issuer_private_key: Chiave privata del wallet per firmare il request object JWT.
        audience: audience del JWT (l'URL del destintario del request object JWT, ovvero quello del Credential Issuer Status Assertion endpoint),
        credential_hash: hash del sd-jwt della credenziale al netto delle disclosure in formato esadecimale
        credential_hash_alg: algoritmo usato per calcolare l'hash della firma contenuta nella credenziale
        lifetime: durata del del request object JWT in secondi (default 3600 secondi, cioè 1 ora = 60 minuti x 60 secondi)

    Returns:
        Stringa rappresentante il request object JWT da inviare nell'header DPoP.
    """
    # Estrae chiave pubblica da quella privata
    issuer_public_key = issuer_private_key.public_key()

    # Converti la chiave pubblica in formato JWK
    public_jwk = jwk.JWK.from_pem(
        issuer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Estrai il thumbprint come KID (RFC 7638)
    kid = public_jwk.thumbprint()

    # Determina l'algoritmo in base alla curva
    crv = public_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Crea il payload JWT
    now = int(time.time())

    payload = {
        "iss": kid,
        "aud": audience,
        "iat": now,
        "exp": now + int(lifetime),
        "jti": str(uuid.uuid4()),
        "credential_hash": credential_hash,
        "credential_hash_alg": credential_hash_alg,
    }

    # Crea header JWT

    headers = {"typ": "status-assertion-request+jwt", "alg": alg, "kid": kid}

    # Serializza la chiave privata per firmare con PyJWT
    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Firma il JWT
    jwt_token = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return jwt_token
