import hashlib
import json
import logging
import time
import uuid
from typing import Tuple

import jwt
import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from jwcrypto import jwe, jwk

from app.utils.http_utils import _parse_json_response, http_request_with_retry
from app.utils.utils import base64url_encode, sanitize_for_logging
from settings import (
    CREDENTIAL_INVALID,
    CREDENTIAL_SUSPENDED,
    CREDENTIAL_VALID,
)

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _parse_json_for_par(response: requests.Response) -> dict:
    """Parse and validate JSON response for PAR endpoint."""
    result = _parse_json_response(response, str(response.url))
    logger.info("✅ Risposta OK:")
    # codeql[py/log-injection]
    logger.info("%s", sanitize_for_logging(json.dumps(result, indent=2)))
    return result


def _parse_text_response(response: requests.Response) -> str:
    """Return response body as stripped text."""
    text = response.text.strip()
    # codeql[py/log-injection]
    logger.info("✅ Risposta: %s", sanitize_for_logging(text[:200] + "..." if len(text) > 200 else text))
    return text


def _parse_jwt_response(expected_ct: str):
    """Return parser that validates Content-Type and returns JWT text."""

    def parser(response: requests.Response) -> str:
        ct = response.headers.get("Content-Type", "")
        if expected_ct not in ct:
            raise RuntimeError(f"Risposta non {expected_ct} ma {ct}")
        text = response.text.strip()
        # codeql[py/log-injection]
        logger.info("✅ JWT ricevuto: %s", sanitize_for_logging(text))
        return text

    return parser


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
    logger.info(f"Entering method: request_as_par. Params: [client_id: {client_id}, url: {url}]")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json; charset=utf-8",
        "OAuth-Client-Attestation": wallet_attestation_jwt,
        "OAuth-Client-Attestation-PoP": wallet_attestation_dpop_jwt,
    }
    data = {"client_id": client_id, "request": request_object_jwt}

    logger.info(f"Header: {json.dumps(headers, indent=2)}")

    logger.info(f"Payload: {json.dumps(data, indent=2)}")

    return http_request_with_retry(
        "POST",
        url,
        headers=headers,
        data=data,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_json_for_par,
    )


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

    logger.info(f"Entering method: request_authorize. Params: [query_string: {query_string}, url: {url}]")

    full_url = url + query_string

    return http_request_with_retry(
        "GET",
        full_url,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_text_response,
    )


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
    logger.info(f"Entering method: request_token. Params [url: {url}]")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json; charset=utf-8",
        "OAuth-Client-Attestation": wallet_attestation_jwt,
        "OAuth-Client-Attestation-PoP": wallet_attestation_dpop_jwt,
        "DPoP": dpop_proof_jwt,
    }
    data = {"grant_type": grant_type, "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier}

    logger.info(f"Header: {json.dumps(headers, indent=2)}")

    logger.info(f"Payload: {json.dumps(data, indent=2)}")

    return http_request_with_retry(
        "POST",
        url,
        headers=headers,
        data=data,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_json_for_par,
    )


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
    logger.info(f"Entering method: request_credential. Params: [url: {url}]")

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; charset=UTF-8",
        "Authorization": f"DPoP {access_token}",
        "DPoP": dpop_proof_jwt,
    }
    data = {"credential_identifier": credential_id, "proof": {"proof_type": "jwt", "jwt": proof_jwt}}

    logger.info(f"Header: {json.dumps(headers, indent=2)}")

    logger.info(f"Payload: {json.dumps(data, indent=2)}")

    return http_request_with_retry(
        "POST",
        url,
        headers=headers,
        json_body=data,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_json_for_par,
    )


def _parse_nonce_response(response: requests.Response) -> str:
    """Parse c_nonce from nonce endpoint JSON response."""
    result = _parse_json_response(response, str(response.url))
    if not result:
        raise ValueError("Il JSON ricevuto non contiene alcun dato")
    c_nonce = result.get("c_nonce")
    if c_nonce is None:
        raise ValueError("Il JSON ricevuto non contiene la chiave 'c_nonce'")
    # codeql[py/log-injection]
    logger.info("✅ c_nonce estratto: %s", sanitize_for_logging(c_nonce))
    return c_nonce


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
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json; charset=UTF-8"}
    # codeql[py/log-injection]
    logger.info(">>>> Invio POST a %s", sanitize_for_logging(url))
    # codeql[py/log-injection]
    logger.info("📦 Header:\n%s", sanitize_for_logging(json.dumps(headers, indent=2)))
    return http_request_with_retry(
        "POST",
        url,
        headers=headers,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_nonce_response,
    )


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
    full_url = url + query_string
    # codeql[py/log-injection]
    logger.info(">>>> Invio GET %s", sanitize_for_logging(full_url))
    return http_request_with_retry(
        "GET",
        full_url,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_jwt_response("application/oauth-authz-req+jwt"),
    )


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
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json; charset=utf-8"}
    data = {"response": response_uri_request_jwt, "state": state}
    # codeql[py/log-injection]
    logger.info(">>>> Invio POST a %s", sanitize_for_logging(url))
    # codeql[py/log-injection]
    logger.info("📦 Header:\n%s", sanitize_for_logging(json.dumps(headers, indent=2)))
    # codeql[py/log-injection]
    logger.info("📦 Payload:\n%s", sanitize_for_logging(json.dumps(data, indent=2)))
    return http_request_with_retry(
        "POST",
        url,
        headers=headers,
        data=data,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_json_for_par,
    )


def _handle_presentation_redirect(response: requests.Response) -> str:
    """Extract redirect URL from 3xx response for presentation callback."""
    redirect_url = response.headers["Location"]
    # codeql[py/log-injection]
    logger.info("➡️  Redirect verso: %s", sanitize_for_logging(redirect_url))
    return redirect_url


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
    # codeql[py/log-injection]
    logger.info(">>>> Invio GET %s", sanitize_for_logging(url))

    def _log_and_parse(response: requests.Response) -> str:
        logger.info("📍 Risposta: %s", response.status_code)
        # codeql[py/log-injection]
        logger.info(
            "📍 Body: %s",
            sanitize_for_logging(response.text[:500] + ("..." if len(response.text) > 500 else "")),
        )
        text = response.text.strip()
        # codeql[py/log-injection]
        logger.info("✅ Risposta finale: %s", sanitize_for_logging(text))
        return text

    return http_request_with_retry(
        "GET",
        url,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_log_and_parse,
        handle_redirect=_handle_presentation_redirect,
        allow_redirects=False,
    )


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
    headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json; charset=UTF-8"}
    data = {"status_assertion_requests": status_assertion_requests}
    # codeql[py/log-injection]
    logger.info(">>>> Invio POST a %s", sanitize_for_logging(url))
    # codeql[py/log-injection]
    logger.info("📦 Header:\n%s", sanitize_for_logging(json.dumps(headers, indent=2)))
    # codeql[py/log-injection]
    logger.info("📦 Payload:\n%s", sanitize_for_logging(json.dumps(data, indent=2)))
    return http_request_with_retry(
        "POST",
        url,
        headers=headers,
        json_body=data,
        max_retries=max_retries,
        retry_delay=retry_delay,
        proxies=proxies,
        no_proxy_domains=no_proxy_domains,
        parse_response=_parse_json_for_par,
    )


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


##
#
#   VERSION 1.3.3
#
##
def generate_par_request_object_jwt(
    issuer_private_key: EllipticCurvePrivateKey,
    audience: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    response_type: str,
    redirect_uri: str,
    scope: str,
    authorization_details: list = None,
    lifetime: int = 300
) -> str:
    """
    Genera un Request Object JWT firmato con chiave EC per la versione 1.3.3

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
        lifetime: durata del del request object JWT in secondi (default 300 secondi)

    Returns:
        Stringa rappresentante il request object JWT da inviare nell'header DPoP.
    """
    logger.info(
        f"Entering method: generate_par_request_object_jwt. Params: [issuer_private_key: {issuer_private_key}] "
    )

    issuer_public_key = issuer_private_key.public_key()

    public_jwk = jwk.JWK.from_pem(
        issuer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    kid = public_jwk.thumbprint()

    crv = public_jwk.get("crv")

    logger.info(f"crv: {crv}")

    alg_map = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "RSA-OAEP-256": "RSA-OAEP-256",
        "A128CBC-HS256": "A128CBC-HS256",
        "A256CBC-HS512": "A256CBC-HS512",
    }

    alg = alg_map.get(crv)

    if not alg:
        raise ValueError(f"Crv not supported: {crv}")

    now = int(time.time())

    payload = {
        "iss": kid,
        "aud": audience,
        "exp": now + int(lifetime),
        "iat": now,
        "response_type": response_type,
        "client_id": kid,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "authorization_details": authorization_details,  # 1.3.3
        "redirect_uri": redirect_uri,
        "jti": str(uuid.uuid4())
    }

    headers = {"typ": "jwt", "alg": alg, "kid": kid}

    private_pem = issuer_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwt_token = jwt.encode(payload, key=private_pem, algorithm=alg, headers=headers)

    return jwt_token


def generate_dpop_jwt(
    issuer_private_key: EllipticCurvePrivateKey,
    http_method: str,
    http_url: str,
    access_token: str = None,
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
    logger.info(
        f"Entering generate_dpop_jwt. Params [issuer_private_key: {issuer_private_key}, http_method:{http_method}, http_url: {http_url}, access_token: {access_token}]"
    )

    issuer_public_key = issuer_private_key.public_key()

    public_jwk = jwk.JWK.from_pem(
        issuer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    crv = public_jwk.get("crv")

    alg_map = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "RSA-OAEP-256": "RSA-OAEP-256",
        "A128CBC-HS256": "A128CBC-HS256",
        "A256CBC-HS512": "A256CBC-HS512",
    }

    alg = alg_map.get(crv)

    if not alg:
        raise ValueError(f"Crv not found: {crv}")

    now = int(time.time())

    payload = {"htu": http_url, "htm": http_method.upper(), "iat": now, "jti": str(uuid.uuid4())}

    if access_token:
        token_bytes = access_token.encode("ascii")
        thumbprint = hashlib.sha256(token_bytes).digest()
        payload["ath"] = base64url_encode(thumbprint)

    headers = {"typ": "dpop+jwt", "alg": alg, "jwk": json.loads(public_jwk.export(private_key=False))}

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
    alg_map = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "RSA-OAEP-256": "RSA-OAEP-256",
        "A128CBC-HS256": "A128CBC-HS256",
        "A256CBC-HS512": "A256CBC-HS512",
    }
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


def generate_proof_jwt(issuer_private_key: EllipticCurvePrivateKey, audience: str, nonce: str, key_attestation: str) -> str:
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
    alg_map = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "RSA-OAEP-256": "RSA-OAEP-256",
        "A128CBC-HS256": "A128CBC-HS256",
        "A256CBC-HS512": "A256CBC-HS512",
    }
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"Curva non supportata: {crv}")

    # Estrai il thumbprint come KID (RFC 7638)
    kid = public_jwk.thumbprint()

    now = int(time.time())
    exp = now + 300  # 5 minuti

    payload = {"iss": kid, "aud": audience, "iat": now, "exp": exp, "nonce": nonce}

    headers = {"typ": "openid4vci-proof+jwt", "alg": alg, "jwk": json.loads(public_jwk.export(private_key=False)),
               "key_attestation": key_attestation}

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
    alg_map = {
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "RSA-OAEP-256": "RSA-OAEP-256",
        "A128CBC-HS256": "A128CBC-HS256",
        "A256CBC-HS512": "A256CBC-HS512",
    }
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

    # codeql[py/log-injection]
    logger.debug(
        "🗝️  Chiave per cifrare il JWE (kid=%s, kty=%s):",
        sanitize_for_logging(kid),
        sanitize_for_logging(kty),
    )
    # codeql[py/log-injection]
    logger.debug("%s", sanitize_for_logging(json.dumps(enc_key, indent=2)))

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

    # codeql[py/log-injection]
    logger.debug("🔑 Algoritmo di cifratura chiave: %s", sanitize_for_logging(key_encryption_alg))
    # codeql[py/log-injection]
    logger.debug("🛡  Algoritmo di cifratura contenuto: %s", sanitize_for_logging(content_encryption_alg))

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

    # codeql[py/log-injection]
    logger.debug(
        "🔓 Payload JWT prima della cifratura:\n%s",
        sanitize_for_logging(json.dumps(payload, indent=2)),
    )

    # Payload JWT claims
    jwe_payload = json.dumps(payload, separators=(",", ":"))

    # ✅ Cifra come JWE
    jwetoken = jwe.JWE(plaintext=jwe_payload.encode("utf-8"), protected=protected_header)
    jwetoken.add_recipient(pub_key)

    # Serializza in formato compatto
    encrypted = jwetoken.serialize(compact=True)

    # codeql[py/log-injection]
    logger.debug("✅ JWE prodotto compatto: %s", sanitize_for_logging(encrypted))

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
