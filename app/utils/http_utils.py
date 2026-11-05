"""Shared HTTP request helpers with retry and proxy support."""

import logging
import time
from typing import Any, Callable
from urllib.parse import urlparse

import requests

from app.utils.diagnostic_log import record_exchange
from app.utils.utils import sanitize_for_logging

logger = logging.getLogger(__name__)


def _should_use_proxy(url: str, proxies: dict | None, no_proxy_domains: list[str] | None) -> bool:
    """Determine if proxy should be used for the given URL."""
    if not proxies:
        return False
    if not no_proxy_domains:
        return True
    parsed = urlparse(url)
    host = parsed.hostname or ""
    for domain in no_proxy_domains:
        if host == domain or host.endswith(f".{domain}"):
            return False
    return True


def _extract_error_from_response(response: requests.Response) -> str:
    """Extract error string from JSON or plain text response."""
    try:
        parsed = response.json()
        err = parsed.get("error", "")
        desc = parsed.get("error_description", "")
        return f"{err} - {desc}".strip(" -")
    except (ValueError, TypeError):
        return " ".join(response.text.split())


def _parse_json_response(response: requests.Response, url: str) -> dict:
    """Validate Content-Type and parse JSON from response. Raises on error."""
    content_type = response.headers.get("Content-Type", "")
    if not content_type:
        raise RuntimeError(f"Risposta ricevuta da {url} non valida: Content-Type non indicato")
    if "application/json" not in content_type:
        raise RuntimeError(
            f"Risposta ricevuta da {url} non valida: Content-Type non è application/json, ma {content_type}"
        )
    try:
        return response.json()
    except ValueError as ve:
        raise ValueError(f"Risposta ricevuta da {url} non valida: {ve}") from ve


def _response_object(response: requests.Response):
    try:
        return response.json()
    except ValueError:
        return response.text


def _record_http(
    method: str, url: str, req_kwargs: dict, response: requests.Response | None = None, error: Exception | None = None
):
    body = req_kwargs.get("json", req_kwargs.get("data"))
    record_exchange(
        method=method,
        url=url,
        request_headers=req_kwargs.get("headers"),
        request_body=body,
        status=response.status_code if response is not None else None,
        response_body=_response_object(response) if response is not None else (str(error) if error else None),
    )


def _execute_request(method: str, url: str, req_kwargs: dict) -> requests.Response:
    """Execute single HTTP request."""
    if method.upper() == "GET":
        return requests.get(url, **req_kwargs)
    return requests.post(url, **req_kwargs)


def _process_response(
    response: requests.Response,
    url: str,
    parse_response: Callable[[requests.Response], Any] | None,
    handle_redirect: Callable[[requests.Response], Any] | None,
) -> Any:
    """Process response: handle redirect, check ok, parse. Raises on error."""
    if handle_redirect and 300 <= response.status_code < 400 and "Location" in response.headers:
        return handle_redirect(response)
    if not response.ok:
        error_str = _extract_error_from_response(response)
        raise RuntimeError(
            f"Errore ritornato dall'endpoint {url}: {error_str} (HTTP Status code: {response.status_code})"
        )
    if parse_response:
        return parse_response(response)
    return response


def http_request_with_retry(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    data: dict | None = None,
    json_body: dict | None = None,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    proxies: dict | None = None,
    no_proxy_domains: list[str] | None = None,
    parse_response: Callable[[requests.Response], Any] | None = None,
    handle_redirect: Callable[[requests.Response], Any] | None = None,
    allow_redirects: bool = True,
) -> Any:
    """
    Execute HTTP request with retry on ConnectionError.
    If handle_redirect is provided and response is 3xx with Location, call it and return.
    If parse_response is provided, call it with the response and return its result.
    Otherwise return the raw response (caller must handle).
    """
    use_proxy = _should_use_proxy(url, proxies, no_proxy_domains)
    req_kwargs: dict = {"headers": headers or {}, "verify": False, "allow_redirects": allow_redirects}
    if data is not None:
        req_kwargs["data"] = data
    if json_body is not None:
        req_kwargs["json"] = json_body
    if use_proxy and proxies:
        req_kwargs["proxies"] = proxies

    for attempt in range(1, max_retries + 1):
        try:
            response = _execute_request(method, url, req_kwargs)
        except requests.ConnectionError as ce:
            _record_http(method, url, req_kwargs, error=ce)
            # codeql[py/log-injection]
            logger.error(
                "❌ Tentativo %d - Errore di connessione: %s",
                attempt,
                sanitize_for_logging(str(ce)),
            )
            if attempt >= max_retries:
                raise ConnectionError(
                    f"Impossibile stabilire la connessione verso {url} dopo ripetuti tentativi"
                ) from ce
            time.sleep(retry_delay)
            continue
        except requests.RequestException as exc:
            _record_http(method, url, req_kwargs, error=exc)
            raise
        _record_http(method, url, req_kwargs, response=response)
        return _process_response(response, url, parse_response, handle_redirect)

    raise RuntimeError(f"Richiesta fallita verso {url} dopo {max_retries} tentativi")
