"""Shared HTTP request helpers with retry and proxy support."""

import json
import logging
import time
from typing import Any, Callable
from urllib.parse import urlencode, urlparse

import requests

from app.utils.diagnostic_log import http_request_message, http_response_message, record_exchange
from app.utils.utils import sanitize_for_logging

logger = logging.getLogger(__name__)

HTTP_FAILURE_MSGID = "La richiesta HTTP verso %(endpoint)s per %(purpose)s è fallita: %(detail)s."


class HttpExchangeError(RuntimeError):
    """HTTP request/response failure with endpoint URL and purpose for the user."""

    def __init__(self, endpoint: str, purpose: str, detail: str, status: int | None = None):
        self.endpoint = endpoint
        self.purpose = purpose
        self.detail = detail
        self.status = status
        super().__init__(self.as_msgid_string())

    def as_msgid_string(self) -> str:
        return HTTP_FAILURE_MSGID % {
            "endpoint": self.endpoint,
            "purpose": self.purpose,
            "detail": self.detail,
        }

    def localized(self, translate: Callable[[str], str] | None = None) -> str:
        t = translate or (lambda message: message)
        return t(HTTP_FAILURE_MSGID) % {
            "endpoint": self.endpoint,
            "purpose": t(self.purpose),
            "detail": self.detail,
        }


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


def _attempted_body(req_kwargs: dict):
    if req_kwargs.get("json") is not None:
        return json.dumps(req_kwargs["json"], ensure_ascii=False)
    data = req_kwargs.get("data")
    if isinstance(data, dict):
        return urlencode(data)
    return data


def _response_text(response: requests.Response) -> str:
    try:
        return response.text
    except Exception:
        return response.content


def _record_http(
    method: str, url: str, req_kwargs: dict, response: requests.Response | None = None, error: Exception | None = None
):
    body = req_kwargs.get("json", req_kwargs.get("data"))
    prepared = getattr(response, "request", None) if response is not None else None
    if prepared is not None:
        request_http = http_request_message(prepared.method, prepared.url, prepared.headers, prepared.body)
    else:
        request_http = http_request_message(method, url, req_kwargs.get("headers"), _attempted_body(req_kwargs))
    if response is not None:
        response_http = http_response_message(
            response.status_code, response.reason, response.headers, _response_text(response)
        )
    else:
        response_http = str(error) if error else ""
    record_exchange(
        method=method,
        url=url,
        request_headers=req_kwargs.get("headers"),
        request_body=body,
        status=response.status_code if response is not None else None,
        response_body=_response_object(response) if response is not None else (str(error) if error else None),
        request_http=request_http,
        response_http=response_http,
    )


def _execute_request(method: str, url: str, req_kwargs: dict) -> requests.Response:
    """Execute single HTTP request."""
    if method.upper() == "GET":
        return requests.get(url, **req_kwargs)
    return requests.post(url, **req_kwargs)


def _http_failure(url: str, purpose: str, detail: str, status: int | None = None) -> HttpExchangeError:
    return HttpExchangeError(endpoint=url, purpose=purpose, detail=detail, status=status)


def _process_response(
    response: requests.Response,
    url: str,
    purpose: str,
    parse_response: Callable[[requests.Response], Any] | None,
    handle_redirect: Callable[[requests.Response], Any] | None,
) -> Any:
    """Process response: handle redirect, check ok, parse. Raises on error."""
    if handle_redirect and 300 <= response.status_code < 400 and "Location" in response.headers:
        return handle_redirect(response)
    if not response.ok:
        error_str = _extract_error_from_response(response)
        detail = f"{error_str} (HTTP {response.status_code})" if error_str else f"HTTP {response.status_code}"
        raise _http_failure(url, purpose, detail, status=response.status_code)
    if parse_response:
        return parse_response(response)
    return response


def http_request_with_retry(
    method: str,
    url: str,
    *,
    purpose: str,
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
                raise _http_failure(
                    url, purpose, "impossibile stabilire la connessione dopo ripetuti tentativi"
                ) from ce
            time.sleep(retry_delay)
            continue
        except requests.RequestException as exc:
            _record_http(method, url, req_kwargs, error=exc)
            raise _http_failure(url, purpose, str(exc)) from exc
        _record_http(method, url, req_kwargs, response=response)
        return _process_response(response, url, purpose, parse_response, handle_redirect)

    raise _http_failure(url, purpose, f"richiesta fallita dopo {max_retries} tentativi")
