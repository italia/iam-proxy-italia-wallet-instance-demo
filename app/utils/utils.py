import base64
import binascii
import hashlib
import json
import logging
import secrets
import string
import unicodedata
from datetime import datetime, timezone
from typing import Tuple, Union
from urllib.parse import parse_qs, urlparse

import fitz
import jmespath
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from jwcrypto import jwk

from settings import CONTENT_PDF_BASE_64_PREFIX

logger = logging.getLogger(__name__)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def base64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def pem_private_key_from_jwk_dict(jwk_dict: dict) -> bytes:
    """
    Converte un JWK in una chiave privata PEM compatibile con PyJWT.
    """
    # Filtro solo i campi standard
    filtered = {k: jwk_dict[k] for k in ["kty", "crv", "x", "y", "d"] if k in jwk_dict}

    jwk_obj = jwk.JWK(**filtered)

    pem = jwk_obj.export_to_pem(private_key=True, password=None)
    return pem  # formato bytes


def pem_public_key_from_jwk_dict(jwk_dict: dict) -> bytes:
    """
    Converte un JWK in una chiave pubblica PEM compatibile con PyJWT.
    """
    # Filtro solo i campi standard
    filtered = {k: jwk_dict[k] for k in ["kty", "crv", "x", "y"] if k in jwk_dict}

    jwk_obj = jwk.JWK(**filtered)

    pem = jwk_obj.export_to_pem(private_key=False, password=None)
    return pem  # formato bytes


def ec_private_key_from_pem_file(pem_path: str) -> EllipticCurvePrivateKey:
    """
    Carica una chiave privata EC da un file PEM e restituisce un oggetto EllipticCurvePrivateKey.
    """
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

    if not isinstance(private_key, EllipticCurvePrivateKey):
        raise ValueError("La chiave caricata non è una chiave privata EC valida.")

    return private_key


def ec_private_key_from_pem_bytes(pem_bytes: bytes) -> EllipticCurvePrivateKey:
    """
    Carica una chiave privata EC da dati PEM in formato bytes e restituisce un oggetto EllipticCurvePrivateKey.
    """
    private_key = load_pem_private_key(pem_bytes, password=None, backend=default_backend())

    if not isinstance(private_key, EllipticCurvePrivateKey):
        raise ValueError("La chiave caricata non è una chiave privata EC valida.")

    return private_key


def ec_public_key_from_pem_file(pem_path: str) -> EllipticCurvePublicKey:
    """
    Carica una chiave pubblica EC da un file PEM e restituisce un oggetto EllipticCurvePublicKey.
    """
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())

    if not isinstance(public_key, EllipticCurvePublicKey):
        raise ValueError("La chiave caricata non è una chiave pubblica EC valida.")

    return public_key


def ec_public_key_from_pem_bytes(pem_bytes: bytes) -> EllipticCurvePublicKey:
    """
    Carica una chiave pubblica EC da dati PEM in formato bytes e restituisce un oggetto EllipticCurvePublicKey.
    """
    public_key = load_pem_public_key(pem_bytes, backend=default_backend())

    if not isinstance(public_key, EllipticCurvePublicKey):
        raise ValueError("La chiave caricata non è una chiave pubblica EC valida.")

    return public_key


def ec_private_key_from_jwk_file(jwk_path: str) -> EllipticCurvePrivateKey:
    """Carica una chiave privata EC da un file JWK e restituisce un oggetto EllipticCurvePrivateKey."""
    with open(jwk_path, "r") as f:
        jwk = json.load(f)

    # Verifica che sia una EC key
    if jwk.get("kty") != "EC":
        raise ValueError("Il file JWK non contiene una chiave EC.")

    crv = jwk["crv"]
    d = base64url_decode(jwk["d"])
    x = base64url_decode(jwk["x"])
    y = base64url_decode(jwk["y"])

    # Mappa nome curva JWK a oggetto cryptography
    curve_map = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }

    if crv not in curve_map:
        raise ValueError(f"Curva EC non supportata: {crv}")

    curve = curve_map[crv]

    x_int = int.from_bytes(x, byteorder="big")
    y_int = int.from_bytes(y, byteorder="big")
    d_int = int.from_bytes(d, byteorder="big")

    public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, curve)
    private_numbers = EllipticCurvePrivateNumbers(d_int, public_numbers)

    return private_numbers.private_key(backend=default_backend())


def pub_ec_key_obj_to_jwk(pub_ec_key: EllipticCurvePublicKey) -> jwk.JWK:
    """Converte una chiave pubblica EC in formato JWK"""
    pub_jwk = jwk.JWK.from_pem(
        pub_ec_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    return pub_jwk


def priv_ec_key_obj_to_jwk(priv_ec_key: EllipticCurvePrivateKey) -> jwk.JWK:
    """Converte una chiave privata EC in formato JWK"""
    priv_pem = priv_ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    priv_jwk = jwk.JWK.from_pem(priv_pem)
    return priv_jwk


def check_curve_supported(key: Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]) -> Tuple[bool, str]:
    """
    Controlla se la chiave ECC usa una curva supportata (P-256, P-384, P-521).

    Args:
        key: Oggetto chiave ECC, può essere privata o pubblica.

    Returns:
        Tuple[bool, str]: True/False se la curva è supportata, e il nome della curva (es. "P-256").
    """
    supported_curves = {
        SECP256R1: "P-256",
        SECP384R1: "P-384",
        SECP521R1: "P-521",
    }

    curve_type = type(key.curve)
    curve_name = supported_curves.get(curve_type, "UNKNOWN")

    return (curve_name != "UNKNOWN", curve_name)


def generate_pem_keys(pvt_key_path: str, pub_key_path: str, curve_name: str = "P-256"):
    """Genera una coppia di chiavi EC in PEM, con curva parametrica (P-256, P-384, P-521)"""
    # Mappa nome curva → oggetto curva cryptography
    curve_map = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }

    if curve_name not in curve_map:
        raise ValueError(f"Curva non supportata: {curve_name}")

    curve = curve_map[curve_name]
    private_key = ec.generate_private_key(curve, default_backend())

    # Salva chiave privata
    with open(pvt_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
            )
        )

    # Salva chiave pubblica PEM
    with open(pub_key_path, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def generate_pkce_pair(length: int = 64) -> dict:
    """
    Genera un pair PKCE: code_verifier e code_challenge secondo RFC 7636.

    Args:
        length (int): lunghezza del code_verifier (min 43, max 128).

    Returns:
        dict: con code_verifier, code_challenge, code_challenge_method
    """

    if not (43 <= length <= 128):
        raise ValueError("length must be between 43 and 128")

    # 1. Genera code_verifier: una stringa base64url sicura
    verifier_bytes = secrets.token_urlsafe(length)
    code_verifier = verifier_bytes[:length]

    # 2. Calcola code_challenge: base64url(SHA256(verifier))
    sha256 = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(sha256).rstrip(b"=").decode("ascii")

    return {"code_verifier": code_verifier, "code_challenge": code_challenge, "code_challenge_method": "S256"}


def get_thumbprint_from_private_key(pvt_key: EllipticCurvePrivateKey) -> str:
    logger.info(f"Entering method: get_thumbprint_from_private_key. Params [pvt_key: {pvt_key}]")

    pub_key = pvt_key.public_key()

    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    jwk_key = jwk.JWK.from_pem(pem)

    return jwk_key.thumbprint()


def determine_alg(key_jwk: jwk.JWK) -> str:
    """
    Mappa la curva della chiave JWK in un algoritmo JWT.
    """
    crv = key_jwk.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"❌ Curva '{crv}' non supportata per la firma SD-JWT")
    return alg


def generate_nonce(length: int = 32) -> str:
    """
    Genera un nonce alfanumerico sicuro, composto da lettere e numeri.

    Args:
        length (int): Lunghezza del nonce da generare. Default 32 caratteri.

    Returns:
        str: Stringa nonce alfanumerica sicura.
    """
    characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
    return "".join(secrets.choice(characters) for _ in range(length))


def guess_credential_configuration_icon(credential_configuration_id):
    credential_configuration_id_lower = credential_configuration_id.lower()
    if "disability" in credential_configuration_id_lower:
        return "♿"
    elif "health" in credential_configuration_id_lower:
        return "➕"
    elif "mdl" in credential_configuration_id_lower:
        return "🚗"
    elif "education" in credential_configuration_id_lower:
        return "🏛️"
    elif "badge" in credential_configuration_id_lower:
        return "🪪"
    else:
        return "📜"


def has_claim(entity: dict, jmes_query: str) -> bool:
    """
    Controlla se il dizionario JSON ha un claim specifico usando una query JMESPath.

    Args:
        entity (dict): Il JSON da interrogare.
        jmes_query (str): La query JMESPath, es. 'metadata.openid_credential_verifier.client_id'.

    Returns:
        bool: True se il valore esiste ed è non nullo, False altrimenti.

    Esempi:
        has_claim(entity, "metadata.openid_credential_verifier.client_id")  # True
        has_claim(entity, "metadata.federation_entity.contacts[0]")         # True
        has_claim(entity, "metadata.vuoto.che.non.esiste")                  # False
    """
    try:
        result = jmespath.search(jmes_query, entity)
        return result is not None
    except Exception:
        return False


def extract_claim(entity: dict, jmes_query: str):
    """
    Estrae un claim da un dizionario JSON usando una query JMESPath.

    Args:
        entity (dict): Il JSON da interrogare.
        jmes_query (str): La query JMESPath, es. 'metadata.openid_credential_verifier.client_id'.

    Returns:
        Any: il valore esiste, None altrimenti.

    Esempi:
        val = extract_claim(entity, "metadata.openid_credential_verifier.client_id")
        if val:
            print("✅ Estratto:", val)
        else:
            print("❌ Non trovato")
    """
    logger.info(f"Entering method: extract_claim. Params [jmes_query: {jmes_query}]")

    try:
        # DEBUG
        # print("🔍 JMESPath query:", jmes_query)
        # print("🔍 Contenuto config:", entity)
        return jmespath.search(jmes_query, entity)
    except Exception:
        return None


def estrai_testo_from_pdf(path: str) -> str:
    doc = fitz.open(path)
    full_text = ""
    for page in doc:
        full_text += page.get_text()
    return full_text


def extract_text_from_base64_pdf(data_uri: str) -> list[str]:
    if data_uri and data_uri.startswith(CONTENT_PDF_BASE_64_PREFIX):
        b64_data = data_uri.split(",", 1)[1]
    else:
        raise ValueError(f"La stringa non contiene un prefisso valido ({CONTENT_PDF_BASE_64_PREFIX})")

    # Correggi la lunghezza per il base64 (padding con '=')
    missing_padding = len(b64_data) % 4
    if missing_padding:
        b64_data += "=" * (4 - missing_padding)

    pdf_bytes = base64.b64decode(b64_data)

    testi_per_pagina = []
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        for page in doc:
            testo_pagina = page.get_text()
            testi_per_pagina.append(testo_pagina.strip())
    return testi_per_pagina


def check_required_claims(claims: dict, expected_claims: set) -> None:
    """
    Verifica che tutte le chiavi attese siano presenti nel dict claims.
    Solleva ValueError se mancano dei claim.

    :param claims: dict contenente i claims.
    :param expected_claims: set di chiavi attese.
    """
    missing = expected_claims - claims.keys()
    if missing:
        raise ValueError(f"Mancano i seguenti claim obbligatori: {', '.join(sorted(missing))}")


def is_hex(s: str) -> bool:
    try:
        int(s, 16)
    except ValueError:
        return False
    # opzionale: controlla che abbia lunghezza pari, se rappresenta byte interi
    return len(s) % 2 == 0


def is_base64(s: str) -> bool:
    try:
        # rimuove eventuali newline/spazi
        sb = s.strip()
        decoded = base64.b64decode(sb, validate=True)
        return base64.b64encode(decoded).decode("ascii") == sb.rstrip("=")
    except Exception:
        return False


def hex_to_base64(hex_str: str) -> str:
    # rimuovi spazi/newline
    h = hex_str.strip()
    data = binascii.unhexlify(h)
    return base64.b64encode(data).decode("ascii")


def to_datetime(value):
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except Exception:
        raise ValueError("Errore in to_utc_datetime: {e}")


def estrai_parametro_query_string(url: str, parametro: str) -> str | None:
    """
    Estrae il valore di un parametro specifico dalla query string di un URL valido.

    Parametri:
        url (str): L'URL completo da analizzare.
        parametro (str): Il nome del parametro da estrarre.

    Ritorna:
        str | None: Il valore del parametro se presente, altrimenti None.
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None  # URL non valido

        query_params = parse_qs(parsed.query)
        return query_params.get(parametro, [None])[0]
    except Exception:
        return None


def sanitize_for_logging(value) -> str:
    """
    Sanitize a value for safe logging to prevent log injection.
    - Removes/replaces newline and control characters (including Unicode controls/separators).
    - Truncates excessively long values to avoid log flooding.
    """
    if value is None:
        return ""
    s = str(value)
    cleaned_chars = []
    for c in s:
        # Unicode category starting with "C" = control, "Z" = separator
        cat = unicodedata.category(c)
        if c in "\n\r\t" or cat.startswith("C") or cat.startswith("Z"):
            cleaned_chars.append(" ")
        else:
            cleaned_chars.append(c)
    cleaned = "".join(cleaned_chars)
    # Truncate to a safe maximum length to avoid log injection via very long input
    max_len = 1024
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "...[truncated]"
    return cleaned


def remove_str_prefix(raw: str, prefixes: list[str]) -> str:
    """Delete a prefix from a string if it exists."""
    value_lower = raw.lower()
    for prefix in prefixes:
        if value_lower.startswith(prefix.lower()):
            return raw[len(prefix) :]
    return raw


def unix_ts_to_str_datetime(timestamp: int, fmt: str = "%d-%m-%Y %H:%M:%S", tmz: datetime.tzinfo = None) -> str | None:
    """Convert a unix timestamp (`int`) into a timezone-aware datetime string.

    Notes:
    - The input timestamp is treated as UTC and converted to the target timezone.
    """
    if tmz is None:
        tmz = datetime.now().astimezone().tzinfo

    result = None
    try:
        dt = datetime.fromtimestamp(timestamp)
        dt = dt.astimezone(tmz)
        return dt.strftime(fmt)
    except (TypeError, ValueError):
        pass
    return result


def unescape_json(value):
    """Unescapes JSON strings and converts to dict if necessary."""
    if isinstance(value, str):
        try:
            # Attempt to parse string as JSON (if it contains escaped characters)
            return json.loads(value)
        except json.JSONDecodeError:
            # Not a valid JSON string, return original value
            return value
    elif isinstance(value, dict):
        # Recursively apply to dictionary values
        return {k: unescape_json(v) for k, v in value.items()}
    elif isinstance(value, list):
        # Recursively apply to list elements
        return [unescape_json(v) for v in value]
    else:
        return value
