import json
import logging
import re
from typing import Union

import jwt
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from utils.utils import base64url_decode, base64url_encode, pem_public_key_from_jwk_dict, sanitize_for_logging

logger = logging.getLogger(__name__)


def der_signature_to_rs(der_sig: bytes, key_size=256):
    """
    Converte una firma DER in firma R+S concatenati (RFC 7515).
    key_size: in bit (256, 384, 521)
    """
    r, s = decode_dss_signature(der_sig)
    num_bytes = (key_size + 7) // 8
    r_bytes = r.to_bytes(num_bytes, byteorder="big")
    s_bytes = s.to_bytes(num_bytes, byteorder="big")
    return r_bytes + s_bytes


def verify_with_keys(main_key, other_keys, kid, try_verify):
    """
    Prova a verificare il JWT prima con la chiave principale (se presente),
    poi con tutte le altre chiavi fornite.
    Se nessuna chiave riesce, solleva JwtVerificationError con i dettagli.
    """
    candidate_keys = []

    if main_key:
        candidate_keys.append((kid, main_key))
    candidate_keys.extend((k.get("kid"), k) for k in other_keys)

    errors = []

    for candidate_kid, key in candidate_keys:
        # codeql[py/log-injection]
        logger.debug("🔑 Provo a verificare il JWT con chiave kid=%s", sanitize_for_logging(candidate_kid))
        try:
            result = try_verify(key)
            if result:
                # codeql[py/log-injection]
                logger.debug("✅ JWT verificato con chiave kid=%s", sanitize_for_logging(candidate_kid))
                return result
        except jwt.InvalidSignatureError:
            msg = f"kid={candidate_kid}: Firma JWT non valida"
            errors.append(msg)
            # codeql[py/log-injection]
            logger.debug("❌ %s", sanitize_for_logging(msg))

        except jwt.ExpiredSignatureError:
            msg = f"kid={candidate_kid}: JWT scaduto"
            errors.append(msg)
            # codeql[py/log-injection]
            logger.debug("❌ %s", sanitize_for_logging(msg))

        except jwt.InvalidTokenError as e:
            msg = f"kid={candidate_kid}: JWT non valido ({e})"
            errors.append(msg)
            # codeql[py/log-injection]
            logger.debug("❌ %s", sanitize_for_logging(msg))

        except Exception as e:
            msg = f"kid={candidate_kid}: Errore imprevisto ({e})"
            errors.append(msg)
            # codeql[py/log-injection]
            logger.debug("❌ %s", sanitize_for_logging(msg))

    # se siamo qui → tutte le chiavi hanno fallito
    error_msg = "JWT non validato con nessuna chiave. Motivi: " + "; ".join(errors)
    # codeql[py/log-injection]
    logger.error("🚫 %s", sanitize_for_logging(error_msg))
    raise ValueError(error_msg)


def _decode_jwt_parts(signed_jwt: str) -> tuple[dict, dict, str, str, str]:
    """Decode JWT into header, payload, and base64 parts. Raises ValueError if invalid."""
    parts = signed_jwt.split(".")
    if len(parts) != 3:
        raise ValueError("Formato JWT non valido: dovrebbe avere 3 parti separate da punti")
    header_b64, payload_b64, signature_b64 = parts[0], parts[1], parts[2]
    header = json.loads(base64url_decode(header_b64).decode())
    payload = json.loads(base64url_decode(payload_b64).decode())
    return header, payload, header_b64, payload_b64, signature_b64


def _convert_der_signature_if_needed(
    signed_jwt: str, header: dict, header_b64: str, payload_b64: str, sig_b64: str
) -> str:
    """Convert DER signature to R+S if needed. Returns updated signed_jwt."""
    sig_bytes = base64url_decode(sig_b64)
    if not sig_bytes or sig_bytes[0] != 0x30:
        logger.debug("ℹ️  La firma non sembra in formato DER, proseguo senza conversione")
        return signed_jwt
    logger.warning("⚠️  La firma del jwt sembra in formato DER, provo a convertirla in R+S concatenati")
    alg_to_crv = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
    key_sizes = {"P-256": 256, "P-384": 384, "P-521": 521}
    crv = alg_to_crv.get(header.get("alg"))
    if not crv or crv not in key_sizes:
        raise ValueError(f"Impossibile determinare la curva dall'alg header: {header.get('alg')}")
    rs_bytes = der_signature_to_rs(sig_bytes, key_size=key_sizes[crv])
    new_sig_b64 = base64url_encode(rs_bytes)
    return f"{header_b64}.{payload_b64}.{new_sig_b64}"


def _resolve_jwks(jwks: dict | None, payload: dict) -> dict:
    """Resolve JWKS from param or payload claim. Raises ValueError if missing."""
    if jwks and jwks.get("keys"):
        return jwks
    logger.debug("ℹ️  JWKS non fornito o vuoto: provo a leggerlo dal payload del jwt (claim 'jwks')")
    jwks_from_payload = payload.get("jwks")
    if jwks_from_payload and isinstance(jwks_from_payload, dict):
        logger.debug("✅ JWKS trovato nel payload del JWT")
        return jwks_from_payload
    raise ValueError("Nessun JWKS fornito o presente nel payload del JWT")


def decode_and_verify_jwt(signed_jwt: str, jwks: dict = None):
    """
    Legge un JWT firmato, lo valida e lo decodifica.
    - Se non viene fornito un JWKS, lo cerca nel claim 'jwks' del payload del signed_jwt.
    - Prova prima con la chiave che ha il kid trovato nell'header.
    - Se la firma fallisce, prova a validare con le altre chiavi usando verify_with_keys.
    """
    try:
        logger.debug(f"Entering method: decode_and_verify_jwt. Params [signed_jwt: {signed_jwt}]")

        header, payload, h_b64, p_b64, s_b64 = _decode_jwt_parts(signed_jwt)

        logger.debug(f"Header: {json.dumps(header, indent=2)}")

        logger.debug(f"Payload: {json.dumps(payload, indent=2)}")

        signed_jwt = _convert_der_signature_if_needed(signed_jwt, header, h_b64, p_b64, s_b64)
        jwks = _resolve_jwks(jwks, payload)
        jwks_keys = jwks.get("keys", [])
        if not jwks_keys:
            raise ValueError("JWKS dont cont JWK")

        kid = header.get("kid")
        if kid:
            main_key = next((k for k in jwks_keys if k.get("kid") == kid), None)
            other_keys = [k for k in jwks_keys if k.get("kid") != kid]
        else:
            logger.warning("Nessun 'kid' nell'header del JWT, prendo la prima chiave nel JWKS")
            main_key = jwks_keys[0] if jwks_keys else None
            other_keys = jwks_keys[1:]

        def try_verify(jwk: dict):
            current_kid = jwk.get("kid")
            if not current_kid:
                raise ValueError("La chiave usata per validare il JWT non presenta l'header 'kid'")
            crv = jwk.get("crv")
            alg = {
                "P-256": "ES256",
                "P-384": "ES384",
                "P-521": "ES512",
                "RSA-OAEP-256": "RSA-OAEP-256",
                "A128CBC-HS256": "A128CBC-HS256",
                "A256CBC-HS512": "A256CBC-HS512",
            }.get(crv)
            if not alg:
                raise ValueError(f"Curva '{crv}' non supportata")
            public_key_pem = pem_public_key_from_jwk_dict(jwk)
            return jwt.decode(
                signed_jwt,
                public_key_pem,
                algorithms=[alg],
                options={"verify_exp": True, "verify_aud": False},
                leeway=120,
            )

        payload_verified = verify_with_keys(main_key, other_keys, kid, try_verify)
        logger.debug("✅ JWT verificato con successo!")
        return payload_verified
    except ValueError as ve:
        logger.error("❌ JWT non valido: %s", sanitize_for_logging(str(ve)))
        raise
    except Exception as e:
        logger.error("❌ Errore interno durante la decodifica/verifica del JWT: %s", sanitize_for_logging(str(e)))
        raise


def extract_key_for_enc(jwks: dict) -> str:
    """
    Estrae la prima chiave JWK trovata in jwks con 'use' == 'enc' e se non la trova, prende la prima senza il claim 'use'
    """
    logger.debug("📦 JWKS in input: %s", sanitize_for_logging(json.dumps(jwks, indent=2)))

    # Trova la chiave EC
    keys = jwks.get("keys", [])
    if not keys:
        logger.debug("❌ JWKS non contiene chiavi")
        return None

    # Cerca prima una chiave con 'use' == 'enc'
    enc_key = next((k for k in keys if k.get("use") == "enc"), None)
    if not enc_key:
        logger.warning("⚠️ Nessuna chiave con 'use'=='enc' trovata nel JWKS, uso la prima senza 'use'")
        enc_key = next((k for k in keys if "use" not in k), None)

    if not enc_key:
        logger.debug("❌ Nessuna chiave valida trovata nel JWKS per cifrare")
        return None

    kid = enc_key.get("kid")
    kty = enc_key.get("kty")

    if not kid:
        logger.debug("❌ La chiave scelta non ha kid")
        return None

    if not kty:
        logger.debug("❌ La chiave scelta non ha kty")
        return None

    logger.debug(
        "🗝️  Chiave scelta per cifrare (kid=%s): %s",
        sanitize_for_logging(kid),
        sanitize_for_logging(json.dumps(enc_key, indent=2)),
    )

    enc_key_string = json.dumps(enc_key)

    return enc_key_string


def is_jwt(token: str) -> bool:
    """
    Verifica se una stringa ha il formato di un JWT (3 parti separate da punti, base64url-like).

    :param token: La stringa da verificare.
    :return: True se la stringa ha il formato di un JWT, False altrimenti.
    """
    logger.info(f"Entering method: is_jwt. Params [token: {token}]")

    jwt_pattern = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

    return bool(jwt_pattern.match(token))


def jwk_private_to_public(jwk: dict) -> dict:
    """
    Converte un JWK che descrive una chiave privata EC in un JWK pubblico.

    Args:
        jwk: JWK in formato dict contenente almeno i campi 'kty', 'crv', 'x', 'y'.

    Returns:
        Un nuovo JWK (dict) contenente solo la parte pubblica.
    """
    if jwk.get("kty") != "EC":
        raise ValueError("Solo chiavi EC sono supportate")

    required_fields = ("crv", "x", "y")
    if not all(k in jwk for k in required_fields):
        raise ValueError("Il JWK non contiene tutti i campi pubblici necessari (crv, x, y)")

    # Copia solo i campi pubblici
    pub_jwk = {"kty": "EC", "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}

    # Se ci sono "kid", "use", "alg", li manteniamo
    for optional in ("kid", "use", "alg"):
        if optional in jwk:
            pub_jwk[optional] = jwk[optional]

    return pub_jwk


def jwk_to_jwks(jwk: Union[dict, str]) -> str:
    """
    Converte un JWK singolo in una JWKS (JSON Web Key Set).

    Args:
        jwk: Un JWK come dizionario Python o stringa JSON.

    Returns:
        Una stringa JSON rappresentante una JWKS valida.
    """
    # Se è una stringa JSON, parsala in dict
    if isinstance(jwk, str):
        try:
            jwk = json.loads(jwk)
        except json.JSONDecodeError as e:
            raise ValueError("Il JWK fornito non è una stringa JSON valida") from e

    # Controllo minimo sul JWK
    if not isinstance(jwk, dict) or "kty" not in jwk:
        raise ValueError("Input non valido: deve essere un JWK con almeno il campo 'kty'")

    jwks = {"keys": [jwk]}

    return json.dumps(jwks, indent=2)
