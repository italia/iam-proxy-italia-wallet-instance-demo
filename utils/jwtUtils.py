import logging
logger = logging.getLogger(__name__)

import re
import json
from typing import Union
import jwt
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from utils.utils import (
    base64url_decode,
    base64url_encode,
    pem_public_key_from_jwk_dict
)

def der_signature_to_rs(der_sig: bytes, key_size=256):
    """
    Converte una firma DER in firma R+S concatenati (RFC 7515).
    key_size: in bit (256, 384, 521)
    """
    r, s = decode_dss_signature(der_sig)
    num_bytes = (key_size + 7) // 8
    r_bytes = r.to_bytes(num_bytes, byteorder='big')
    s_bytes = s.to_bytes(num_bytes, byteorder='big')
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
        logger.debug(f"🔑 Provo a verificare il JWT con chiave kid={candidate_kid}")
        try:
            result = try_verify(key)
            if result:
                logger.debug(f"✅ JWT verificato con chiave kid={candidate_kid}")
                return result
        except jwt.InvalidSignatureError:
            msg = f"kid={candidate_kid}: Firma JWT non valida"
            errors.append(msg)
            logger.debug(f"❌ {msg}")

        except jwt.ExpiredSignatureError:
            msg = f"kid={candidate_kid}: JWT scaduto"
            errors.append(msg)
            logger.debug(f"❌ {msg}")

        except jwt.InvalidTokenError as e:
            msg = f"kid={candidate_kid}: JWT non valido ({e})"
            errors.append(msg)
            logger.debug(f"❌ {msg}")

        except Exception as e:
            msg = f"kid={candidate_kid}: Errore imprevisto ({e})"
            errors.append(msg)
            logger.debug(f"❌ {msg}")

    # se siamo qui → tutte le chiavi hanno fallito
    error_msg = "JWT non validato con nessuna chiave. Motivi: " + "; ".join(errors)
    logger.error(f"🚫 {error_msg}")
    raise ValueError(error_msg)

def decode_and_verify_jwt(signed_jwt: str, jwks: dict = None):
    """
    Legge un JWT firmato, lo valida e lo decodifica.
    - Se non viene fornito un JWKS, lo cerca nel claim 'jwks' del payload del signed_jwt.
    - Prova prima con la chiave che ha il kid trovato nell'header.
    - Se la firma fallisce, prova a validare con le altre chiavi usando verify_with_keys.
    """
    try:
        logger.debug(f"🔐 JWT firmato in input da validare e decodificare: {signed_jwt}")
        
        # Decodifica header e payload senza verificare la firma
        parts = signed_jwt.split('.')
        if len(parts) != 3:
            raise ValueError("Formato JWT non valido: dovrebbe avere 3 parti separate da punti")
        
        header_b64, payload_b64, signature_b64 = signed_jwt.split('.')
        header_json = base64url_decode(header_b64).decode()
        payload_json = base64url_decode(payload_b64).decode()
        header = json.loads(header_json)
        payload = json.loads(payload_json)

        logger.debug("📦 Header decodificato:")
        logger.debug(json.dumps(header, indent=2))
        logger.debug("📦 Payload decodificato:")
        logger.debug(json.dumps(payload, indent=2))
        
        # Controlla se la firma è DER (inizia con 0x30) e convertila
        # La firma nei JWT deve essere in formato R+S concatenati (per JWS).
        # Se la ricevi in DER significa che chi te la manda non sta seguendo correttamente lo standard JWS.
        # Il fix è giusto, ma il problema reale è a monte: la firma dovrebbe arrivarti già in R+S.
        signature_bytes = base64url_decode(signature_b64)
        if signature_bytes and signature_bytes[0] == 0x30:
            try:
                logger.warning("⚠️  La firma del jwt sembra in formato DER, provo a convertirla in R+S concatenati")
                
                # Prendi l'algoritmo di firma dall'header
                alg = header.get("alg")
                alg_to_crv = {
                    "ES256": "P-256",
                    "ES384": "P-384",
                    "ES512": "P-521"
                }
                
                crv = alg_to_crv.get(alg)
                
                if not crv:
                    raise ValueError(f"Impossibile determinare la curva dall'alg header del jwt: {alg}")
                
                key_size = {
                    "P-256": 256,
                    "P-384": 384,
                    "P-521": 521
                }.get(crv)
                
                if not key_size:
                    raise ValueError(f"Curva specificata nell'alg header del jwt non è supportata: {crv}")
                
                logger.debug(f"⚙️  Curva determinata dall'alg header del jwt: {crv}, key_size: {key_size}")

                rs_bytes = der_signature_to_rs(signature_bytes, key_size=key_size)
                
                # Se va bene, ricostruisci il JWT
                signature_b64_new = base64url_encode(rs_bytes)
                signed_jwt = f"{header_b64}.{payload_b64}.{signature_b64_new}"
                
                logger.debug("✅ Firma convertita DER→R+S e jwt aggiornato")
            except Exception as e:
                logger.error(f"❌ Errore durante la conversione DER→R+S: {str(e)}")
                raise ValueError(f"Conversione firma DER→R+S del jwt fallita: {e}")
        else:
            logger.debug("ℹ️  La firma non sembra in formato DER, proseguo senza conversione")

        # Se jwks non fornito o vuoto, cerco nel claim 'jwks' del payload
        if not jwks or not jwks.get('keys'):
            logger.debug("ℹ️  JWKS non fornito o vuoto: provo a leggerlo dal payload del jwt (claim 'jwks')")
            jwks_from_payload = payload.get("jwks")
            if jwks_from_payload and isinstance(jwks_from_payload, dict):
                jwks = jwks_from_payload
                logger.debug("✅ JWKS trovato nel payload del JWT")
            else:
                raise ValueError("Nessun JWKS fornito o presente nel payload del JWT")

        jwks_keys = jwks.get('keys', [])
        if not jwks_keys:
            raise ValueError("JWKS non contiene chiavi JWK")
        
        kid = header.get("kid")
        if not kid:
            logger.warning("⚠️  Nessun 'kid' nell'header del JWT, prendo la prima chiave nel JWKS come principale")
            logger.debug(f"🗝️  KID disponibili nel JWKS: {[k.get('kid') for k in jwks_keys]}")
            main_key = jwks_keys[0] if jwks_keys else None
            other_keys = jwks_keys[1:] if len(jwks_keys) > 1 else []
        else:
            logger.debug(f"ℹ️  Nell'header del JWT il 'kid' è pari a {kid}, prendo nel JWKS come chiave principale quella che ha questo kid")
            logger.debug(f"🗝️  KID disponibili nel JWKS: {[k.get('kid') for k in jwks_keys]}")
            main_key = next((k for k in jwks_keys if k.get("kid") == kid), None)
            other_keys = [k for k in jwks_keys if k.get("kid") != kid]

        def try_verify(jwk: dict):
            """
            Verifica il JWT con la chiave fornita.
            Se va bene, ritorna il payload decodificato.
            Se fallisce, solleva eccezioni di jwt (InvalidSignatureError, ExpiredSignatureError, ecc.)
            """
            current_kid = jwk.get("kid")
            if not current_kid:
                logger.error(f"❌ La chiave usata per validare il JWT non presenta l'header 'kid'")
                raise ValueError(f"❌ La chiave usata per validare il JWT non presenta l'header 'kid'")

            crv = jwk.get("crv")
            alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
            alg = alg_map.get(crv)

            if not alg:
                logger.error(f"❌ Chiave con kid={current_kid} usata per validare il JWT presenta la curva '{crv}' che non è supportata dal wallet")
                raise ValueError(f"La chiave con kid={current_kid} usata per validare il JWT presenta la curva '{crv}' che non è supportata dal wallet")
            
            public_key_pem = pem_public_key_from_jwk_dict(jwk)

            # jwt.decode solleva eccezioni se il JWT non è valido
            payload = jwt.decode(
                signed_jwt,        # il JWT da verificare
                public_key_pem,    # la chiave per la validazione della firma
                algorithms=[alg],
                options={"verify_exp": True, "verify_aud": False},  # controlla la scadenza ma non l'audience
                leeway=120  # 2 minuti di tolleranza
            )
            
            logger.debug(f"✅ JWT verificato con successo usando la chiave kid={current_kid}")
            return payload
    
        # Verifica con tutte le chiavi tramite helper
        payload_verified = verify_with_keys(main_key, other_keys, kid, try_verify)
        logger.debug("✅ JWT verificato con successo!")
        return payload_verified

    except ValueError as ve:
        logger.error(f"❌ JWT non valido: {ve}")
        raise
    except Exception as e:
        logger.error(f"❌ Errore interno durante la decodifica/verifica del JWT: {e}")
        raise

def extract_key_for_enc(jwks: dict) -> str:
    """
    Estrae la prima chiave JWK trovata in jwks con 'use' == 'enc' e se non la trova, prende la prima senza il claim 'use'
    """
    logger.debug(f"📦 JWKS in input: {json.dumps(jwks, indent=2)}")
    
    # Trova la chiave EC
    keys = jwks.get('keys', [])
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
        logger.debug(f"❌ La chiave scelta non ha kid")
        return None
    
    if not kty:
        logger.debug(f"❌ La chiave scelta non ha kty")
        return None
    
    logger.debug(f"🗝️  Chiave scelta per cifrare (kid={kid}): {json.dumps(enc_key, indent=2)}")
    
    enc_key_string = json.dumps(enc_key)
    
    return enc_key_string

def is_jwt(token: str) -> bool:
    """
    Verifica se una stringa ha il formato di un JWT (3 parti separate da punti, base64url-like).
    
    :param token: La stringa da verificare.
    :return: True se la stringa ha il formato di un JWT, False altrimenti.
    """
    jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
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
    pub_jwk = {
        "kty": "EC",
        "crv": jwk["crv"],
        "x": jwk["x"],
        "y": jwk["y"]
    }

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
    if not isinstance(jwk, dict) or 'kty' not in jwk:
        raise ValueError("Input non valido: deve essere un JWK con almeno il campo 'kty'")
    
    jwks = {
        "keys": [jwk]
    }

    return json.dumps(jwks, indent=2)

