import json
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from jwcrypto import jwk
from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer, SDObj
from sd_jwt.verifier import SDJWTVerifier

from utils.utils import base64url_decode, sanitize_for_logging

logger = logging.getLogger(__name__)


def issue_sd_jwt(
    vct: str,
    issuer_private_jwk_dict: dict,
    claims: dict,
    selectively_disclosable_claims: list[str],
    extra_header_parameters: dict,
    holder_public_jwk_dict: dict = None,
) -> str:
    """
    Crea una credenziale SD-JWT con disclosure selettiva.

    Args:
        vct (str): Nome/identificatore della credenziale (per logging).
        issuer_private_jwk_dict: Chiave privata dell'issuer in formato jwk dict.
        claims (dict): Tutti i claim da includere nella credenziale.
        extra_header_parameters (dict): headers aggiuntivi da includere nella credenziale.
        selectively_disclosable_claims (list[str]): Elenco dei claim da rendere selettivi.
        holder_public_jwk_dict (dict, optional): Chiave pubblica dell'holder in formato jwk dict per il key binding.

    Returns:
        str: Credenziale SD-JWT compatta (<sd-jwt>~<disclosures>~)
    """
    logger.debug("📥 Richiesta emissione della credenziale SD-JWT '%s'", sanitize_for_logging(vct))

    # Determina l'algoritmo in base alla curva della chiave privata JWK dell'issuer
    crv = issuer_private_jwk_dict.get("crv")
    alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
    alg = alg_map.get(crv)
    if not alg:
        raise ValueError(f"La chiave privata JWK dell'issuer presenta una curva non supportata: {crv}")
    logger.debug("🔑 La chiave privata JWK dell'issuer presenta la curva %s", sanitize_for_logging(crv))

    # Rimuovi la chiave 'kid' dall'issuer_jwk_dict, se presente
    issuer_private_jwk_dict_normalized = issuer_private_jwk_dict.copy()
    if "kid" in issuer_private_jwk_dict_normalized:
        del issuer_private_jwk_dict_normalized["kid"]

    # Usa from_json per creare l'oggetto JWK
    issuer_private_jwk_normalized = jwk.JWK.from_json(json.dumps(issuer_private_jwk_dict_normalized))

    holder_public_jwk = None

    if holder_public_jwk_dict:
        # Determina l'algoritmo in base alla curva della chiave pubblica JWK dell'holder per il key binding
        crv = holder_public_jwk_dict.get("crv")
        alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
        alg = alg_map.get(crv)
        if not alg:
            raise ValueError(
                f"La chiave pubblica JWK dell'holder per il key binding presenta una curva non supportata: {crv}"
            )
        logger.debug(
            "🔑 La chiave pubblica dell'holder per il key binding presenta la curva %s",
            sanitize_for_logging(crv),
        )

        # Usa from_json per creare l'oggetto JWK
        holder_public_jwk = jwk.JWK.from_json(json.dumps(holder_public_jwk_dict))

    # Wrappa i claims selettivi con SDObj
    user_claims = {}
    for k, v in claims.items():
        if k in selectively_disclosable_claims:
            user_claims[SDObj(k)] = v
        else:
            user_claims[k] = v

    logger.debug("🧾 Claims disponibili:")
    logger.debug("%s", sanitize_for_logging(json.dumps(claims, indent=2)))

    logger.debug(
        "📤 Claim richiesti per la selective disclosure: %s",
        sanitize_for_logging(selectively_disclosable_claims),
    )

    # Crea l'oggetto SDJWTIssuer con il formato di serializzazione richiesto
    issuer = SDJWTIssuer(
        user_claims=user_claims,
        issuer_keys=issuer_private_jwk_normalized,
        holder_key=holder_public_jwk,  # solo JWK pubblica, se si vuole key binding
        sign_alg=alg,
        extra_header_parameters=extra_header_parameters,
        serialization_format="compact",
    )

    # La credenziale è già creata nel costruttore
    sd_jwt = issuer.sd_jwt_issuance

    logger.debug("✅ SD-JWT generato con successo per '%s'", sanitize_for_logging(vct))
    return sd_jwt


def decode_and_verify_sd_jwt(sd_jwt_compact: str, jwks: dict, disclosures=None) -> dict:
    """
    Legge un SD-JWT da una stringa in input e lo valida.
    Ritorna il payload decodificato se valido con le disclosure rivelate, altrimenti solleva ValueError.
    """
    try:
        # Estrai la lista delle chiavi da jwks
        jwks_keys = jwks.get("keys")
        if not isinstance(jwks_keys, list):
            raise ValueError("Il parametro 'jwks' non contiene una lista valida di chiavi in 'keys'")

        logger.debug("➡️  Credenziale da validare e decodificare:")
        logger.debug("%s", sanitize_for_logging(sd_jwt_compact))

        # Decodifica header e payload
        header_b64, payload_b64, signature_b64 = sd_jwt_compact.split(".")
        header_json = base64url_decode(header_b64).decode()
        payload_json = base64url_decode(payload_b64).decode()
        header = json.loads(header_json)
        payload = json.loads(payload_json)

        logger.debug("✅ Credenziale decodificata")
        logger.debug("📦 Header:")
        logger.debug("%s", sanitize_for_logging(json.dumps(header, indent=2)))
        logger.debug("📦 Payload:")
        logger.debug("%s", sanitize_for_logging(json.dumps(payload, indent=2)))

        # Estrai il kid
        kid = header.get("kid")
        if not kid:
            raise ValueError("Nessun 'kid' presente nell'header del SD-JWT")

        # Cerca la chiave con il kid corrispondente
        issuer_pub_jwk = next((k for k in jwks_keys if k.get("kid") == kid), None)
        if not issuer_pub_jwk:
            raise ValueError(f"Nessuna chiave trovata con kid={kid} per validare la firma del SD-JWT")

        logger.debug("🔑 Chiave trovata con kid: %s", sanitize_for_logging(kid))
        logger.debug("%s", sanitize_for_logging(json.dumps(issuer_pub_jwk, indent=2)))

        # Importa la chiave per ispezione della curva (opzionale)
        public_jwk = jwk.JWK()
        public_jwk.import_key(**issuer_pub_jwk)

        # Callback per ottenere la chiave pubblica del firmatario
        cb_get_issuer_key = _make_issuer_key_callback(issuer_pub_jwk)

        # Crea il verifier
        verifier = SDJWTVerifier(sd_jwt_compact, cb_get_issuer_key)

        # Filtra disclosure duplicate
        if disclosures:
            claims = verifier.get_verified_payload(disclosures=disclosures)
        else:
            claims = verifier.get_verified_payload()

        logger.debug("✅ Decodifica e validazione riuscita!")
        logger.debug("📦 Claims finali:")
        logger.debug("%s", sanitize_for_logging(json.dumps(claims, indent=2)))

        return claims

    except Exception as e:
        logger.error("❌ La credenziale rilasciata non è valida: %s", sanitize_for_logging(str(e)))
        raise ValueError(f"La credenziale rilasciata non è valida: {e}")


def present_sd_jwt(
    vct: str,
    sd_jwt_compact: str,
    aud: str,
    nonce: str,
    claims_to_reveal: list[str],
    holder_private_jwk_dict: dict = None,
) -> str:
    """
    Crea una presentazione SD-JWT selettiva con Key Binding JWT.

    Args:
        vct (str): Nome/identificatore della credenziale (per logging).
        sd_jwt_compact (str): Credenziale SD-JWT compatta (<sd-jwt>~<disclosures>~).
        aud (str): Audience del verifier.
        nonce (str): Nonce ricevuto dal verifier.
        claims_to_reveal (list[str]): Lista di claim da rivelare (es: ["name", "birthdate"]).
        holder_private_jwk_dict (dict, optional): Chiave privata dell'holder in formato jwk dict per il key binding.

    Returns:
        str: Presentazione compatta: <sd-jwt>~<disclosures>~<kb-jwt>
    """
    logger.debug("📤 Richiesta presentazione della credenziale SD-JWT %s", sanitize_for_logging(vct))

    holder_public_jwk = None
    alg = None
    if holder_private_jwk_dict:
        # Determina l'algoritmo in base alla curva della chiave privata JWK dell'holder per il key binding
        crv = holder_private_jwk_dict.get("crv")
        alg_map = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
        alg = alg_map.get(crv)
        if not alg:
            raise ValueError(
                f"La chiave privata JWK dell'holder per il key binding presenta una curva non supportata: {crv}"
            )
        logger.debug(
            "🔑 La chiave privata JWK dell'holder per il key binding presenta la curva %s",
            sanitize_for_logging(crv),
        )

        # Usa from_json per creare l'oggetto JWK
        holder_public_jwk = jwk.JWK.from_json(json.dumps(holder_private_jwk_dict))

    holder = SDJWTHolder(sd_jwt_compact)

    sd_jwt, disclosures = _split_sd_jwt_presentation(sd_jwt_compact)

    payload = _decode_jws_payload(sd_jwt)
    logger.debug("🧾 Payload:")
    logger.debug("%s", sanitize_for_logging(json.dumps(payload, indent=2)))

    logger.debug("📜 Disclosure disponibili:")
    for d in disclosures:
        disclosure = _decode_disclosure(d)
        logger.debug("%s", sanitize_for_logging(disclosure))

    logger.debug("📤 Claim richiesti per la presentazione: %s", sanitize_for_logging(claims_to_reveal))

    holder.create_presentation(
        claims_to_disclose=claims_to_reveal,
        nonce=nonce,
        aud=aud,
        holder_key=holder_public_jwk,
        sign_alg=alg,
    )

    presentation = holder.sd_jwt_presentation
    logger.debug("✅ Presentazione generata per la credenziale %s!", sanitize_for_logging(vct))
    return presentation


def paths_to_nested_dict(paths: list[str]) -> dict:
    root = {}
    for path in paths:
        parts = path.split(".")
        d = root
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = True
    return root


def _decode_disclosure(disclosure_b64: str):
    if disclosure_b64:
        decoded = base64url_decode(disclosure_b64)
        return json.loads(decoded.decode("utf-8"))
    return ""


def _decode_jws_payload(jws_token: str) -> dict:
    # JWS formato: header.payload.signature
    parts = jws_token.split(".")
    if len(parts) != 3:
        raise ValueError("JWS malformato")
    payload_b64 = parts[1]
    payload_bytes = base64url_decode(payload_b64)
    return json.loads(payload_bytes.decode("utf-8"))


def _split_sd_jwt_presentation(sd_jwt_str):
    parts = sd_jwt_str.strip().split("~")
    sd_jwt = parts[0]
    disclosures = parts[1:]
    return sd_jwt, disclosures


def _make_issuer_key_callback(jwk_dict: dict):
    """
    Restituisce una funzione callback compatibile con SDJWTVerifier,
    che fornisce una JWK pubblica per la verifica, a partire da un dizionario JWK.
    """
    jwk_obj = jwk.JWK()
    jwk_obj.import_key(**jwk_dict)

    def get_issuer_key(issuer: str, headers: dict) -> jwk.JWK:
        return jwk_obj  # ✅ restituisce direttamente oggetto JWK

    return get_issuer_key
