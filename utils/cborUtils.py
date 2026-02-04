import base64
import logging
import pprint
logger = logging.getLogger(__name__)

from constants import HASH_ALGORITHM

from datetime import date, datetime, timezone
from decimal import Decimal
import hashlib
from typing import Tuple

import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

# Funzione helper per creare DER signature da r, s
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Assicurati che 'make_issuer_key_callback' sia definito in utils/utils.py oppure qui stesso
from utils.utils import (
    base64url_encode,
    base64url_decode,
    check_required_claims,
    hex_to_base64,
    is_base64,
    is_hex
)

"""
https://paradym.id/tools/mdoc

L'IssuerAuth ha la struttura del COSE_Sign1 (RFC 8152):
[
  protected_headers     (bstr)
  unprotected_headers   (map)
  payload               (bstr)
  signature             (bstr)
]

Index	Contenuto	
0       Dato in formato CBOR (non taggato) rappresentante l'ID dell'algoritmo di firma usato;
1       Mappa chiave valore (https://datatracker.ietf.org/doc/html/rfc9360.html#name-x509-cose-header-parameters, https://datatracker.ietf.org/doc/html/rfc8152.html#section-3.1) che presenta:  
            - (33;<x5chain>): la catena di certificati X.509 la cui chiave del primo elemento della catena è da usare per validare la firma (la public key dell'issuer)
            - (4;<kid>): kid della public key dell'issuer  
2       Dato in formato CBOR (taggato con 24) rappresentante il MSO
3       Firma raw del payload+headers dell'IssuerAuth (https://datatracker.ietf.org/doc/html/rfc8152.html#appendix-C.1.1)

Il MSO è il cuore della parte firmata:
è l'oggetto che descrive quali dati sono inclusi nella credenziale, come verificarli, e quali digests devono avere.

Lo standard (ISO/IEC 18013-5) lo definisce come un oggetto CBOR che:

- indica il tipo di documento (docType),
- la versione,
- i dati hashati/digestati (valueDigests),
- le informazioni di validità,
- info sulla chiave pubblica del device holder (deviceKeyInfo); questa chiave pubblica è del device e non serve per verificare il MSO stesso.
"""

def decode_and_verify_issuer_signed(issuer_signed_base64_url: str, expected_namespaces: set, expected_version: str, expected_doc_type: str) -> dict:
    """
    Legge un IssuerSigned CBOR mdoc codificato in base 64 url da una stringa in input che rappresenta la struttura CBOR-encoded IssuerSigned 
    di una credenziale mDL che segue lo standard ISO 18013-5 (mDL / mdoc). 
    (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-credential-response-5) e lo valida.
    Ritorna il payload decodificato se valido, altrimenti None.
    
    Validare un CBOR mdoc (Mobile Driving Licence, Mobile ID, etc., come previsto dallo standard ISO/IEC 18013-5 o ISO/IEC 23220) 
    richiede alcuni passaggi ben precisi, perché un mdoc è un oggetto CBOR complesso firmato, e la validazione coinvolge:

    ✅ Parsing del CBOR;
    ✅ Estrazione della parte firmata (MobileSecurityObject / MSO);
    ✅ Estrazione del certificato o chiave pubblica usata per firmare;
    ✅ Verifica della firma digitale;
    ✅ Calcolare gli hash (digest) dei nameSpaces e confrontarli con quelli dichiarati nel MSO.
    """
    try:
        logger.debug("➡️  Issuer signed da validare e decodificare:")
        logger.debug(issuer_signed_base64_url)
        
        # Decodifica issuer signed base64 url encoded
        issuer_signed_bytes = base64url_decode(issuer_signed_base64_url)
        issuer_signed = cbor2.loads(issuer_signed_bytes)
        
        logger.debug("✅ Issuer signed decodificato:")
        logger.debug(pprint.pformat(issuer_signed))
        
        issuer_auth_array = issuer_signed['issuerAuth']
        
        mso = None
        
        try:
            mso = _handle_cose_sign1(issuer_auth_array, expected_version, expected_doc_type)
        except ValueError as ve:
            raise ValueError(f"Fallita la verifica dell'issuerAuth: {ve}")
        
        namespaces = issuer_signed['nameSpaces']
        
        mso_value_digests = mso.get('valueDigests')
        
        try:
            _handle_namespaces(namespaces,expected_namespaces,mso_value_digests)
        except ValueError as ve:
            raise ValueError(f"Fallita la validazione dei nameSpaces: {ve}")
                
        namespaces_json = _namespaces_to_json(namespaces)
        namespaces_json_serializable = _make_json_serializable(namespaces_json)
        
        mso_json = _mso_to_json(mso)
        mso_json_serializable = _make_json_serializable(mso_json)
        
        result_json = {}
        result_json["nameSpaces"] = namespaces_json_serializable
        result_json["mso"] = mso_json_serializable
        
        logger.debug("✅ Decodifica e validazione riuscita!")
        
        return result_json

    except Exception as e:
        logger.error(f"❌ La credenziale rilasciata non è valida: {str(e)}")
        raise ValueError(f"La credenziale rilasciata non è valida: {e}")

def _handle_namespaces(namespaces: dict, expected_namespaces: set, mso_value_digests: dict):
    check_required_claims(namespaces, expected_namespaces)
    
    for ns_name, ns_content in namespaces.items():
        if ns_name not in expected_namespaces:
            continue
        
        if ns_name in expected_namespaces:            
            if not isinstance(ns_content, list):
                raise ValueError(f"Namespace '{ns_name}' non è di tipo list")
                
            digest_dict = mso_value_digests.get(ns_name)
            
            if not digest_dict:
                raise ValueError(f"Nessun digest dichiarato per il Namespace '{ns_name}' nel MSO")
                
            for i, element in enumerate(ns_content):
                
                # Se element è un CBORTag
                if not isinstance(element, cbor2.CBORTag):
                    raise ValueError(f"Elemento [{i}] del Namespace '{ns_name}' non è un CBOR Tag")
                
                # Decodifico l'elementto corrente e ottengo un dict con digestID, random, elementIdentifier, elementValue
                elementDecoded = cbor2.loads(element.value)
                
                try:
                    expected_claims = {"digestID", "random", "elementIdentifier", "elementValue"}
                    check_required_claims(elementDecoded, expected_claims)
                except ValueError as ve:
                    raise ValueError(f"Elemento [{i}] del Namespace '{ns_name}' non è valido: {ve}")
                                            
                digestID = elementDecoded.get('digestID')
                random_bytes = elementDecoded.get('random')
                elementIdentifier = elementDecoded.get('elementIdentifier')
                elementValue = elementDecoded.get('elementValue')
                                                        
                # Se elementValue è datetime.date, ricrea CBORTag(1004, iso string) per il digest                           
                if isinstance(elementValue, date):
                    elementValue_for_digest = cbor2.CBORTag(1004, elementValue.isoformat())
                else:
                    elementValue_for_digest = elementValue
                    
                # Ricostruisci la struttura CBOR esatta sull'operazione svolta durante l'emissione:
                struct = {
                    "digestID": digestID,
                    "random": random_bytes,
                    "elementIdentifier": elementIdentifier,
                    "elementValue": elementValue_for_digest
                }
                        
                # Serializza canonicalmente il dict
                inner_cbor = cbor2.dumps(struct, canonical=True)
                
                # Incapsula nel tag 24
                outer_cbor = cbor2.CBORTag(24, inner_cbor)
                
                # Serializza canonicalmente il tag 24
                final_bytes = cbor2.dumps(outer_cbor, canonical=True)
                                        
                # Calcola digest SHA-256
                digest = hashlib.sha256(final_bytes).digest()
                
                # Recupera digest dichiarato
                expected_digest = digest_dict.get(digestID)
                        
                if not expected_digest:
                    raise ValueError(f"Elemento [{i}] del Namespace '{ns_name}': digestID={digestID} non trovato nel MSO per {elementIdentifier}")
                else:
                    if digest != expected_digest:
                        raise ValueError(f"Elemento [{i}] del Namespace '{ns_name}': mismatch digest per {elementIdentifier}, calcolato '{digest.hex()}' trovato nel MSO '{expected_digest.hex()}'")

# Restituisce mso
def _handle_cose_sign1(cose_msg: list, expected_version: str, expected_doc_type: str) -> dict:
    if len(cose_msg) != 4:
        raise ValueError(f"Il COSE_Sign1 deve contenere esattamente 4 elementi, ma ne ha {len(cose_msg)}")
    
    if not all(x is not None for x in cose_msg):
        raise ValueError("Uno o più elementi di cose_COSE_Sign1 sono None")
        
    protected_header_bytes = cose_msg[0]
    unprotected_header_map = cose_msg[1]
    payload_bytes = cose_msg[2]
    signature_bytes = cose_msg[3]
    
    algorithmIdentifier = _handle_protected_header(protected_header_bytes)
    
    certificate, kid = _handle_unprotected_header(unprotected_header_map)
    
    mso = _handle_payload(payload_bytes,expected_version,expected_doc_type)
    
    _handle_signature(signature_bytes, algorithmIdentifier, certificate, protected_header_bytes, payload_bytes)
    
    return mso

# Restituisce mso
def _handle_payload(cbor_elem: bytes, expected_version: str, expected_doc_type: str) -> dict:
    try:
        decoded = cbor2.loads(cbor_elem)
        
        if isinstance(decoded, cbor2.CBORTag):
            mso = cbor2.loads(decoded.value)
            
            if mso:
                # Estrai campi obbligatori
                doc_type = mso.get('docType')
                version = mso.get('version')
                value_digests = mso.get('valueDigests')
                digest_algorithm = mso.get('digestAlgorithm')
                device_key_info = mso.get('deviceKeyInfo')
                validity_info = mso.get('validityInfo')
                
                # controllo campo docType
                if not doc_type:
                    raise ValueError("Il MSO non presenta il campo 'docType'")
                
                if doc_type != expected_doc_type:
                    raise ValueError(f"Il valore del campo 'docType' del MSO non è valido: atteso '{expected_doc_type}', trovato '{doc_type}'")
                
                # controllo campo version
                if not version:
                    raise ValueError("Il MSO non presenta il campo 'version'")
                
                if version != expected_version:
                    raise ValueError(f"Il valore del campo 'version' del MSO non è valido: atteso '{expected_version}', trovato '{version}'")
                
                # controllo campo valueDigests
                if not value_digests:
                    raise ValueError("Il MSO non presenta il campo 'valueDigests'")
                
                if not isinstance(value_digests, dict):
                    raise ValueError("Il valore del campo 'valueDigests' del MSO presenta un formato non valido")
                
                # controllo campo digestAlgorithm
                if not digest_algorithm:
                    raise ValueError("Il MSO non presenta il campo 'digestAlgorithm'")
                
                if digest_algorithm != HASH_ALGORITHM:
                    raise ValueError(f"Il valore del campo 'digestAlgorithm' del MSO non è valido: atteso '{HASH_ALGORITHM}', trovato '{digest_algorithm}'")
                
                # controllo campo deviceKeyInfo
                if not device_key_info:
                    raise ValueError("Il MSO non presenta il campo 'deviceKeyInfo'")
                
                if not isinstance(device_key_info, dict):
                    raise ValueError("Il valore del campo 'deviceKeyInfo' del MSO presenta un formato non valido")
                
                device_key = device_key_info.get('deviceKey')
                
                if not device_key:
                    raise ValueError("Il MSO non presenta il campo 'deviceKeyInfo.deviceKey'")
                
                if not isinstance(device_key, dict):
                    raise ValueError("Il valore del campo 'deviceKeyInfo.deviceKey' del MSO presenta un formato non valido")
               
                # controllo campo validityInfo
                if not validity_info:
                    raise ValueError("Il MSO non presenta il campo 'validityInfo'")
                
                if not isinstance(validity_info, dict):
                    raise ValueError("Il valore del campo 'validityInfo' del MSO presenta un formato non valido")
                
                try:
                    validity_info_expected_claims = {"signed", "validFrom", "validUntil"}
                    check_required_claims(validity_info, validity_info_expected_claims)
                except ValueError as ve:
                    raise ValueError(f"Il valore del campo 'validityInfo' del MSO non è valido: {ve}")
                
                signed_dt = validity_info.get('signed')
                valid_from_dt = validity_info.get('validFrom')
                valid_until_dt = validity_info.get('validUntil')
                
                _check_validity_range(signed_dt, valid_from_dt, valid_until_dt)

                return mso
            else:
                raise ValueError(f"MSO non trovato all'interno del payload")
        else:
            raise ValueError(f"Payload non è unn CBOR valido")
        
    except cbor2.CBORDecodeError:
        raise ValueError(f"Payload non è unn CBOR")
    

def _check_validity_range(signed_dt: datetime, valid_from_dt: datetime, valid_until_dt: datetime) -> None:
    """
    Verifica che i campi di validità temporale siano coerenti.
    
    - signed deve essere compreso tra valid_from e valid_until
    - valid_from non deve essere nel futuro
    - valid_until non deve essere già scaduto

    Solleva ValueError in caso di incongruenze.
    """
    now_utc_ts = datetime.now(tz=timezone.utc)

    if not (valid_from_dt <= signed_dt <= valid_until_dt):
        raise ValueError("Il campo 'signed' non è compreso tra 'validFrom' e 'validUntil'")

    if valid_from_dt > now_utc_ts:
        raise ValueError("Il campo 'validFrom' è nel futuro")

    if valid_until_dt < now_utc_ts:
        raise ValueError("Il campo 'validUntil' è già scaduto")

def _handle_protected_header(cbor_elem: bytes) -> int:
    try:
        decoded = cbor2.loads(cbor_elem)
        
        algorithmIdentifier = decoded.get(1)
        if algorithmIdentifier is not None:
            return algorithmIdentifier
        else:
            raise ValueError("Nessun algorithm identifier trovato nel campo 1 del protected header del MSO")
    except cbor2.CBORDecodeError:
        raise ValueError("Il protected header del MSO non è in formato CBOR")

def _handle_unprotected_header(elem: dict) -> Tuple[bytes, str]:           
    cert_field = elem.get(33)
    
    cert_der = None
    
    if cert_field is not None:
        if isinstance(cert_field, list) and len(cert_field) > 0:
            cert_der = cert_field[0]
        elif isinstance(cert_field, bytes):
            cert_der = cert_field

        if not cert_der:
            raise ValueError("Il campo 33 dell'unprotected header del MSO non contiene una catena di certificati")
        
    else:
        raise ValueError("Nessuna catena di certificati trovata nel campo 33 dell'unprotected header del MSO")
    
    kid = elem.get(4)
    #if not kid:
    #    raise ValueError("Nessun kid trovato nel campo 4 dell'unprotected header del MSO")
    
    return cert_der,kid

def _handle_signature(signature_bytes: bytes, alg: int, cert_der_bytes: bytes, protected_header_bytes: bytes, payload_bytes: bytes):
    alg_name = _cose_alg_id_to_name(alg)
    logger.debug(f"📌 Verifica firma con algoritmo COSE {alg_name}")
    
    # 1. Recupero chiave pubblica per validare la firma
    
    curve_name_map  = {
        "secp256r1": "P-256",
        "prime256v1": "P-256",  # alias di secp256r1
        "secp384r1": "P-384",
        "secp521r1": "P-521"
    }
    
    cert = x509.load_der_x509_certificate(cert_der_bytes)
    public_key = cert.public_key()
    
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        curve_name = curve.name
        
        if curve_name not in curve_name_map:
            raise ValueError(f"La chiave pubblica estratta dal certificato x509 presenta un curva non supportata: {curve_name}")
        
        p_curve_name = curve_name_map.get(curve_name, curve_name) 
    
        logger.debug(f"🔑 La chiave pubblica estratta dal certificato x509 è una chiave ellitica con curva {p_curve_name}")
    else:
        logger.error(f"❌ La chiave pubblica estratta dal certificato x509 non è una chiave ellitica")
        raise ValueError(f"La chiave pubblica estratta dal certificato x509 non è una chiave ellitica")

    # 2. Costruzione della struttura firmata (Sig_structure)
    context = "Signature1"
    external_aad = b""
    sig_structure = [
        context,
        protected_header_bytes,
        external_aad,
        payload_bytes
    ]
    
    # 3. Serializzazione della struttura firmata in CBOR (to_be_signed)
    to_be_signed = cbor2.dumps(sig_structure)
    logger.debug(f"📄 to_be_signed generato: {to_be_signed.hex()}")
    
    
    # 4 Calcolo del digest (hash) della struttura firmata
    
    # Mappa algoritmo COSE → algoritmo hash
    hash_alg_map = {
        -7: hashes.SHA256(),   # ES256
        -35: hashes.SHA384(),  # ES384
        -36: hashes.SHA512(),  # ES512
    }

    hash_alg = hash_alg_map.get(alg)
    if hash_alg is None:
        raise ValueError(f"Algoritmo hash non supportato per COSE alg {alg_name}")

    digest = hashes.Hash(hash_alg)
    digest.update(to_be_signed)
    digest_bytes = digest.finalize()

    logger.debug(f"🔍 Digest calcolato su to_be_signed ({hash_alg.name}): {digest_bytes.hex()}")
    
    # 5. Decodifica della firma
    # Nota: signature_bytes in COSE sono concatenazione r||s (raw)
    r, s = _parse_cose_ecdsa_signature(signature_bytes, alg)
    
    logger.debug(f"🖋️  Firma COSE - r: {r}")
    logger.debug(f"🖋️  Firma COSE - s: {s}")
    
    # Codifica r,s in formato DER ASN.1 perché cryptography (e OpenSSL) usano quello
    der_signature = encode_dss_signature(r, s)
    
    logger.debug(f"🖋️  Firma COSE - DER: {der_signature}")
    
    # 6. Verifica firma
    try:
        public_key.verify(der_signature, to_be_signed, ec.ECDSA(hash_alg))
        logger.debug("✅ Firma valida")
    except InvalidSignature as e:
        logger.error(f"❌ Firma non valida per algoritmo {alg_name}: {e}")
        raise ValueError(f"Firma non valida") from e
    except Exception as e:
        logger.error(f"❌ Errore durante la verifica della firma per algoritmo {alg_name}: {e}")
        raise
    
def _parse_cose_ecdsa_signature(signature_bytes: bytes, alg: int):
    # Mappa lunghezze r&s (in byte) per algoritmo
    alg_sig_lengths = {
        -7: 32,   # ES256 -> r=32, s=32
        -35: 48,  # ES384 -> r=48, s=48
        -36: 66   # ES512 -> r=66, s=66 (P-521 padded)
    }
    
    part_len = alg_sig_lengths.get(alg)
    
    alg_name = _cose_alg_id_to_name(alg)
    
    if part_len is None:
        raise ValueError(f"Algoritmo COSE {alg_name} non supportato")
    
    expected_len = part_len * 2
    
    if len(signature_bytes) != expected_len:
        raise ValueError(f"Firma lunga {len(signature_bytes)} ma attesa {expected_len} per algoritmo {alg_name}")
    
    # Estrai r e s da firma raw
    r = int.from_bytes(signature_bytes[:part_len], "big")
    s = int.from_bytes(signature_bytes[part_len:], "big")
    
    return r, s

def _cose_alg_id_to_name(alg_id: int) -> str:
    """
    Traduce l'ID numerico dell'algoritmo COSE in un nome leggibile.
    Riferimento: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    """
    cose_alg_map = {
        -7:  "ES256",
        -35: "ES384",
        -36: "ES512",
        -8:  "EdDSA",
        -37: "PS256",
        -38: "PS384",
        -39: "PS512",
        -257:"RS256",
        -258:"RS384",
        -259:"RS512",
    }
    if alg_id not in cose_alg_map:
        return "Unknown"
    return cose_alg_map[alg_id]

def _decode_cose_key(device_key: dict) -> dict:
    # Mappa valori noti per kty (key type)
    kty_map = {
        2: "EC"
    }
    
    # Mappa curve
    crv_map = {
        1: "P-256",
        2: "P-384",
        3: "P-521"
    }
    
    # Estrai valori
    kty = device_key.get(1)
    alg = device_key.get(3)
    crv = device_key.get(-1)
    x = device_key.get(-2)
    y = device_key.get(-3)
    
    # Costruisci JWK solo se abbiamo tutti i campi necessari
    if kty in kty_map and crv in crv_map and x and y:
        jwk = {
            "kty": kty_map[kty],            
            "crv": crv_map[crv],            
            "x": base64url_encode(x),
            "y": base64url_encode(y)
        }

        alg_name = _cose_alg_id_to_name(alg)
        if alg_name != "Unknown":
            jwk["alg"] = alg_name
            
        return jwk
    else:
        raise ValueError("Impossibile creare JWK: dati mancanti o non validi")

def _mso_to_json(mso: dict):
    new_json = {}
    
    new_json["docType"] = mso.get('docType')
    new_json["version"] = mso.get('version')
    new_json["digestAlgorithm"] = mso.get('digestAlgorithm')
    
    device_key_info = mso.get('deviceKeyInfo')    
    device_key = device_key_info.get('deviceKey')  
    new_json["deviceKeyInfo"] = _decode_cose_key(device_key)
        
    validity_info = mso.get('validityInfo')
    signed_dt = validity_info.get('signed')
    valid_from_dt = validity_info.get('validFrom')
    valid_until_dt = validity_info.get('validUntil')    
    
    validityInfo = {}
    validityInfo["signed"] = signed_dt
    validityInfo["validFrom"] = valid_from_dt
    validityInfo["validUntil"] = valid_until_dt
    
    new_json["validityInfo"] = validityInfo
    
    return new_json
    
def _namespaces_to_json(namespaces: dict):
    new_json = {}
    
    for namespace_name, namespace_content in namespaces.items():
        new_json[namespace_name] = {}
        
        # Caso: namespace_content è una lista di CBORTag
        if isinstance(namespace_content, list):
            document = {}      
            for element in namespace_content:                    
                # Se element è un CBORTag
                if isinstance(element, cbor2.CBORTag):
                    # Decodifica il CBORTag e ottengo un dict da cui leggo i claims elementIdentifier ed elementValue
                    elementDecoded = cbor2.loads(element.value)
                                            
                    element_identifier = elementDecoded.get('elementIdentifier')
                    element_value = elementDecoded.get('elementValue')
                    
                    # Solo se abbiamo trovato identifier
                    if element_identifier is not None:
                        document[element_identifier] = element_value
                        
            new_json[namespace_name] = document

    return new_json

def _make_json_serializable(obj):
    if isinstance(obj, dict):
        return {k: _make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable(item) for item in obj]
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        # Se elementValue è bytes, lo converti in Base64
        try:
            obj_b64 = base64.b64encode(obj).decode('ascii')
            #html_img_tag = f'<img src="data:image/jpeg;base64,{obj_b64}" alt="Foto">'
            #with open("immagine.html", "w") as f:
            #    f.write(html_img_tag)
        except Exception as e:
            raise ValueError(f"Errore nella conversione byte to base64")
        return obj_b64
    elif isinstance(obj, Decimal):
        return float(obj)
    else:
        return obj
