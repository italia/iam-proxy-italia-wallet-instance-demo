import json
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

OID_MAP = {
    NameOID.COUNTRY_NAME: "C",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.COMMON_NAME: "CN",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.EMAIL_ADDRESS: "emailAddress",
}

def certificate_der_to_json(der_bytes: bytes) -> str:
    """
    Converte un certificato X.509 in formato DER in un JSON leggibile.
    
    :param der_bytes: bytes del certificato in formato DER
    :return: stringa JSON con le informazioni principali
    """
    cert = x509.load_der_x509_certificate(der_bytes, default_backend())

    # Calcola fingerprint in SHA-256
    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    # Serializza la chiave pubblica in PEM
    public_key_pem = cert.public_key().public_bytes(
        encoding=x509.Encoding.PEM,
        format=x509.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    cert_info = {
        "subject": {format_name(cert.subject)},
        "issuer": {format_name(cert.issuer)},
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after.isoformat(),
        "version": cert.version.name,
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "fingerprint_sha256": fingerprint_sha256,
        "der_base64": base64.b64encode(der_bytes).decode('utf-8'),
        "public_key_pem": public_key_pem,
    }

    return json.dumps(cert_info, indent=2)


def format_name(name):
    parts = []
    for attr in name:
        oid = attr.oid
        value = attr.value
        short_name = OID_MAP.get(oid, oid.dotted_string)  # usa abbreviazione o OID se non mappato
        parts.append(f"{short_name}={value}")
    return ", ".join(parts)