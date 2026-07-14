"""
Utility helpers for CBOR-encoded mdoc/mDL credentials.

References:
- ISO/IEC 18013-5
- RFC 9360 (COSE): https://datatracker.ietf.org/doc/html/rfc9360
- RFC 9052 (CBOR Object Signing and Encryption): https://datatracker.ietf.org/doc/html/rfc9052
- RFC 8949 (CBOR): https://datatracker.ietf.org/doc/html/rfc8949
- RFC 9053: https://datatracker.ietf.org/doc/html/rfc9053
- IT-WALLET v1.3.3 SPECS: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/credential-data-model.html#mdoc-cbor-credential-format
"""

import base64
import logging
import pprint
import cbor2

from app.utils.utils import base64url_decode, base64url_encode, sanitize_for_logging
from pymdoccbor.mdoc.verifier import MdocCbor, MobileDocument
from datetime import date, datetime, timezone
from typing import TypeVar
from decimal import Decimal
from settings import HASH_ALGORITHM

logger = logging.getLogger(__name__)


def decode_and_verify_issuer_signed(issuer_signed_base64_url: str, expected_namespaces: list,
                                    expected_version: str, expected_doc_type: str) -> dict | None:
    """
    Decode and verify a base64url-encoded IssuerSigned CBOR mdoc credential (ISO 18013-5).

    :param issuer_signed_base64_url: Base64url-encoded IssuerSigned CBOR bytes.
    :param expected_namespaces: List of namespace keys expected in the credential.
    :param expected_version: Expected MSO version string.
    :param expected_doc_type: Expected MSO docType string.
    :return: Dict with 'nameSpaces' and 'mso' keys, or None if validation fails.
    """
    logger.debug("Decoding and verifying IssuerSigned credential.")
    # codeql[py/log-injection]
    logger.debug("Raw input: %s", sanitize_for_logging(issuer_signed_base64_url))

    issuer_signed_bytes = base64url_decode(issuer_signed_base64_url)
    issuer_signed_raw = cbor2.loads(issuer_signed_bytes)

    logger.debug("IssuerSigned decoded successfully: %s", sanitize_for_logging(pprint.pformat(issuer_signed_raw)))

    # create document and device response for pymdoccbor validator
    document = {"docType": expected_doc_type, "issuerSigned": issuer_signed_raw}
    device_response_dict = dict(version=expected_version, documents=[document])
    device_response_bytes = cbor2.dumps(device_response_dict)

    (mdoc := MdocCbor()).loads(device_response_bytes)
    if not mdoc.verify():
        if mdoc.documents_invalid:
            doc: MobileDocument = mdoc.documents_invalid[0]
            if doc.hash_verification and not doc.hash_verification["valid"]:
                logger.error("Namespace hash validation failed. Mismatched entries: %s",
                             doc.hash_verification.get("failed", []))
                return None
        logger.error("IssuerSigned verification failed.")
        return None

    doc: MobileDocument = mdoc.documents[0]
    logger.debug("Namespace hashes verified: %d/%d.", doc.hash_verification["verified"], doc.hash_verification["total"])

    mso_dict = doc.issuersigned.issuer_auth.payload_as_dict

    _validate_mso_core(mso_dict, expected_version, expected_doc_type)
    _validate_mso_device_and_validity(mso_dict)
    for ns in expected_namespaces:
        if ns not in mdoc.disclosure_map.keys():
            raise ValueError(f"Missing required namespace: {ns}")

    logger.debug("Credential decoded and validated successfully.")
    return {
        "nameSpaces": _make_json_serializable(mdoc.disclosure_map),
        "mso": _mso_to_json(mso_dict),
    }


def _validate_mso_core(mso: dict, expected_version: str, expected_doc_type: str) -> None:
    """Validate MSO core fields: docType, version, valueDigests, digestAlgorithm."""
    doc_type = mso.get("docType")
    if not doc_type or doc_type != expected_doc_type:
        raise ValueError(f"docType: expected '{expected_doc_type}', got '{doc_type}'")
    version = mso.get("version")
    if not version or version != expected_version:
        raise ValueError(f"version: expected '{expected_version}', got '{version}'")
    value_digests = mso.get("valueDigests")
    if not value_digests or not isinstance(value_digests, dict):
        raise ValueError("valueDigests is missing or invalid")
    digest_algorithm = mso.get("digestAlgorithm")
    if not digest_algorithm or digest_algorithm != HASH_ALGORITHM:
        raise ValueError(f"digestAlgorithm: expected '{HASH_ALGORITHM}', got '{digest_algorithm}'")


def _validate_mso_device_and_validity(mso: dict) -> None:
    """Validate MSO deviceKeyInfo and validityInfo."""
    device_key_info = mso.get("deviceKeyInfo")
    if not device_key_info or not isinstance(device_key_info, dict):
        raise ValueError("deviceKeyInfo is missing or invalid")
    device_key = device_key_info.get("deviceKey")
    if not device_key or not isinstance(device_key, dict):
        raise ValueError("deviceKeyInfo.deviceKey is missing or invalid")
    validity_info = mso.get("validityInfo")
    if not validity_info or not isinstance(validity_info, dict):
        raise ValueError("validityInfo is missing or invalid")
    _check_validity_info(validity_info)


def _check_validity_info(validity_info: dict) -> None:
    """
    Validate that validityInfo contains all required fields and that temporal values are consistent.

    :param validity_info: Dictionary containing the MSO validity fields.
    :raises ValueError: If any required field is missing or any temporal constraint is violated.
    """
    for field in ("signed", "validFrom", "validUntil"):
        if field not in validity_info:
            raise ValueError(f"validityInfo: missing required field '{field}'")

    signed_dt = validity_info["signed"]
    valid_from_dt = validity_info["validFrom"]
    valid_until_dt = validity_info["validUntil"]
    now_utc_ts = datetime.now(tz=timezone.utc)

    if not (valid_from_dt <= signed_dt <= valid_until_dt):
        raise ValueError("Field 'signed' is not within the range ['validFrom', 'validUntil']")

    if valid_from_dt > now_utc_ts:
        raise ValueError("Field 'validFrom' is in the future")

    if valid_until_dt < now_utc_ts:
        raise ValueError("Field 'validUntil' has already expired")


def _mso_to_json(mso: dict) -> dict:
    """Extract and return a JSON-serializable subset human-readable of the MSO dict."""

    device_key_info = mso.get("deviceKeyInfo") or {}
    _dict = {
        "docType": mso.get("docType"),
        "version": mso.get("version"),
        "digestAlgorithm": mso.get("digestAlgorithm"),
        "deviceKeyInfo": _decode_cose_key(device_key_info.get("deviceKey")),
        "validityInfo": mso.get("validityInfo")
    }
    return _make_json_serializable(_dict)


def _cose_alg_id_to_name(alg_id: int) -> str:
    """
    Map a COSE algorithm numeric ID to its human-readable name.
    Reference: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    """
    cose_alg_map = {
        -7: "ES256",
        -35: "ES384",
        -36: "ES512",
        -8: "EdDSA",
        -37: "PS256",
        -38: "PS384",
        -39: "PS512",
        -257: "RS256",
        -258: "RS384",
        -259: "RS512",
    }
    if alg_id not in cose_alg_map:
        return "Unknown"
    return cose_alg_map[alg_id]


def _decode_cose_key(device_key: dict) -> dict:
    """Decode a COSE key map into a JWK dict."""
    # Key type map
    kty_map = {2: "EC"}

    crv_map = {1: "P-256", 2: "P-384", 3: "P-521"}

    kty = device_key.get(1)
    alg = device_key.get(3)
    crv = device_key.get(-1)
    x = device_key.get(-2)
    y = device_key.get(-3)

    if kty in kty_map and crv in crv_map and x and y:
        jwk = {"kty": kty_map[kty], "crv": crv_map[crv], "x": base64url_encode(x), "y": base64url_encode(y)}
        alg_name = _cose_alg_id_to_name(alg)
        if alg_name != "Unknown":
            jwk["alg"] = alg_name
        return jwk
    else:
        raise ValueError("Cannot build JWK: missing or invalid COSE key fields")


T = TypeVar('T')
def _make_json_serializable(obj: T) -> T:
    """Recursively convert a decoded CBOR object into a JSON-serializable Python object."""
    if isinstance(obj, dict):
        return {k: _make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable(item) for item in obj]
    elif isinstance(obj, (datetime, date)):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        try:
            return base64.b64encode(obj).decode("ascii")
        except Exception:
            raise ValueError("Failed to convert bytes to base64")
    elif isinstance(obj, Decimal):
        return float(obj)
    else:
        return obj
