from app.models.config.credentials_config import Credential, CredentialsConfig


def get_mdoc_claim(config, credential):
    element_id = config.get("element_identifier")
    elm_keys = []
    if config.get("subgroup"):
        elm_keys.extend(config.get("subgroup").split("."))
    elm_keys.append(element_id)
    if config.get("namespace"):
        data = credential.get("nameSpaces", {}).get(config.get("namespace"), {})
    else:
        data = credential.get("mso", {})
    return __get_nested_value(data, elm_keys)


def get_sdjwt_claim(config, credential):
    element_id = config.get("element_identifier")
    elm_keys = []
    if config.get("subgroup"):
        elm_keys.extend(config.get("subgroup").split("."))
    elm_keys.append(element_id)
    return __get_nested_value(credential, elm_keys)


def parser_credential_format_to_internal(
    credential_config: CredentialsConfig, credential_type_id: str, credential: dict
) -> dict:
    cred_conf: Credential = credential_config.supported_credentials.get(credential_type_id)
    internal_mapping = credential_config.internal_attributes_mappings.get(cred_conf.internal_mapping_ref)

    fmt_id = cred_conf.document_format.id
    _parser_func = __get_parser_func(fmt_id)
    if _parser_func is None:
        raise ValueError(f"Unsupported credential format: {fmt_id}")

    internal_credential = {}
    for k, v in internal_mapping.items():
        fmt_mapping = v.get(fmt_id)
        value = _parser_func(fmt_mapping, credential)

        keys = k.split(".")
        if len(keys) > 1:
            target = internal_credential.setdefault(keys[0], {})
            for part in keys[1:-1]:
                target = target.setdefault(part, {})
            target[keys[-1]] = value
        else:
            internal_credential[k] = value

    return internal_credential


def __get_parser_func(fmt_id: str):
    parser_funcs = {
        "mdoc-cbor": get_mdoc_claim,
        "sd-jwt-vc": get_sdjwt_claim,
    }
    return parser_funcs.get(fmt_id)


def __get_nested_value(data: dict, keys: list):
    if not keys:
        return data
    if not isinstance(data, dict):
        return None
    return __get_nested_value(data.get(keys[0]), keys[1:])
