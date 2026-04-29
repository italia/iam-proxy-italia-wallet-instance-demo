import json
import logging

import requests

logger = logging.getLogger(__name__)


def get_json_from_response(response: requests.Response) -> str:
    """Parse JSON array of strings from oid_fed_list response."""
    data = response.json()
    return data


def get_dictionary_from_json(input: str) -> dict:
    '''
    Parses a JSON string and returns the dict.
    if input is empty return empty dictionary.
    if input is not a valid JSON string, raises a ValueError with an appropriate message.
    '''

    logger.debug(f"Entering method: get_dictionary_from_json. Params [input: {input}]")
    if not input:
        return {}
    try:
        if isinstance(input, dict):
            return input
        elif isinstance(input, str):
            return json.loads(input)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON string: {e}")

def get_value_from_json(input: str, key: str) -> any:
    '''
    if input is empty return None.
    if key is empty or not a string, raises a ValueError with an appropriate message.
    Returns the value associated with the specified key.
    '''

    logger.debug(f"Entering method: get_key_from_json. Params [input: {input}, key: {key}]")
    if not input:
        return None
    if not key or not isinstance(key, str):
        raise ValueError("Key cannot be empty or must be a string.")
    data = get_dictionary_from_json(input)
    return data.get(key)
