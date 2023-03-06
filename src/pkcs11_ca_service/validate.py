"""Module to validate data"""
from fastapi import HTTPException

valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_/= \nåäöÅÄÖ")


def validate_input_string(input_string: str) -> None:
    """Validate an input string. We only allow letters, numbers, [+, -, _, /, =, ' ', \n] and swedish [å, ä, ö]

    Parameters:
    input_string (str): Input data.

    Returns:
    None
    """

    if not set(input_string).issubset(valid_chars):
        print("Non valid char in input")
        raise HTTPException(status_code=400, detail="Non valid char in input")
