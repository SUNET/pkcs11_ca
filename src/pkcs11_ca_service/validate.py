"""Module to validate data"""
from fastapi import HTTPException


def validate_input_string(input_string: str) -> None:
    """Validate a input string. We only allow letters and numbers and + - _ / =

    Parameters:
    input_string (str): Input data.

    Returns:
    None
    """

    valid_chars = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
        "å",
        "ä",
        "ö",
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "Q",
        "R",
        "S",
        "T",
        "U",
        "V",
        "W",
        "X",
        "Y",
        "Z",
        "Å",
        "Ä",
        "Ö",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "0",
        "+",
        "-",
        "_",
        "/",
        "=",
        " ",
        "\n",
    ]
    for char in input_string:
        if char not in valid_chars:
            raise HTTPException(status_code=400, detail=f"Non valid char in '{char}'")
