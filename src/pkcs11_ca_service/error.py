"""
Module which have all our exceptions
"""


class DBInitFail(Exception):
    """Class to handle DB init"""

    def __init__(self, message: str = "DB init fail") -> None:

        self.message = message
        super().__init__(self.message)


class NoSuchDBObject(Exception):
    """Class to handle objects not existsing in DB"""

    def __init__(self, message: str = "No such object in DB") -> None:

        self.message = message
        super().__init__(self.message)


class UnsupportedJWTAlgorithm(Exception):
    """Class to handle unsupported JTW algorithms"""

    def __init__(self, message: str = "Unsupported JWT algorithm") -> None:

        self.message = message
        super().__init__(self.message)


class WrongDataType(Exception):
    """Class to handle wrong data types"""

    def __init__(self, message: str = "Wrong data type") -> None:

        self.message = message
        super().__init__(self.message)
