import unittest
import requests


class TestSign(unittest.TestCase):
    """ Test pdf signing """
    url = "http://localhost:8006"

    def test_sign(self) -> None:
        """
        Test sign
        """
        req = requests.post(
            url=self.url + "/pdf/sign",
            headers={"Content-Type": "application/json"},
            json="",
            timeout=10,
            verify=False,
        )
        assert req.status_code == 200
