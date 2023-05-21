"""
Test our timestamp
"""
import os
import subprocess
import unittest

import requests

from src.pkcs11_ca_service.config import ROOT_URL

from .lib import verify_pkcs11_ca_tls_cert

TIMESTAMP_ENDPOINT = "/timestamp"
TIMESTAMP_CONTENT_TYPE = "application/timestamp-query"


class TestTimestamp(unittest.TestCase):
    """
    Test our timestamp
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_timestamp(self) -> None:
        """
        Test timestamp response
        """

        timestamp_req = b"0C\x02\x01\x01010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 \xe2!qiO\xd8\xe4$\x05P\xf9\x95\xc5X\xbc\xc9g\xb3\xdf\x0e\x92\x8bQ\xa7F\xb2\xcb\xa2om\x9e\xa4\x02\x08\x00\x84\xeb\xbb\xeben\x1e\x01\x01\xff"  # pylint: disable=line-too-long

        req = requests.post(
            self.ca_url + TIMESTAMP_ENDPOINT,
            data=timestamp_req,
            headers={"Content-Type": TIMESTAMP_CONTENT_TYPE},
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        print(req.content.hex())

    def test_timestamp_verify(self) -> None:
        """
        Test timestamp response and verify with openssl
        """

        # 34070729087df0bb18ae8e7e4659a4f58e4fe57e626a8e345c6ec85aae265cf0 is the timestamp_state.txt sha256 hash
        # hash_message =$(openssl dgst -sha256 state.txt | cut -d " " -f 2)
        subprocess.check_call(
            [
                "bash",
                "-c",
                """echo "testmessage" > timestamp_state.txt; openssl ts -query -digest 34070729087df0bb18ae8e7e4659a4f58e4fe57e626a8e345c6ec85aae265cf0 -sha256 -cert -out ts_req.tsq 2> /dev/null; curl -k https://ca:8005/timestamp -H 'Content-Type: application/timestamp-query' -s -S --data-binary "@ts_req.tsq" -o "ts_req.tsr" ; openssl ts -reply -in ts_req.tsr -token_out 2> /dev/null | openssl pkcs7 -inform der -print_certs 2> /dev/null | sed -n '/-----BEGIN/,/-----END/p' > timestamp_chain.pem ; openssl ts -verify -digest 34070729087df0bb18ae8e7e4659a4f58e4fe57e626a8e345c6ec85aae265cf0 -in ts_req.tsr -CAfile timestamp_chain.pem > /dev/null 2> /dev/null""",  # pylint: disable=line-too-long
            ]
        )
        # Dummy code for unittest to run?
        self.assertTrue(1 == 2 - 1)
