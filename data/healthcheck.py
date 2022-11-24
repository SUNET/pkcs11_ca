"""
Send a healthcheck request to the CA server
"""
import sys
import requests
from src.pkcs11_ca_service.asn1 import create_jwt_header_str

with open("trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()

request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, "http://localhost:8005/healthcheck")}
req = requests.get("http://localhost:8005/healthcheck", headers=request_headers, timeout=5)
if req.status_code == 200:
    sys.exit(0)
else:
    sys.exit(1)
