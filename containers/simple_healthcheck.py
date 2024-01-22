"""
Send a healthcheck request to the remote pkcs11 server
"""

import sys

import requests

req = requests.get("http://localhost:8080/pkcs11/simple_healthcheck", timeout=10) #, verify="./tls_certificate.pem")
if req.status_code == 200:
    sys.exit(0)
else:
    sys.exit(1)
