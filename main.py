import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import ca
import csr
import serial
import crl
import cert
import certdb

# Create/load new ca
if not os.path.isfile("ca.key"):
    rootca, rootca_key = ca.new_ca()
    ca.save_ca(rootca, rootca_key)
else:
    rootca, rootca_key = ca.load_ca()

# Create new csr
csr_cert, csr_key = csr.new_csr()
csr.save_csr(csr_cert, csr_key, "csr.pem", "csr.key")

# Sign csr
signed_csr = csr.sign_csr(csr_cert)
cert.save_cert(signed_csr, "csr_signed.pem")

fingerprint = signed_csr.fingerprint(hashes.SHA256()).hex()


# Show serial
serials = serial.get_serials()

print(serials)

c = 0
for curr_serial in serials:
    if c == 1:
        print(curr_serial.hex())
        crl.revoke_cert(curr_serial)
    c += 1

certdb.get_issued_certs()
