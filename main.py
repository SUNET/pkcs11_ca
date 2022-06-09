import ca
import csr
import serial

import os

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
csr.save_signed_csr(signed_csr, "csr_signed.pem")


# Show serial
# serials = serial.get_serials()


