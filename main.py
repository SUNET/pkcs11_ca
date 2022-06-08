import ca
import csr

import os

if not os.path.isfile("ca.key"):
    rootca, rootca_key = ca.new_ca()
    ca.save_ca(rootca, rootca_key)

#rootca, rootca_key = ca.load_ca()

csr_cert, csr_key = csr.new_csr()
csr.save_csr(csr_cert, csr_key)

signed_csr = csr.sign_csr(csr_cert)
csr.save_signed_csr(signed_csr)

