import ca
import csr
import serial
import crl
import cert
import certdb

#if not os.path.isfile("ca.key"):
#rootca, rootca_key = ca.new_ca()
#ca.save_ca(rootca, rootca_key)
#else:
rootca, rootca_key = ca.load_ca()

# Create new csr
csr_cert, csr_key = csr.new_csr()
csr.save_csr(csr_cert, csr_key, "csr.pem", "csr.key")

# Sign csr
signed_csr = csr.sign_csr(csr_cert)
cert.save_cert(signed_csr, "csr_signed.pem")

# Create new csr
csr_cert, csr_key = csr.new_csr()
csr.save_csr(csr_cert, csr_key, "csr.pem", "csr.key")

# Sign csr
signed_csr = csr.sign_csr(csr_cert)
cert.save_cert(signed_csr, "csr_signed.pem")

# Show serial
serials = serial.get_serials()

# Revoke the cert 
curr_crl = crl.revoke_cert(serials[1])


# fingerprint = cert.fingerprint_cert(signed_csr)



certdb.get_issued_certs()

curr_crl = crl.load_crl()

print(curr_crl)
