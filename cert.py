from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def data_to_cert(data):
    return x509.load_pem_x509_certificate(bytes(data, 'utf-8'))

def fingerprint_cert(curr_cert):
    return curr_cert.fingerprint(algorithm=hashes.SHA256()).hex()

# FIXME handle error better
def get_subject(curr_cert):
    try:
        for r in curr_cert.subject.rdns:
            if r.rfc4514_string().startswith("CN="):
                return r.rfc4514_string().replace("CN=", "")
    except:
        return None
    return None
          
def save_cert(new_cert, new_cert_path):
    # Write our CSR out to disk.
    with open(new_cert_path, "wb") as f:
        f.write(new_cert.public_bytes(serialization.Encoding.PEM))

    print("Saved cert to disk OK")
