from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

import datetime

import ca
import serial

crl_path = "crl.txt"

def save_crl(new_crl):
    # Write our CSR out to disk.
    with open(crl_path, "a",) as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM).decode('utf-8'))


def revoke_cert(curr_serial):
    if curr_serial not in serial.get_serials():
        raise("FIXME SERIAL NOT EXIST")
    
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name(ca.ca_nameattributes))
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(1, 0, 0))
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        curr_serial
    ).revocation_date(
        datetime.datetime.today()
    ).build()
    
    builder = builder.add_revoked_certificate(revoked_cert)
    builder = builder.add_revoked_certificate(revoked_cert)

    # Get ca and ca_key to sign and add attributes with
    rootca, rootca_key= ca.load_ca()
    
    curr_crl = builder.sign(
        
    private_key=rootca_key, algorithm=hashes.SHA256(),
    )

    save_crl(curr_crl)
    
    return curr_crl
