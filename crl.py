from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

import datetime
import os

import ca
import serial

crl_path = "crl.pem"

def data_to_crl(data):
    return x509.load_pem_x509_crl(data)

def load_serials_from_crl():
    serials = []
    
    with open(crl_path, "rb") as f:
        curr_crl = f.read()

    curr_crl = x509.load_pem_x509_crl(curr_crl)

    for r in curr_crl:
        if r not in serials:
            print (r)
            serials.append(r.serial_number)

    return serials


def load_crl():
    with open(crl_path, "rb") as f:
        curr_crl = f.read()

    return x509.load_pem_x509_crl(curr_crl)

def save_crl(new_crl):
    with open(crl_path, "w",) as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

    print("Saved CRL to disk")

# FIXME, make sure crl is updated once every hour
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

    
    # Get previous revoked serials
    if os.path.isfile(crl_path):
        loaded_crl = load_crl()   

        # Add previous revoked serials to our new crl
        #for r in revoked_serials:
        print(type(loaded_crl))
        for curr_revoked_cert in loaded_crl:
            builder = builder.add_revoked_certificate(curr_revoked_cert)
            
    builder = builder.add_revoked_certificate(revoked_cert)

    # Get ca and ca_key to sign and add attributes with
    rootca, rootca_key= ca.load_ca()
    
    curr_crl = builder.sign(
        
    private_key=rootca_key, algorithm=hashes.SHA256(),
    )

    save_crl(curr_crl)
    
    return curr_crl
