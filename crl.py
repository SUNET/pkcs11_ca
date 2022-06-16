from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

import datetime
import os
import time

import ca
import serial

crl_path = "crl.pem"

def data_to_crl(data):
    return x509.load_pem_x509_crl(data)

# FIXME
def load_crl():
    if not os.path.isfile(crl_path):
        raise("FIXME")
    
    with open(crl_path, "rb") as f:
        curr_crl = f.read()

    return x509.load_pem_x509_crl(curr_crl)

def save_crl(new_crl):
    with open(crl_path, "w",) as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

    print("Saved CRL to disk")


def is_revoked(curr_serial):
    if os.path.isfile(crl_path):
        loaded_crl = load_crl()   
        for curr_revoked_cert in loaded_crl:
            if curr_serial == curr_revoked_cert.serial_number:
                return True

    return False

# FIXME, make sure crl is updated once every hour
def revoke_cert(curr_serial):
    if curr_serial not in serial.get_serials():
        raise("FIXME SERIAL WAS NOT ISSUED BY THIS CA")

    # If cert is already revoked
    if is_revoked(curr_serial):
        return load_crl()
    
    
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name(ca.ca_nameattributes))

    # Set last update to one minute ago, to ensure no timing problems
    builder = builder.last_update(datetime.datetime.today() - datetime.timedelta(1))
    builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(1, 0, 0))

    # Add previous revoked serials
    if os.path.isfile(crl_path):
        loaded_crl = load_crl()   
        for curr_revoked_cert in loaded_crl:
            builder = builder.add_revoked_certificate(curr_revoked_cert)

    # Add this cert to crl
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        curr_serial
    ).revocation_date(
        datetime.datetime.today()
    ).build()
    
    # Add this serial to the new crl
    builder = builder.add_revoked_certificate(revoked_cert)

    # Get ca and ca_key to sign
    rootca, rootca_key= ca.load_ca()
    
    curr_crl = builder.sign(private_key=rootca_key, algorithm=hashes.SHA256(),)

    save_crl(curr_crl)

    print ("Revoked cert OK")
    
    return curr_crl

def new_crl():
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name(ca.ca_nameattributes))

    # Set last update to 2 minutes ago, to ensure no timing problems
    builder = builder.last_update(datetime.datetime.today() - datetime.timedelta(2))
    builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(1, 0, 0))
    
    # Get previous revoked serials
    if os.path.isfile(crl_path):
        loaded_crl = load_crl()   
        for curr_revoked_cert in loaded_crl:
            builder = builder.add_revoked_certificate(curr_revoked_cert)

    # Get ca and ca_key to sign
    rootca, rootca_key= ca.load_ca()
    
    curr_crl = builder.sign(private_key=rootca_key, algorithm=hashes.SHA256(),)

    save_crl(curr_crl)

    print ("Created new CRL")
    
    return curr_crl

# Ensure we create a new CRL every interval (24 hours)
def background_worker(interval):
    while True:
        new_crl()
        time.sleep(interval)
        
