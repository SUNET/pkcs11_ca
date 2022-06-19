import datetime
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

import ca
import serial
import db

def data_to_crl(data):
    if isinstance(data, str):
        d = " " + data + " "
    else:
        d = " " + data.decode('utf-8') + " "

    values = d.split("-----")[2]
    if "\n" not in values:
        read_d = '\n'.join(values[i:i+64]
                          for i in range(0, len(values), 64))
        d = "-----BEGIN X509 CRL-----\n" + read_d \
            + "\n-----END X509 CRL-----\n"
    else:
        d = "-----BEGIN X509 CRL-----" + values \
            + "-----END X509 CRL-----\n"

    return x509.load_pem_x509_crl(d.encode('utf-8'))

# FIXME read from db
def load_crl():
    return data_to_crl(db.load_crl())

def save_crl(new_crl):
    db.save_crl(new_crl.public_bytes(Encoding.PEM).decode('utf-8'),
                str(new_crl.last_update),
                str(new_crl.next_update),
                1) # FIXME REAL AUTHOR

    print("Saved CRL to disk")

def is_revoked(curr_serial, curr_crl=None):
    if curr_crl is None:
        curr_crl = load_crl()
    
    for c in curr_crl:
        if curr_serial == c.serial_number:
            return True

    return False

# FIXME, make sure crl is updated once every hour
def revoke_cert(curr_serial):

    if not db.serial_exists(serial.string(curr_serial)):
        # FIXME
        raise ("SERIAL NOT ISUED BY US")

    # If cert is already revoked
    loaded_crl = load_crl()
    if is_revoked(curr_serial, loaded_crl):
        return loaded_crl()
        
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name(ca.ca_nameattributes))

    # Set last update to one minute ago, to ensure no timing problems
    builder = builder.last_update(datetime.datetime.today() - datetime.timedelta(1))
    builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(1, 0, 0))


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
    
    #loaded_crl = load_crl()   
    #for curr_revoked_cert in loaded_crl:
    #    builder = builder.add_revoked_certificate(curr_revoked_cert)

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
        
