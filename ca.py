# Victor Näslund <victor@sunet.se>
# Code to create our own CA

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import serial
import cert
import config

# FIXME change to ca from ca-test
# FIXME add proper email address
ca_nameattributes = [
    x509.NameAttribute(NameOID.COUNTRY_NAME, config.ca_info_country_name),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.ca_info_state_or_province_name),
    x509.NameAttribute(NameOID.LOCALITY_NAME, config.ca_info_locality_name),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.ca_info_organization_name),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.ca_info_organizational_unit_name),
    x509.NameAttribute(NameOID.COMMON_NAME, config.ca_info_common_name),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, config.ca_info_email_address),
]

# FIXME get latest serial number for new cert issued by us
# Store in some database

# FIXME, get from hardware
def fingerprint():
    # Write CA and key
    with open(config.ca_keyfile, "rb") as f:
        private_key = f.read()

    with open(config.ca_certfile, "rb") as f:
        curr_cert = f.read()

    root_key = serialization.load_pem_private_key(
        private_key, password=config.ca_keyfile_password.encode('utf-8')
    )

    root_cert = x509.load_pem_x509_certificate(curr_cert)

    print("Loaded CA OK")
    
    return cert.fingerprint(root_cert)

def load_ca():
    # Write CA and key
    with open(config.ca_keyfile, "rb") as f:
        private_key = f.read()

    with open(ca_certfile, "rb") as f:
        curr_cert = f.read()

    root_key = serialization.load_pem_private_key(
        private_key, password=config.ca_keyfile_password.encode('utf-8')
    )

    root_cert = x509.load_pem_x509_certificate(curr_cert)

    print("Loaded CA OK")
    
    return root_cert, root_key

# FIXME, get from hardware
def new_ca(private_key=None):
    if private_key is None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name(ca_nameattributes))
    builder = builder.issuer_name(x509.Name(ca_nameattributes))

    builder = builder.not_valid_before(datetime.datetime.today() \
                                       - datetime.timedelta(1, 0, 0))
    builder = builder.not_valid_after(datetime.datetime.today() \
                                      + datetime.timedelta(config.expire_date, 0, 0))

    new_serial = serial.new_serial()
    builder = builder.serial_number(new_serial)
    builder = builder.public_key(private_key.public_key())
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256()
    )

    # DONT SAVE THE CAs serial, only for pki issued by the CA
    # serial.save_serial(new_serial)
    
    print("Created CA OK")
    
    return certificate, private_key

def save_ca(certificate, private_key):
    # Write CA and key
    with open(ca_keyfile, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(ca_keyfile_password.encode('utf-8'))
        ))

    with open(ca_certfile, "wb") as f:
        f.write(certificate.public_bytes(
            encoding=Encoding.PEM
        ))

    print("Saved CA to disk OK")
