# Victor Näslund <victor@sunet.se>
# Code to create your own CA

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import serial

ca_certfile = "ca.pem"
ca_keyfile = "ca.key"

# FIXME read password from config file
ca_privatekeyfile_password = "CHANGEME"
ca_expiry = datetime.timedelta(365*2, 0, 0)

# FIXME change to ca from ca-test
# FIXME add proper email address
ca_nameattributes = [
    x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Stockholm"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Stockholm"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'SUNET'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'SUNET Infrastructure'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'ca-test.sunet.se'),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, 'soc@sunet.se'),
]

# FIXME get latest serial number for new cert issued by us
# Store in some database
def load_ca():
    # Write CA and key
    with open(ca_keyfile, "rb") as f:
        private_key = f.read()

    with open(ca_certfile, "rb") as f:
        cert = f.read()

    root_key = serialization.load_pem_private_key(
        private_key, password=ca_privatekeyfile_password.encode('utf-8')
    )

    root_cert = x509.load_pem_x509_certificate(cert)

    print("Loaded CA OK")
    
    return root_cert, root_key

def save_ca(certificate, private_key):
    # Write CA and key
    with open(ca_keyfile, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(ca_privatekeyfile_password.encode('utf-8'))
        ))

    with open(ca_certfile, "wb") as f:
        f.write(certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ))

    print("Saved CA to disk OK")

def new_ca(private_key=None):
    if private_key is None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(x509.Name(ca_nameattributes))

    builder = builder.issuer_name(x509.Name(ca_nameattributes))

    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0))
    builder = builder.not_valid_after(datetime.datetime.today() + ca_expiry)

    new_serial = serial.new_serial()
    builder = builder.serial_number(new_serial)

    builder = builder.public_key(private_key.public_key())
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256()
    )

    # Save serial to database
    serial.write_serial(new_serial)
    
    print("Created CA OK")
    
    return certificate, private_key


