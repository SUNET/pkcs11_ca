
# openssl ca -config ./ca.conf -out signed_cert_from_csr.pem -infiles csr.pem

import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import ca
import serial
import certdb
import validateCsr

csr_privatekeyfile_password = "CHANGEME"

csr_keyfile = "csr.key"
csr_csrfile = "csr.pem"

def data_to_csr(data):
    csr = x509.load_pem_x509_csr(data)
    return csr
        
def save_csr(csr, key, csr_path, key_path):
    # Write our key to disk for safe keeping
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                csr_privatekeyfile_password.encode('utf-8'))))

    # Write our CSR out to disk.
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("Saved CSR to disk OK")
        
def new_csr(private_key=None):
    if private_key is None:
        # Generate our key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Malmo"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Malmo"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SUNET"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'SUNET SOC'),
        x509.NameAttribute(NameOID.COMMON_NAME, "sunet-soc-test.sunet.se"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName("test1-soc.sunet.se"),
            x509.DNSName("test2-soc.sunet.se"),
            x509.DNSName("test3-soc.sunet.se"),
        ]),
        critical=True,

    # Test to adding more extensions
    #).add_extension(
    #    x509.BasicConstraints(ca=False, path_length=None), critical=True,

    # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256())

    print("Created CSR OK")
    
    return csr, private_key

def sign_csr(csr):

    # Get ca and ca_key to sign and add attributes with
    rootca, rootca_key= ca.load_ca()

    builder = x509.CertificateBuilder()
    builder = builder.public_key(csr.public_key())

    # Set our ca issuing names
    if not validateCsr.validate_subject_name(csr.subject):
        raise("FIXME not a valid name")

    builder = builder.subject_name(x509.Name(csr.subject.rdns))
    builder = builder.issuer_name(x509.Name(ca.ca_nameattributes))

    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0))
    builder = builder.not_valid_after(datetime.datetime.today() + ca.ca_expiry)

    new_serial = serial.new_serial()
    builder = builder.serial_number(new_serial)

    for e in csr.extensions:
        # FIXME add error handling
        # If the extension is subject_alternative_name
        if e.oid.dotted_string == "2.5.29.17":
            if not validateCsr.validate_subject_alternative_name(e):
                raise("FIXME not a valid name")

        builder = builder.add_extension(e.value, critical=e.critical)

    certificate = builder.sign(
        private_key=rootca_key, algorithm=hashes.SHA256()
    )

    serial.write_serial(new_serial)
    certdb.write_cert(certificate)
    
    print("Signed certificate OK")
    
    return certificate
