
# openssl ca -config ./ca.conf -out signed_cert_from_csr.pem -infiles csr.pem

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


import datetime

import ca
import validateCsr

csr_privatekeyfile_password = "CHANGEME"

def save_signed_csr(csr):
    # Write our CSR out to disk.
    with open("csr_signed.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("Saved signed CSR to disk OK")
        
def save_csr(csr, key):
    # Write our key to disk for safe keeping
    with open("csr_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                csr_privatekeyfile_password.encode('utf-8'))))

    # Write our CSR out to disk.
    with open("csr.pem", "wb") as f:
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
        
    # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256())

    print("Created CSR OK")
    
    return csr, private_key


def sign_csr(csr=None):
    if csr is None:
        with open("csr.pem", "rb") as f:
            csr_file = f.read()
        csr = x509.load_pem_x509_csr(csr_file)
    
    rootca, rootca_key= ca.load_ca()

    builder = x509.CertificateBuilder()
    builder = builder.public_key(csr.public_key())

    
    # Set our ca issuing names
    builder = builder.subject_name(x509.Name(csr.subject.rdns))
    builder = builder.issuer_name(x509.Name(ca.ca_nameattributes))

    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0))
    builder = builder.not_valid_after(datetime.datetime.today() + ca.ca_expiry)

    builder = builder.serial_number(ca.ca_serial_number)
    

    for e in csr.extensions:
        if e.oid.dotted_string == "2.5.29.17":
            # FIXME add error handling
            if not validateCsr.validate_subject_alternative_name(e):
                raise("FIXME not a valid name")
            
            builder = builder.add_extension(
                x509.SubjectAlternativeName(e.value),
                critical=True)

    certificate = builder.sign(
        private_key=rootca_key, algorithm=hashes.SHA256()
    )

    print("Signed certificate OK")
    
    return certificate
