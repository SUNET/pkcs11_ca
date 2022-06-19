
# openssl ca -config ./ca.conf -out signed_cert_from_csr.pem -infiles csr.pem

import datetime

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import ca
import serial
import db
import cert
import validateCsr
import config

# input a string
def data_to_csr(data):
    if isinstance(data, str):
        d = " " + data + " "
    else:
        d = " " + data.decode('utf-8') + " "

    values = d.split("-----")[2]
    if "\n" not in values:
        read_d = '\n'.join(values[i:i+64]
                          for i in range(0, len(values), 64))
        d = "-----BEGIN CERTIFICATE REQUEST-----\n" + read_d \
            + "\n-----END CERTIFICATE REQUEST-----\n"
    else:
        d = "-----BEGIN CERTIFICATE REQUEST-----" + values \
            + "-----END CERTIFICATE REQUEST-----\n"

    return x509.load_pem_x509_csr(d.encode('utf-8'))
        
def save_csr_file(csr, key, csr_path, key_path):
    # Write our key to disk for safe keeping
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                config.csr_keyfile_password.encode('utf-8'))))

    # Write our CSR out to disk.
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(Encoding.PEM))

    print("Saved CSR to disk OK")

def save_csr(csr):
    return db.save_csr(csr.public_bytes(Encoding.PEM).decode('utf-8'),
                       datetime.datetime.today(),
                       1 # FIXME: REAL author from http conenction
                       )
    
def new_csr(private_key=None):
    if private_key is None:
        # Generate our key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
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

    curr_date = datetime.datetime.today() - datetime.timedelta(1, 0, 0)
    builder = builder.not_valid_before(curr_date)
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

    certificate = builder.sign(private_key=rootca_key, algorithm=hashes.SHA256())


    id_csr = save_csr(csr)
    cert.save_cert(certificate, id_csr=id_csr)
    
    print("Signed certificate OK")
    
    return certificate
