from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import os

import cert

certs_folder_root = "./certs"
certdb_path = "certdb.txt"

def get_issued_certs():
    certs = []
    curr_data = ""
    
    with open(certdb_path) as f:
        for line in f:
            if "#" in line:
                continue
            
            if "-----BEGIN CERTIFICATE-----" in line:
                curr_data = line
            elif "-----END CERTIFICATE-----" in line:
                curr_data += line
                if "-----BEGIN CERTIFICATE-----" not in curr_data:
                    continue
                certs.append(cert.data_to_cert(curr_data))
            else:
                curr_data += line

    return certs
                
    
def save_cert(new_cert):
    if not os.path.isfile(certdb_path):
        with open(certdb_path, "w") as f:
            f.write("# CERTS just one after another\n")
            f.write("# are comments\n")
            f.write("""# -----BEGIN CERTIFICATE-----
MIID6jCCAtKgAwIBAgIUNmCdij/Na3WBNO8dYctkkI5lub8wDQYJKoZIhvcNAQEL
BQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0xEjAQBgNVBAcM
CVN0b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNVTkVUIEluZnJh
c3RydWN0dXJlMRkwFwYDVQQDDBBjYS10ZXN0LnN1bmV0LnNlMRswGQYJKoZIhvcN
AQkBFgxzb2NAc3VuZXQuc2UwHhcNMjIwNjEyMDk1OTEyWhcNMjQwNjEyMDk1OTEy
WjBzMQswCQYDVQQGEwJTRTEOMAwGA1UECAwFTWFsbW8xDjAMBgNVBAcMBU1hbG1v
MQ4wDAYDVQQKDAVTVU5FVDESMBAGA1UECwwJU1VORVQgU09DMSAwHgYDVQQDDBdz
dW5ldC1zb2MtdGVzdC5zdW5ldC5zZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANvPkp9ZOTdlmlYF1xIhblSDHGhesExuUHUyVHqbfmM9X/0+fRl2QLfZ
s9s1kFe5j7kNV4V0LPig6jR9TvCZ7FpGw0pwFS9jhjQvqg3cabHQBliJxPHwGq60
Z3VlpYwoz99EkcyLo/Qv3Wfl4uEnjrR3HED0gQJLcugIQ80yLmSC0SJ6cfSNFIa0
8COb5hXu4w0znen/BF23k7ykfgEAzCr7joUzCkGcYMB1G5GKQoqTTKt9wJzhDmaJ
L7wpQjzGOa0S5qzqOkyX29itk8+Cs6Q4a2uQ2xqtATuTAcJL1AFdYIZyGn5BPr9X
ptnA/uMdEMYrd4Ls49K2GmzLT32Nu5sCAwEAAaNMMEowSAYDVR0RAQH/BD4wPIIS
dGVzdDEtc29jLnN1bmV0LnNlghJ0ZXN0Mi1zb2Muc3VuZXQuc2WCEnRlc3QzLXNv
Yy5zdW5ldC5zZTANBgkqhkiG9w0BAQsFAAOCAQEArWKPvIZic6+gNBSoDSTAl0L/
ZJQFmywUux4yRNzDeoHoHQcpKmlxwnhpIOSTMOvSxqBGo2B1S/RLimeiw3X6dlKK
mxBshGonkwUI3+XtQ0uv5dKfn6VQh+WtPzGYvwi3E/tCZHqyxQ9NdlHBx0XyJXAm
VyTQLIK8epgMk1Akfr2vHoxdgvozKWavzu9D9CbVbB5lcfkcyZlrLED6az6gzigu
w8H84CnxHehgvABlVz1HiFqT3iBaVXVQgMDCTDsAeKnVO+g9WZezLi3+mlhH8qWD
qtppkTdG/GxT0R4Jl9cCFtkMZEFUu/eUvcRqLcr5hoxg5Gf8HqVZ6BVrOrEaWA==
-----END CERTIFICATE-----

""")
    
    # Write our CSR to oyt certdb.
    with open(certdb_path, "a") as f:
        f.write(new_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8') + "\n")

    fingerprint = cert.fingerprint_cert(new_cert)
    # create folder
    os.makedirs(certs_folder_root +"/" + fingerprint[0:2], mode=0o755, exist_ok=True) 

    subject = cert.get_subject(new_cert)
    if subject is None:
        cert_path = certs_folder_root +"/" + fingerprint[0:2] + "/" + fingerprint + ".pem"
    else:
        cert_path = certs_folder_root +"/" + fingerprint[0:2] + "/" + subject + ".pem"
            
    # Write our CSR out to disk.
    with open(cert_path, "w") as f:
        f.write(new_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8') + "\n")
