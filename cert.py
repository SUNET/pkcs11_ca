from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes

import db
import serial

def data_to_cert(data):            
    if isinstance(data, str):
        d = " " + data + " "
    else:
        d = " " + data.decode('utf-8') + " "

    values = d.split("-----")[2]
    if "\n" not in values:
        read_d = '\n'.join(values[i:i+64]
                          for i in range(0, len(values), 64))
        
        d = "-----BEGIN CERTIFICATE-----\n" + read_d \
            + "\n-----END CERTIFICATE-----\n"
    else:
        d = "-----BEGIN CERTIFICATE-----" + values \
            + "-----END CERTIFICATE-----\n"
        
    return x509.load_pem_x509_certificate(d.encode('utf-8'))

def fingerprint(curr_cert):
    finger = curr_cert.fingerprint(algorithm=hashes.SHA256()).hex()
    if len(finger) % 2 != 0:
        finger = "0" + finger

    # Ensure all serials have the same length, its an integer so extra 0 at the begining is ok
    while len(finger) < 64:
        finger = "00" + finger
        
    colon_f = ':'.join(finger[i:i+2]
                       for i in range(0, len(finger), 2))
    
    return colon_f
    
# FIXME handle error better
def get_subject(curr_cert):
    try:
        for r in curr_cert.subject.rdns:
            if r.rfc4514_string().startswith("CN="):
                return r.rfc4514_string().replace("CN=", "")
    except:
        return None
    return None
          
def save_cert(new_cert, id_csr):
    curr_serial = serial.string(new_cert.serial_number)
    
    db.save_cert(curr_serial,
                 id_csr,
                 new_cert.public_bytes(Encoding.PEM).decode('utf-8'),
                 str(new_cert.not_valid_before),
                 str(new_cert.not_valid_after),
                 fingerprint(new_cert),
                 "FIXME"
                 )
    
    print("Saved cert to disk OK")
