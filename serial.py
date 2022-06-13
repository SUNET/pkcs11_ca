from cryptography import x509

import os

serials_path = "serials.txt"

def new_serial():
    return x509.random_serial_number()

def save_serial(curr_serial):
    curr_serial = '%x' % curr_serial

    if len(curr_serial) % 2 != 0:
        curr_serial = "0" + curr_serial

    if not os.path.isfile(serials_path):
        with open(serials_path, "w") as f:
            f.write("# Serials are in hex format, same as openssl info for a cert\n")

    colon_s = ':'.join(curr_serial[i:i+2]
                       for i in range(0, len(curr_serial), 2))
    print (colon_s)
    
    with open(serials_path, "a") as f:
        f.write(colon_s + "\n")
        
    print("Saved serial to disk OK")

def get_serials():
    serials = {}

    with open(serials_path) as f:
        for line in f:
            if "#" in line:
                continue
            s = str(line[:-1])
            s = (int(s.replace(":", ""), base=16))
            serials[s] = 0

    return serials
