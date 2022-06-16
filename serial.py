from cryptography import x509

import os

serials_path = "serials.txt"

# We use serials as integers in the code and store them as hex encoded integers in the database

def new_serial():
    return x509.random_serial_number()

def data_to_serial(data):
    if isinstance(data, str):
        d = data
    else:
        d = data.decode('utf-8')
    return int(d.replace(":", ""), base=16)

def save_serial(curr_serial):
    curr_serial = '%x' % curr_serial

    if len(curr_serial) % 2 != 0:
        curr_serial = "0" + curr_serial

    if not os.path.isfile(serials_path):
        with open(serials_path, "w") as f:
            f.write("# Serials are in hex format, same as openssl info for a cert\n")

    colon_s = ':'.join(curr_serial[i:i+2]
                       for i in range(0, len(curr_serial), 2))

    with open(serials_path, "a") as f:
        f.write(colon_s + "\n")
        
    print("Saved serial to disk OK")

def get_serials_pem():
    serials = ""

    with open(serials_path) as f:
        for line in f:
            if "#" in line or len(line) < 5:
                continue
            serials += line.replace("\n", ",")

    return serials[:-1]

    
def get_serials():
    serials = []

    with open(serials_path) as f:
        for line in f:
            if "#" in line:
                continue
            s = str(line[:-1])
            s = (int(s.replace(":", ""), base=16))
            serials.append(s)

    return serials

