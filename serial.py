import os

from cryptography import x509

import db

# We use serials as integers in the code and store them as hex encoded integers in the database

def new_serial():
    return x509.random_serial_number()

def data_to_serial(data):
    if isinstance(data, str):
        d = data
    else:
        d = data.decode('utf-8')
    return int(d.replace(":", ""), base=16)

def string(curr_serial):
    curr_serial_s = '%x' % curr_serial

    if len(curr_serial_s) % 2 != 0:
        curr_serial_s = "0" + curr_serial_s

    # Ensure all serials have the same length, its an integer so extra 0 at the begining is ok
    while len(curr_serial_s) < 40:
        curr_serial_s = "00" + curr_serial_s
        
    colon_s = ':'.join(curr_serial_s[i:i+2]
                       for i in range(0, len(curr_serial_s), 2))

    return colon_s

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

