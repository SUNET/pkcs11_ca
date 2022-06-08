
import sys

valid_dns_file = "valid_dns_names.txt"

def is_valid_name(name, names):
    for n in names:
        if name.endswith(n):
            return True
    return False

def valid_dns_names():
    names = {}
    with open(valid_dns_file) as f:
        for line in f:
            line = line.strip()
            
            if line.strip().startswith("#"):
                continue

            if len(line) < 2:
                continue

            names[line] = 0
    return names
            
def validate_subject_alternative_name(extension):
    valid_names = valid_dns_names()

    for v in extension.value:
        if not is_valid_name(v.value, valid_names):
            return False

    return True

