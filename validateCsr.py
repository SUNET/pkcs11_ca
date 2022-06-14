from cryptography import x509


valid_dns_file = "valid_dns_names.txt"

def is_valid_name(name, names):
    for n in names:

        # Make sure the topdmain is in the list
        # Not mydnssunet.se is invalid, it must be mydns.sunet.se
        if name.endswith("." + n):
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

# The cryptoprahpy lib should make sure we get the correct oid in the cert to validate agains
def validate_subject_name(extension):
    valid_names = valid_dns_names()

    for r in extension:
        if r.oid.dotted_string == "2.5.4.3":
            if is_valid_name(r.value, valid_names):        
                return True

    # FIXME better logging
    print("Falied validatation of subject name, could not find subject in cert")
    return False

