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


def validate_subject_name(extension):
    valid_names = valid_dns_names()

    # <Name(C=SE,ST=Malmo,L=Malo,O=SUNET,OU=SUNET SOC,CN=sunet-soc-test.sunet.se)>
    # The library handles parsing well so we dont have to
    for r in extension.rdns:
        if r.rfc4514_string().startswith("CN="):
            if is_valid_name(r.rfc4514_string(), valid_names):
                return True
    return False

