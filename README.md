# TODO: lookup extract RSA sig from GPG sig, should be possible so we can sign with current gpg yubikey signs
# Check, create and insert root ca in main.py not in postgres.py

# * Postgres container from debian and then install postgresql, replace the 'docker official' postgres container
# * Remove DB and pkcs11 keys created from tests
# * Certificate Management over CMS
# * ACME
# * GPG JWT sigs, perhaps extract underlying RSA/ec/eddsa public key, in addition to RSA/ec/eddsa

# To run, deploy, test and everything run
bash dev-run.sh

# If problems then simply stop the containers, delete database and hsm data ./data/db_data and ./data/hsm_tokens then run bash dev-run.sh to recreate the system

# To delete a label in the PKCS11 device:
pkcs11-tool -b --login --so-pin $PKCS11PIN --pin $PKCS11PIN --token $PKCS11_TOKEN --module $PKCS11_MODULE --label my_label_here -y privkey
pkcs11-tool -b --login --so-pin $PKCS11PIN --pin $PKCS11PIN --token $PKCS11_TOKEN --module $PKCS11_MODULE --label my_label_here -y pubkey
