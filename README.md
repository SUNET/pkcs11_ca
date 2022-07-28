# Libs and prerequsites

# sudo apt-get install uvicorn python3-fastapi softhsm python3-jwt python3-asyncpg
# pip3 install python_x509_pkcs11
# sudo apt-get --purge remove postgresql* # for a clean install if currently broken
# sudo apt install postgresql postgresql-contrib
#
# sudo systemctl restart postgresql
#sudo su - postgres -c "createuser pkcs11_testuser1"
#sudo su - postgres -c "createdb pkcs11_testdb1 -O pkcs11_testuser1"
#echo "Now run:"
#echo "sudo su - postgres"
#echo "psql"
#echo "alter user pkcs11_testuser1 with password 'DBUserPassword';"


# Run the code
bash dev-run.sh

# To run some tests, sign csrs, test the authorization, create crls
# Must be run while the uvicorn command above is running
# In another shell run:
# python3 -m unittest

# TODO: lookup extract RSA sig from GPG sig, should be possible so we can sign with current gpg yubikey signs
# Check, create and insert root ca in main.py not in postgres.py
