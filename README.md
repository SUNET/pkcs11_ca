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


export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN='my_test_token_1'
export PKCS11_PIN='1234'

softhsm2-util --delete-token --token my_test_token_1
softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

# mypy  --strict --namespace-packages --ignore-missing-imports src/pkcs11_ca_service/*.py

# In another shell, start the server with
uvicorn src.pkcs11_ca_service.main:app --workers 1
