Run

## Create a CA cert and key

rm -rf ca.crt ca.key serials.txt certdb.txt csr.pem csr.key csr_signed.pem crl.txt crl.pem certs; python3 test.py

## Start the CA server

python3 start.py

