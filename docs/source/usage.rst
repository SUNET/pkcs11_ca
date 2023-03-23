Usage
=====

Installation
------------

To use PKCS11 CA, first install it using

.. code-block:: bash

   # Clone down the repository
   git clone https://github.com/SUNET/pkcs11_ca.git
   
   # Install openssl python3-pip, docker and docker-compose
   # For example: sudo apt-get install docker.io openssl python3-pip
   # pip3 install docker-compose

.. code-block:: bash

   # Export env variables
   export CA_URL="https://ca:8005"
   export CA_DNS_NAME="ca"

   export ACME_ROOT="/acme" # no trailing /

   export PKCS11_SIGN_API_TOKEN="xyz"

   export PKCS11_TOKEN=my_test_token_1
   export PKCS11_PIN=1234
   export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

   export POSTGRES_HOST="postgres"
   export POSTGRES_USER="pkcs11_testuser1"
   export POSTGRES_PASSWORD="DBUserPassword"
   export POSTGRES_PORT="5432"
   export POSTGRES_DATABASE="pkcs11_testdb1"
   export POSTGRES_TIMEOUT="5"

.. code-block:: bash

   # Create and start the containers
   bash deploy.sh

.. note::

   Your CA's $CA_URL **MUST** be reachable from your client and the clients DNS name **MUST** be reachable from the CA.

   | A simple way is ensuring that both the CA and client uses public DNS
   | **or** your having your client in a container in the CA's docker network.


Start a container in the CA's docker network
----------------

.. code-block:: bash

   # To start a container inside the CA's docker network
   docker run --user 0 -it --entrypoint /bin/bash --network pkcs11_ca_default pkcs11_ca_test1


Using an ACME client with the PKCS11 CA
----------------
The Automatic Certificate Management Environment (ACME) protocol is a communications protocol for automating interactions between certificate authorities and their users' servers.
Allowing the automated deployment of public key infrastructure at very low cost.
It was designed by the Internet Security Research Group (ISRG) for their Let's Encrypt service.
The protocol, based on passing JSON-formatted messages over HTTPS has been published as an Internet Standard in RFC 8555 by its own chartered IETF working group

We will use `Dehydrated <https://github.com/dehydrated-io/dehydrated>`_ as our ACME client for this example.

.. code-block:: bash

   # Inside the container you started above
   # Get dehydrated
   git clone https://github.com/dehydrated-io/dehydrated.git
   cd dehydrated

   # The CA uses a self-signed certificate by default for its https connections so lets add the '-k' option to dehydrated's curl command
   sed -i 's/ CURL_OPTS=$/ CURL_OPTS=" -k "/g' dehydrated

   # Get the dns hostname which the certificate will be issued to.
   echo $HOSTNAME > domains.txt

   # Create a CSR for our hostname, this does not have to be using RSA, an EC curve is preferable.
   openssl req -subj "/C=SE/CN=my-web-server" -addext "subjectAltName = DNS:${HOSTNAME}" -new -newkey rsa:2048 -nodes -keyout csr_rsa.key -out csr_rsa.pem

   # Remove old ACME account if exists and create ACME challenge folder
   # rm -rf /var/www/dehydrated accounts/
   mkdir -p /var/www/dehydrated

.. code-block:: python

   # Copy and run this python script
   # which runs dehydrated and also responds to the CA's ACME challenge
   from typing import Union
   import threading
   from http.server import BaseHTTPRequestHandler, HTTPServer
   import time
   import subprocess
   import sys
   import os

   class AcmeChallengeHTTPRequestHandler(BaseHTTPRequestHandler):

     def do_GET(self) -> None:
       tokens = os.listdir("/var/www/dehydrated")
       if len(tokens) != 1:
         print("ERROR: must have only one token in /var/www/dehydrated")
         sys.exit(1)

       with open(f"/var/www/dehydrated/{tokens[0]}", "rb") as f_data:
         key_auth = f_data.read()

       self.send_response(200)
       self.send_header("Content-Length", str(len(key_auth)))
       self.end_headers()

       self.wfile.write(key_auth)
       self.server.server_close()
       self.server.shutdown()


   def run_http_server() -> None:
     server_address = ("", 80)
     httpd = HTTPServer(server_address, AcmeChallengeHTTPRequestHandler)
     httpd.timeout = 10
     httpd.handle_request()

   t = threading.Thread(target=run_http_server, daemon=True)
   t.start()
   time.sleep(2)

   # Run dehydrated to register an ACME account with the CA
   # The CA url is configurable in the config file
   subprocess.call(["bash", "-c", "bash dehydrated --register --accept-terms --ca 'https://ca:8005/acme/directory' --algo secp384r1"])

   # Run dehydrated to request the CA to sign our CSR
   subprocess.call(["bash", "-c", "bash dehydrated --accept-terms --signcsr csr_rsa.pem --ca 'https://ca:8005/acme/directory' | grep -v '# CERT #' > chain.pem"])

   # The issued certificate and its chain
   print("Certificate chain from the CA")
   subprocess.call(["bash", "-c", "cat chain.pem"])

   # The private key for the issued certificate
   print("Private key file: csr_rsa.key")

   # Revoking is done in this way. It will, among other things, cause the CA to put the certificate on its CRL.
   # subprocess.call(["bash", "-c", "bash dehydrated --revoke chain.pem --ca 'https://ca:8005/acme/directory'"])

