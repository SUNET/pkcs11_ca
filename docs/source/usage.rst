Usage
=====

Installation
------------

To use PKCS11 CA, first install it.

Quickly check the first `requirements <https://pkcs11-ca.readthedocs.io/en/latest/requirements.html>`_.

.. code-block:: bash

   # Clone down the repository
   git clone https://github.com/SUNET/pkcs11_ca.git
   
   # Install docker and docker-compose
   # For example on ubuntu/debian:
   # sudo apt-get install docker.io docker-compose

   # Add user to docker group
   sudo usermod -aG docker $USER

   # Update your docker group membership **or** open a new shell
   exec sudo su -l $USER


.. code-block:: bash

   # Lets run with default values for this usage guide.
   # Export the following env variables

   # The URL and DNS name for the PKCS11 CA
   export CA_URL="https://ca:8005"
   export CA_DNS_NAME="ca"

   # The ACME root url endpoint
   export ACME_ROOT="/acme" # no trailing /

   # The API token for the PKCS11 raw signature url endpoint
   export PKCS11_SIGN_API_TOKEN="xyz"

   # PKCS11 token and pin
   export PKCS11_TOKEN="my_test_token_1"
   export PKCS11_PIN="1234"

   # Path to PKCS11 library, SOFTHSM on ubuntu/debian as default
   export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

   # Database variables
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

   Config documentation is `here <https://pkcs11-ca.readthedocs.io/en/latest/configuration.html>`_.

   Your CA's $CA_URL **MUST** be reachable from your client and the clients DNS name **MUST** be reachable from the CA.

   * A simple way is ensuring that both the CA and client uses public DNS
   * **or** having your client in a container in the CA's docker network, see below.


Start a container in the CA's docker network
--------------------------------------------

.. code-block:: bash

   # To start a container inside the CA's docker network
   docker run -it --entrypoint /bin/bash --network pkcs11_ca_default pkcs11_ca_test1


Using an ACME client with the PKCS11 CA
---------------------------------------

The Automatic Certificate Management Environment (ACME) protocol is a communications protocol for automating interactions between certificate authorities and their users' servers.
Allowing the automated deployment of public key infrastructure at very low cost.
It was designed by the Internet Security Research Group (ISRG) for their Let's Encrypt service.
The protocol, based on passing JSON-formatted messages over HTTPS has been published as an Internet Standard in RFC 8555 by its own chartered IETF working group

We will use `Dehydrated <https://github.com/dehydrated-io/dehydrated>`_ as our ACME client for this example.

We will use the client's ENV $HOSTNAME for the hostname the certificate to be issued to.

Copy paste this script as **acme_setup.sh**
which runs dehydrated and also responds to the CA's ACME challenge

.. code-block:: bash

   # Client with mutual DNS access to the CA, maybe the container you started above
   # Get dehydrated
   git clone https://github.com/dehydrated-io/dehydrated.git

   # The CA uses a self-signed certificate by default for its https connections so lets add the '-k' option to dehydrated's curl command
   sed -i 's/ CURL_OPTS=$/ CURL_OPTS=" -k "/g' dehydrated/dehydrated

   # Get the dns hostname which the certificate will be issued to.
   echo $HOSTNAME > domains.txt

   # Create a CSR for our hostname, this does not have to be using RSA, an EC curve is preferable.
   openssl req -subj "/C=SE/CN=my-https-server" -addext "subjectAltName = DNS:${HOSTNAME}" -new -newkey rsa:2048 -nodes -keyout csr_rsa.key -out csr_rsa.pem

   # Create ACME challenge folder
   mkdir -p /var/www/dehydrated

Copy paste this script as **acme_setup.py**
which sets up dehydrated and creates a CSR for the CA to sign using our ACME client


.. code-block:: bash

   bash acme_setup.sh


Copy paste this script as **acme_run.py**
which runs dehydrated and also responds to the CA's ACME challenge

.. code-block:: python

   #!/usr/bin/env python3

   from typing import Union
   from http.server import BaseHTTPRequestHandler, HTTPServer
   import time, subprocess, sys, os, threading

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
     # In the odd case you need root to bind to port 80 then run the container with 'docker run --user 0'
     server_address = ("", 80)
     httpd = HTTPServer(server_address, AcmeChallengeHTTPRequestHandler)
     httpd.timeout = 10
     httpd.handle_request()

   t = threading.Thread(target=run_http_server, daemon=True)
   t.start()
   time.sleep(2)

   # Run dehydrated to register an ACME account with the CA
   # The CA url is configurable in the config file
   subprocess.call(["bash", "-c", "bash dehydrated/dehydrated --register --accept-terms --ca 'https://ca:8005/acme/directory' --algo secp384r1"])

   # Run dehydrated to request the CA to sign our CSR
   subprocess.call(["bash", "-c", "bash dehydrated/dehydrated --accept-terms --signcsr csr_rsa.pem --ca 'https://ca:8005/acme/directory' | grep -v '# CERT #' > cert.pem"])

   # The issued certificate and its chain
   print("Certificate chain from the CA")
   subprocess.call(["bash", "-c", "cat cert.pem"])

   # The private key for the issued certificate
   print("Private key file: ./csr_rsa.key")

   # Revoking is done in this way. It will, among other things, cause the CA to put the certificate on its CRL.
   # subprocess.call(["bash", "-c", "bash dehydrated/dehydrated --revoke cert.pem --ca 'https://ca:8005/acme/directory'"])


Run the python script

.. code-block:: bash

   python3 acme_run.py

Retrieving the issuer for a certificate
---------------------------------------

| **All** non root certificates issued by the PKCS11 CA have the Authority Information Access extension with **CA Issuers**
| It contains an URL to the certificate's issuer certificate.
| This is defined in `RFC 3280 <https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.2.1>`_

This can be used to fetch the certificate chain.

.. code-block:: bash

   # Assuming your certificate file is cert.pem
   ISSUER=$(openssl x509 -noout -text -in cert.pem | grep "CA Issuers - " | cut -f 2-4 -d ':')
   curl -k $ISSUER | openssl x509 -inform DER > issuer.pem

   # View the certificate, '-text' for extra info
   openssl x509 -noout -text -in issuer.pem

   # Verify the issuer *actually is* the issuer of the certificate
   openssl verify -CAfile issuer.pem cert.pem

Retrieving the CRL for the issuer of a certificate
--------------------------------------------------

| **All** non root certificates issued by the PKCS11 CA have the CRL Distribution Points extension
| It contains an URL to the certificate's issuer CRL.
| This is defined in `RFC 3280 <https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.14>`_

This can be used to fetch the CRL needed to verify that the certificate has not been revoked.

.. code-block:: bash

   # Assuming your certificate file is cert.pem
   CRL=$(openssl x509 -noout -text -in cert.pem  | grep -A 4 "CRL Distribution Points:" | grep "URI:" | cut -f 2-4 -d ':')
   curl -k $CRL | openssl crl -inform DER > crl.pem

   # To use the CRL to verify the certificate we also need the certificate issuer for it
   ISSUER=$(openssl x509 -noout -text -in cert.pem | grep "CA Issuers - " | cut -f 2-4 -d ':')
   curl -k $ISSUER | openssl x509 -inform DER > issuer.pem

   # View the CRL, '-text' for extra info
   openssl crl -noout -in crl.pem -text

   # Verify the certificate using the crl
   openssl verify -crl_check -CRLfile crl.pem -CAfile issuer.pem cert.pem

OCSP
----

| **All** non root certificates issued by the PKCS11 CA have the Authority Information Access extension with **OCSP**
| It contains an URL to the certificate's issuer OCSP responder.
| This is defined in `RFC 5280 <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1>`_

This can be used to send an OCSP request to check if the certificate has been revoked or not

.. code-block:: bash

   # Assuming your certificate file is cert.pem
   OCSP=$(openssl x509 -noout -text -in cert.pem  | grep "OCSP - " | cut -f 2-4 -d ':')

   # To use OCSP to verify the certificate we also need the certificate issuer for it
   ISSUER=$(openssl x509 -noout -text -in cert.pem | grep "CA Issuers - " | cut -f 2-4 -d ':')
   curl -k $ISSUER | openssl x509 -inform DER > issuer.pem

   # Send an OCSP request to the PKCS11 CA to verify the certificate, '-text' for extra info
   openssl ocsp -issuer issuer.pem -cert cert.pem -text -url $OCSP

CMC requests
----------------------------

| PKCS11 CA supports CMC requests
| This is defined in `RFC 5272 <https://www.rfc-editor.org/rfc/rfc5272>`_

| Under construction
| This can be used to send an CMC request and receiving CMC responses from the PKCS11 CA
| Look at the unittest `test_cmc.py <https://github.com/SUNET/pkcs11_ca/blob/main/tests/test_cmc.py>`_

.. code-block:: python

   # Under construction
   from python_cmc import cmc as asn1_cmc
   from asn1crypto import cms as asn1_cms



Using the management API
-----------------------------

| PKCS11 CA has a simple but elegant management API.
| Used to inspect or edit PKCS11 CA's database. Typically not needed in day to day operations.

| Under construction
| Look at the unittest `test_certificate.py <https://github.com/SUNET/pkcs11_ca/blob/main/tests/test_certificate.py>`_

.. code-block:: python

   # Under construction

Logging
-----------------------------

.. code-block:: bash

   # View the log for the PKCS11 CA
   docker logs pkcs11_ca_ca_1

   # View the logs for the PKCS11 CA postgres database
   docker logs pkcs11_ca_postgres_1


Start / Stop / Restart the system
-----------------------------

.. code-block:: bash

   # Stop the system/containers
   docker-compose down

   # Start the system/containers
   docker-compose up -d


Completely reset the system
-----------------------------

.. code-block:: bash

   # Stop the system/containers
   docker-compose down

   # Delete the HSM keys and database data # Note that this is for softhsm, if you use a real HSM then deleting the HSM keys are out of scope for this example
   rm -rf data/db_data/ data/hsm_tokens/
