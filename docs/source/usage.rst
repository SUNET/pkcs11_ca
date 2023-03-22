Usage
=====

Installation
------------

To use PKCS11 CA, first install it using

.. code-block:: console

   # Clone down the repository
   git clone https://github.com/SUNET/pkcs11_ca.git
   
   # Install openssl, docker and docker-compose. For example: sudo apt-get install docker.io openssl && pip3 install docker-compose
   
.. code-block:: console
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

.. code-block:: console
   # Create and start the containers
   $ dev-run.sh
   

Creating recipes
----------------

# To retrieve a list of random ingredients,
# you can use the ``lumache.get_random_ingredients()`` function:
