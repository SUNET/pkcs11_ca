Features
========

| `PKCS11 (HSM) key storage <https://pkcs11-ca.readthedocs.io/en/latest/features.html#pkcs11-key-storage>`_
| `ACME <https://pkcs11-ca.readthedocs.io/en/latest/features.html#id1>`_
| `CMC <https://pkcs11-ca.readthedocs.io/en/latest/features.html#id2>`_
| `Automatic OCSP, CRL, and CA Issuers <https://pkcs11-ca.readthedocs.io/en/latest/usage.html#retrieving-the-issuer-for a-certificate>`_
| `Management API <https://pkcs11-ca.readthedocs.io/en/latest/features.html#elegant-management-api>`_


PKCS11 key storage
------------------------

| The PKCS11 CA stores its keys in a `PKCS11 <https://en.wikipedia.org/wiki/PKCS_11>`_ device. Default is to use the free software HSM emulator called SOFTHSM.
| Switching to a physical HSM is as simple as changing your PKCS11 library path in the `config file <https://pkcs11-ca.readthedocs.io/en/latest/configuration.html>`_.
| It is also possible to use a PKCS11 configured yubikey.

| The PKCS11 CA uses `python-x509-pkcs11 <https://github.com/SUNET/python_x509_pkcs11>`_ as its PKCS11 library.
| It is written by the same authors as the PKCS11 CA. The library in turn uses `python-pkcs11 <https://python-pkcs11.readthedocs.io/en/latest/>`_.


ACME
----------------

| PKCS11 CA implements the server side of ACME.

.. note::
   The Automatic Certificate Management Environment (ACME) protocol is a communications protocol for automating interactions between certificate authorities and their users' servers.
   Allowing the automated deployment of public key infrastructure at very low cost.
   It was designed by the Internet Security Research Group (ISRG) for their Let's Encrypt service.
   The protocol, based on passing JSON-formatted messages over HTTPS has been published as an Internet Standard in RFC 8555 by its own chartered IETF working group

| Here is the `ACME guide <https://pkcs11-ca.readthedocs.io/en/latest/usage.html#using-an-acme-client-with-the-pkcs11-ca>`_ to use the PKCS11 CA with your ACME client.


CMC
------------

| PKCS11 CA is capable of responding to CMC requests.
| Issue certs from a CMC request which contains a CSR.
| Revoke issued certificates contained in a CMC revoke request.

.. note::
   The Certificate Management over CMS (CMC) is an Internet Standard published by the IETF, defining transport mechanisms for the Cryptographic Message Syntax (CMS).
   It is defined in RFC 5272, its transport mechanisms in RFC 5273.
   Similarly to the Certificate Management Protocol (CMP), it can be used for obtaining X.509 digital certificates in a public key infrastructure (PKI).

| Here is the `CMC guide <https://pkcs11-ca.readthedocs.io/en/latest/usage.html>`_ to use the PKCS11 CA with your CMC client.

Elegant management API
-----------------------

| The PKCS11 CA's management API is designed to not be needed in day to day operations. Typically only used in special cases to inspect or edit the PKCS11 database.
| It is a simple but elegant JWT scheme.

.. note::
   This is under active development and might be functionally changed in the future.

| Here is the `API management guide <https://pkcs11-ca.readthedocs.io/en/latest/usage.html>`_ for the PKCS11 CA.
