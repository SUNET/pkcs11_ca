from cryptography.hazmat.primitives.serialization import Encoding
import psycopg2
from fastapi.responses import JSONResponse
import fastapi

import time
import json

import crl
import csr
import cert
import serial
import ca
import db

def crl_file():
    try:
        curr_crl = crl.load_crl().public_bytes(Encoding.PEM)
        return fastapi.Response(status_code=200,
                                content=curr_crl,
                                media_type="application/x-pkcs7-crl")
    except:
        return fastapi.Response(status_code=422,
                                content=csr_sign_fail,
                                media_type="text/plain")

def CRL():
    try:
        curr_crl = crl.load_crl().public_bytes(Encoding.PEM)
        return {"crl": curr_crl}
    except:
        return JSONResponse(status_code=422,
                            content={"detail": "Failed retrieving CRL"})

    
def issued_serials():
    try:
        serials = db.issued_serials()
        return {"serials": serials}
    except:
        return JSONResponse(status_code=422,
                            content={"detail": "Failed retrieving serials"})

def issued_certs():
    try:
        certs = db.issued_certs()
        return {"certs": certs}
    except:
        raise
        return JSONResponse(status_code=422,
                            content={"detail": "Failed retrieving certs"})

