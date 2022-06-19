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

csr_invalid_input = "Invalid CSR in PEM format"
csr_sign_fail = "Failed signing the CSR"
csr_already_exists = "CSR already exists"

revoke_invalid_input = "Invalid serial or cert in PEM format"
revoke_fail = "Failed revoking cert"

def is_issued_serial(c):
    try:
        if c.serial is not None:
            curr_serial = serial.data_to_serial(r.serial)
        else:
            curr_cert = cert.data_to_cert(r.pem)
            curr_serial = curr_cert.serial_number
            
    except:
        return JSONResponse(status_code=400,
                                content={"detail": "Invalid serial or cert in PEM format"})
    try:
        return {"is_issued_serial": db.cert_exists(curr_serial)}
    except:
        return JSONResponse(status_code=422,
                                content={"detail": "Problem checking serial"})

def is_issued_cert(c):
    try:
        if c.serial is not None:
            curr_serial = serial.data_to_serial(r.serial)
        else:
            curr_cert = cert.data_to_cert(r.pem)
            curr_serial = curr_cert.serial_number
            
    except:
        return JSONResponse(status_code=400,
                                content={"detail": "Invalid serial or cert in PEM format"})
    try:
        return {"is_issued_cert": db.cert_exists(curr_serial)}
    except:
        return JSONResponse(status_code=422,
                                content={"detail": "Problem checking cert"})

def sign_csr(c):
    try:
        new_csr = csr.data_to_csr(c.pem)
    except:
        # FIXME LOG ALL
        return JSONResponse(status_code=400,
                            content={"detail": csr_invalid_input})
    
    try:
        new_cert = csr.sign_csr(new_csr)
        return JSONResponse(status_code=201,
                            content={"certificate":
                                     new_cert.public_bytes(Encoding.PEM)
                                     .decode('utf-8')})

    except psycopg2.errors.UniqueViolation:
        return JSONResponse(status_code=422,
                            content={"detail": csr_already_exists})
    except:
        return JSONResponse(status_code=422,
                            content={"detail": csr_sign_fail})

# Special for compatibility
async def sign_csr_file(request):
    data = await request.body()    
    try:
        new_csr = csr.data_to_csr(data)
    except:
        # FIXME LOG ALL
        return fastapi.Response(status_code=400,
                                content=csr_invalid_input,
                                media_type="text/plain")
    try:
        new_cert = csr.sign_csr(new_csr)
        new_cert_pem = new_cert.public_bytes(Encoding.PEM)
        return fastapi.Response(status_code=200,
                                content=new_cert_pem,
                                media_type="application/x-pem-file")

    except psycopg2.errors.UniqueViolation:
        return fastapi.Response(status_code=422,
                                content=csr_already_exists,
                                media_type="text/plain")
    except:
        raise
        # FIXME LOG ALL
        return fastapi.Response(status_code=422,
                                content=csr_sign_fail,
                               media_type="text/plain")
    
def revoke(c):
    try:
        if c.serial is not None:
            curr_serial = serial.data_to_serial(c.serial)
        else:
            curr_cert = cert.data_to_cert(c.pem)
            curr_serial = curr_cert.serial_number
    except:
        return JSONResponse(status_code=400,
                                content={"detail": revoke_invalid_input})
    try:
        curr_crl = crl.revoke_cert(curr_serial)
        return {"crl": curr_crl.public_bytes(Encoding.PEM).decode('utf-8')}
    except:
        return JSONResponse(status_code=422,
                                content={"detail": revoke_fail})

def is_revoked(c):
    try:
        if c.serial is not None:
            curr_serial = serial.data_to_serial(c.serial)
        else:
            curr_cert = cert.data_to_cert(c.pem)
            curr_serial = curr_cert.serial_number
    except:
        return JSONResponse(status_code=400,
                                content={"detail": revoke_invalid_input})
    try:
        return {"is_revoked": crl.is_revoked(curr_serial)}    
    except:
        return JSONResponse(status_code=422,
                                content={"detail": "Problem checking cert"})
