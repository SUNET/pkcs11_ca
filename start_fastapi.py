from typing import Union
import fastapi
from pydantic import BaseModel
import sys

import config
import post_path
import get_path
import db


class Csr(BaseModel):
    pem: str

#class Author(BaseModel):
#    ip: str,
#    date: str

class Cert(BaseModel):
    pem: Union[str, None] = None
    serial: Union[str, None] = None

# First check the DB, will exit if fail
db.start()

app = fastapi.FastAPI()


## GET HTTP ##
@app.get("/" + config.ca_info_common_name + ".crl")
def crl_file():
    return get_path.crl_file()

@app.get("/crl")
def crl():
    return get_path.CRL()
        
@app.get("/issued_serials")
def issued_serials():
    return get_path.issued_serials()

@app.get("/issued_certs")
def issued_certs():
    return get_path.issued_certs()

## POST HTTP ##
@app.post("/is_issued_serial")
def is_issued_serial(c: Cert):
    return post_path.is_issued_serial(c)

@app.post("/is_issued_cert")
def is_issued_cert(c: Cert):
    return post_path.is_issued_cert(c)

@app.post("/sign_csr")
def sign_csr(c: Csr):
    return post_path.sign_csr(c)

# Special for compatibility
@app.post("/sign_csr_file")
async def sign_csr_file(request: fastapi.Request):
    return await post_path.sign_csr_file(request)

@app.post("/revoke")
def revoke(c: Cert):
    return post_path.revoke(c)

@app.post("/is_revoked")
def revoke(c: Cert):
    return post_path.is_revoked(c)

