from http.server import BaseHTTPRequestHandler
import json

from cryptography.hazmat.primitives import serialization

import ca
import csr
import certdb
import crl
import serial
import cert

class handler(BaseHTTPRequestHandler):

    MAX_BYTES_POST = 10000
    server_version = "SUNET CA"
    sys_version = "0.98"

    def send_data(self, status, message, content_type, as_json):

        if as_json:
            ct = "application/json"
            m = bytes(json.dumps(message, sort_keys=True, indent=4), "utf-8")
        else:
            ct = "text/plain"
            if isinstance(message, str):
                m = bytes(message, "utf-8")
            elif isinstance(message, bool):
                m = bytes(str(message).lower(), "utf-8")
            elif isinstance(message, bytes):
                m = message
            else:
                raise("FIXME must be a string, bool or bytes")

        self.send_response(status)
        self.send_header('Content-type', ct)
        self.end_headers()
        self.wfile.write(m)
            
    ## POST METHODS ##
    def post_sign_csr(self, data, as_json):
        try:
            new_csr = csr.data_to_csr(data)
        except:
            self.send_data(401, "Not a valid CSR in PEM format", "text/plain", as_json)
            return

        try:
            cert = csr.sign_csr(new_csr)
        except:
            self.send_data(401, "Problem signing the CSR", "text/plain", as_json)
            return

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.send_data(200, cert_pem, "application/x-pem-file", as_json)

    def post_revoke(self, data, as_json):
        try:
            curr_serial = serial.data_to_serial(data)
            curr_crl = crl.revoke_cert(curr_serial)
            curr_crl = curr_crl.public_bytes(serialization.Encoding.PEM)
            self.send_data(200, curr_crl.public_bytes(serialization.Encoding.PEM), "application/x-pkcs7-crl", as_json)
            return

        except:
            try:
                curr_cert = cert.data_to_cert(data)
                curr_serial = curr_cert.serial_number
                curr_crl = crl.revoke_cert(curr_serial)
                curr_crl = curr_crl.public_bytes(serialization.Encoding.PEM)
                self.send_data(200, curr_crl, "application/x-pkcs7-crl", as_json)
                return
            except:
                self.send_data(401, "Problem revoking the cert, valid data is serial or the cert in PEM format", "text/plain", as_json)
                
    def post_is_revoked(self, data, as_json):
        try:
            curr_serial = serial.data_to_serial(data)
            is_rev = crl.is_revoked(curr_serial)
            self.send_data(200, is_rev, "text/plain", as_json)
            return

        except:
            try:
                curr_cert = cert.data_to_cert(data)
                curr_serial = curr_cert.serial_number
                is_rev = crl.is_revoked(curr_serial)
                self.send_data(200, is_rev, "text/plain", as_json)
                return
            except:
                self.send_data(401, "Problem checking cert, valid data is serial or the cert in PEM format", "text/plain", as_json)
    ## END POST METHODS ##

    ## GET METHODS ##
    def get_issued_serials(self, as_json):
        serials = serial.get_serials_pem()
        self.send_data(200, serials, "text/plain", as_json)
        
    def get_issued_certs(self, as_json):
        certs = certdb.get_issued_certs_pem()
        self.send_data(200, certs, "application/x-pem-file", as_json)

    def get_crl(self, as_json):
        curr_crl = crl.load_crl().public_bytes(serialization.Encoding.PEM)
        self.send_data(200, curr_crl, "application/x-pkcs7-crl", as_json)
    ## END GET METHODS ##
        
    # FIXME REMOVE ALL BUT GET AND POST        
    def do_GET(self):
        # FIXME check API KEY in header

        if self.path.endswith("_json"):
            as_json = True
        else:
            as_json = False

        if self.path == "/issued_serials" or self.path == "/issued_serials_json":
            self.get_issued_serials(as_json)
            
        elif self.path == "/issued_certs" or self.path == "/issued_certs_json":
            self.get_issued_certs(as_json)

        elif self.path == "/crl" or self.path == "/crl_json" or self.path == "/crl.crl":
            self.get_crl(as_json)

        else:
            self.send_data(404, "Page not found", "text/plain", as_json)

    def do_POST(self):
        # FIXME check API KEY in header
        
        if "Content-Length" in self.headers:
             content_length = int(self.headers['Content-Length'])
        elif "content-length" in self.headers:
            content_length = int(self.headers['content-length'])
        else:
            self.send_data_json(401, "No Content-Length in headers")
            return

        # Probably needed
        if content_length > self.MAX_BYTES_POST:
            self.send_data_json(401, "To big message according to content_length header")
            return

        # FIXME use nginx as proxy and set connection timeouts to 5s
        # Read data as bytes
        post_data = self.rfile.read(content_length)

        if self.path.endswith("_json"):
            as_json = True
        else:
            as_json = False
        
        if self.path == "/sign_csr" or self.path == "/sign_csr_json":
            self.post_sign_csr(post_data, as_json)

        elif self.path == "/revoke" or self.path == "/revoke_json":
            self.post_revoke(post_data, as_json)

        elif self.path == "/is_revoked" or self.path == "/is_revoked_json":
            self.post_is_revoked(post_data, as_json)

        else:
            self.send_data(404, "Page not found", "text/plain", as_json)

