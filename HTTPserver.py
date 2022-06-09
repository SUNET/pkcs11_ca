from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import serialization

import ca
import csr

class handler(BaseHTTPRequestHandler):

    server_version = "SUNET CA"
    sys_version = "0.98"
    
    def send_data(self, status, message):
            self.send_response(status)
            self.send_header('Content-type','application/json')        
            self.end_headers()
            self.wfile.write(bytes(message, "utf-8"))
            
    def post_csr_get_cert(self, data):
        try:
            new_csr = csr.data_to_csr(data)
        except:
            self.send_data(401, "Not a valid CSR in PEM format\n")
            return

        try:
            cert = csr.sign_csr(new_csr)
        except:
            self.send_data(401, "Problem signing the CSR\n")
            return

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.send_data(200, cert_pem.decode('utf-8'))
            
    def post_csr(self, data):
        try:
            csr.data_to_csr(data)
        except:
            self.send_data(401, "Not a valid CSR in PEM format\n")
            return

        self.send_data(200, "CSR ACCEPTED OK\n")

    # FIXME REMOVE ALL BUT GET AND POST
        
    def do_GET(self):
        # FIXME check API KEY in header

        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.end_headers()

        message = "Hello, World!"
        self.wfile.write(bytes(message, "utf-8"))

    def do_POST(self):

        # FIXME check API KEY in header
        
        if "Content-Length" in self.headers:
            content_length = int(self.headers['Content-Length'])
        elif "content-length" in self.headers:
            content_length = int(self.headers['content-length'])
        else:
            self.send_data(401, "No Content-Length in headers\n")
            return

        if content_length > 10000:
            self.send_data(401, "To big message according to content_length header\n")
            return
        
        post_data = self.rfile.read(content_length)
        
        if self.path == "/post_csr":
            self.post_csr(post_data)
            return

        elif self.path == "/post_csr_get_cert":
            self.post_csr_get_cert(post_data)
            return
        
        self.send_data(401, "Page not found\n")
            
        
with HTTPServer(('', 8000), handler) as server:
    server.serve_forever()
