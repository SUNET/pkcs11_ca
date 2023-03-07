# For use inside the test container and demo purpose

from typing import Union
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import subprocess

class AcmeChallengeHTTPRequestHandler(BaseHTTPRequestHandler):
    ACME_CHALLENGE: str

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.ACME_CHALLENGE.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(self.ACME_CHALLENGE.encode("utf-8"))
        self.server.shutdown()
        self.server.server_close()

    # Disable logging in unittest
    #def log_request(self, code: Union[int, str] = "-", size: Union[int, str] = "-") -> None:
    #    pass


def run_http_server(key_authorization: str) -> None:
    server_address = ("", 80)
    AcmeChallengeHTTPRequestHandler.ACME_CHALLENGE = key_authorization

    httpd = HTTPServer(server_address, AcmeChallengeHTTPRequestHandler)
    httpd.timeout = 10
    httpd.handle_request()



t = threading.Thread(target=run_http_server, args=("MY CHALLENGE HERE",), daemon=True)
t.start()

time.sleep(2)

subprocess.call(["bash", "-c", "rm -rf accounts/ certs/; mkdir -p certs; bash dehydrated --register --accept-terms --algo secp384r1; openssl ec -in accounts/*/account_key.pem -pubout; bash dehydrated --algo secp384r1 --signcsr req.pem --out certs"])
# subprocess.call(["bash", "-c", "rm -rf accounts/ certs/; mkdir -p certs; bash dehydrated --register --accept-terms; openssl ec -in accounts/*/account_key.pem -pubout; bash dehydrated --signcsr req.pem --out certs"])
time.sleep(11)
