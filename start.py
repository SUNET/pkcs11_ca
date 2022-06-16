from http.server import HTTPServer
from socketserver import ThreadingMixIn
import threading
import os

import HTTP_Handler

import ca
import crl

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass



with ThreadingSimpleServer(('', 8000), HTTP_Handler.handler) as server:
#with HTTPServer(('', 8000), HTTP_Handler.handler) as server:

    # Try to load our CA
    # Dont store key in memory
    # FIXME load keys and cert from hardware
    if not os.path.isfile("ca.key"):
        rootca, rootca_key = ca.new_ca()
        ca.save_ca(rootca, rootca_key)
    else:
        rootca, rootca_key = ca.load_ca()

    # Create background thread that updates the crl every 24 hours minus 2 minutes
    crl_daemon = threading.Thread(target=crl.background_worker,
    args=((60*60*24)-(60*2),), daemon=True, name='crl_background_worker')
    crl_daemon.start()
    
    # Start the HTTP API
    server.serve_forever()
