from http.server import HTTPServer
from socketserver import ThreadingMixIn
import threading

import HTTP_Handler

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

with ThreadingSimpleServer(('', 8000), HTTP_Handler.handler) as server:
#with HTTPServer(('', 8000), HTTP_Handler.handler) as server:
    server.serve_forever()
