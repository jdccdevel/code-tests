#!/usr/bin/env python
# coding: utf-8

# BEGIN --- required only for testing, remove in real world code --- BEGIN
#import os
#import sys
#THISDIR = os.path.dirname(os.path.abspath(__file__))
#APPDIR = os.path.abspath(os.path.join(THISDIR, os.path.pardir, os.path.pardir))
#sys.path.insert(0, APPDIR)
# END --- required only for testing, remove in real world code --- END

import os
import httplib
import urllib
import urlparse
import BaseHTTPServer
import SimpleHTTPServer
import datetime
import json
import base64

import testaes

class TestAESHandler(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    """
    Test various modes of AES Encryption
    
    WARNING: THE ENCRYPTION KEY IS SENT IN THE CLEAR!
    DO NOT USE THIS FOR ANYTHING OTHER THAN TESTING!
         
    """

    def set_content_type_json(self):
        """
        Set content-type to "application/json"
        """

        self.send_header("Content-Type", "application/json")


    def set_no_cache(self):
        """
        Disable caching
        """

        self.send_header("Cache-Control", "no-cache")
        self.send_header("Pragma", "no-cache")


    def set_content_length(self, length):
        """
        Set content-length-header
        """

        self.send_header("Content-Length", str(length))

    def do_POST(self):
        """
        Handles HTTP-POST-Request
        This is a JSON Formatted request, testing the given decryption mode
        This decrypts a request, and prints it on the terminal. Then, it returns
        a encrypted response with the servers local time.
        """

        # Read JSON request
        content_length = int(self.headers.get("Content-Length", 0))
        request_json = self.rfile.read(content_length)

        req = json.loads(request_json)

        txt = testaes.decrypt_request(req)
        print "\nRecieved message: %s" % txt
        print "Recieved message (hex): %s" % ':'.join(hex(ord(x))[2:] for x in txt)

        response_txt = "Time is now: %s" % str(datetime.datetime.now())
        print "\nMessage to send: %s\n" % response_txt
        response_json = testaes.encrypt_response(response_txt, req['mode'])

        # Return result
        self.send_response(code = httplib.OK)
        self.set_content_type_json()
        self.set_no_cache()
        self.set_content_length(len(response_json))
        self.end_headers()
        self.wfile.write(response_json)
        return


# Threading HTTP-Server
http_server = BaseHTTPServer.HTTPServer(
    server_address = ('localhost', 8001),
    RequestHandlerClass = TestAESHandler
)

print "Starting HTTP server ..."
print "URL: http://localhost:8001"
try:
    http_server.serve_forever()
except KeyboardInterrupt:
    http_server.shutdown()
    http_server.socket.close()
print "Stopping HTTP server ..."
