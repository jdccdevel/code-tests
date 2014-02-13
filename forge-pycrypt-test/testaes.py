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

from Crypto.Cipher import AES

def aes_mode_add_desc(m_dict, m_name, m_id):
    m_dict[m_name] = m_id;
    m_dict[m_id] = m_name;

aes_mode_conv = {}
aes_mode_add_desc(aes_mode_conv, "ECB", AES.MODE_ECB)
aes_mode_add_desc(aes_mode_conv, "CBC", AES.MODE_CBC)
aes_mode_add_desc(aes_mode_conv, "CFB", AES.MODE_CFB)
aes_mode_add_desc(aes_mode_conv, "PGP", AES.MODE_PGP) # Should not be used, include for completeness
aes_mode_add_desc(aes_mode_conv, "OFB", AES.MODE_OFB)
aes_mode_add_desc(aes_mode_conv, "CTR", AES.MODE_CTR)
aes_mode_add_desc(aes_mode_conv, "OPENPGP", AES.MODE_OPENPGP)


def pad_string(unpad_str, block_size = 16):
    pcount = block_size - (len(unpad_str) % block_size)
    pchar = chr(pcount)
    return unpad_str + (pcount * pchar)

def unpad_string(pad_str, block_size = 16):
    p_chr = pad_str[-1]
    if (ord(p_chr) > block_size):
        return pad_str

    p_count = ord(p_chr)
    if (len(pad_str) < p_count):
        #Invalid padding, return the string unmodified
        return pad_str
    if (p_count > 9):
        # Just in case the last character isn't padding
        pad = pad_str[-1*p_count]
        for p in pad:
            if (ord(p) != p_count):
                return pad_str

    return pad_str[0:-1*p_count]


def decrypt_request(req):
    """
    Decrypt the incoming data, and print it to the terminal
    """

    
    print "Parsed request:"
    print "Key    : %s" %req['b64_key']     # base64 encoded key
    print "IV     : %s" %req['b64_iv']      # base64 encoded iv
    print "Mode   : %s" %req['mode']
    print "b64_enc: %s" %req['b64_encval']  # Base64 encoded encrypted ciphertext

    key = base64.b64decode(req['b64_key'])
    iv = base64.b64decode(req['b64_iv'])
    enc = base64.b64decode(req['b64_encval'])
    
    if (aes_mode_conv[req['mode']] == AES.MODE_CFB):
        print "Setting Encrypt segment_size=128"
        cipher = AES.new(key, aes_mode_conv[req['mode']], iv, segment_size = 128)
    else:
        cipher = AES.new(key, aes_mode_conv[req['mode']], iv)

    txt = unpad_string(cipher.decrypt(enc))
    
    return txt;

def encrypt_response(txt, mode_txt):
    """
    Encrypt the outgoing text, and return the json encoded response
    """

    key = os.urandom(32)
    iv = os.urandom(16)

    if (aes_mode_conv[mode_txt] == AES.MODE_CFB):
        print "Setting Decrypt segment_size=128"
        cipher = AES.new(key, aes_mode_conv[mode_txt], iv, segment_size = 128)
    else:
        cipher = AES.new(key, aes_mode_conv[mode_txt], iv)

    enc_txt = cipher.encrypt(pad_string(txt))
    
    resp = {}
    resp['b64_key'] = base64.b64encode(key)
    resp['b64_iv'] = base64.b64encode(iv)
    resp['mode'] = mode_txt
    resp['b64_encval'] = base64.b64encode(enc_txt)

    print "Sending response:"
    print "Key    : %s" %resp['b64_key']     # base64 encoded key
    print "IV     : %s" %resp['b64_iv']      # base64 encoded iv
    print "Mode   : %s" %resp['mode']
    print "b64_enc: %s" %resp['b64_encval']  # Base64 encoded encrypted ciphertext

    return json.dumps(resp)
    
