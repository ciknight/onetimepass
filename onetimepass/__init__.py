# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import six
import struct
import time

__auth__ = 'CI_Knight <ci_knight@msn.cn>'


def _smart_str(s):
    if isinstance(s, str):
        return s.encode('utf-8')
    elif isinstance(s, int):
        return str(s)
    return s


def get_hotp(secret, intervals_no, token_length=6):
    secret = _smart_str(secret)
    secret = secret.replace(b' ', b'')
    try:
        key = base64.b32decode(secret, casefold=True)
    except TypeError:
        raise TypeError('Incorrect secret')

    """
    struct pack
    fmt: >Q, > big-endian, Q unsigned long long
    Docs: https://docs.python.org/3/library/struct.html#module-struct
    """
    msg = struct.pack('>Q', intervals_no)
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
    ob = hmac_digest[19] if six.PY3 else ord(hmac_digest[19])
    o = ob & 15
    token_base = struct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff
    token = token_base % (10 ** token_length)
    return token

def get_totp(secret, interval_length, clock=None):
    if clock is None:
        clock = int(time.time())

    intervals_no = clock // interval_length
    return get_hotp(secret, intervals_no)
