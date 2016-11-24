# -*- coding: utf-8 -*-

import base64
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

import hashlib
import hmac
import qrcode
import random
import six
import struct
import time
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

__auth__ = 'CI_Knight <ci_knight@msn.cn>'


class OneTimePass(object):

    DIGEST_METHOD = hashlib.sha1
    # S = string.ascii_letters + string.digits
    S = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    def __init__(self, *args, **kwagrs):
        super(OneTimePass, self).__init__()
        secret = kwagrs.get('secret')
        if not secret:
            secret = self.generate_secret()

        secret = self._smart_str(secret).replace(b' ', b'')
        try:
            self.key = base64.b32decode(secret, casefold=True)
        except TypeError:
            raise TypeError('Incorrect secret')

    @staticmethod
    def _smart_str(s):
        if isinstance(s, str):
            return s.encode('utf-8')
        elif isinstance(s, (int, float)):
            return str(s)
        return s

    @staticmethod
    def _is_valid_token(token, token_length):
        if isinstance(token, bytes):
            token = six.b(str(token))
        return token.isdigit() and len(token) <= token_length

    @classmethod
    def generate_secret(cls, size=16):
        if size <= 0:
            return None

        return ''.join([random.choice(cls.S) for _ in range(0, size)])

    @classmethod
    def generate_qrcode(cls, secret, name, otp_type='totp', issuer=None,  b64=False):
        """ generate google Authenticator qrcode """
        base = 'otpauth://%s/' % otp_type
        uri = '%(base)s%(name)s?secret=%(secret)s' % {
            'base': base,
            'name': quote(name, safe='@'),
            'secret': secret
        }
        if issuer:
            uri += '&issuer=%s' % issuer

        buffer = StringIO()
        qr = qrcode.make(uri)
        if b64:
            qr.save(buffer)
            return base64.b64encode(buffer.getvalue())

        return qr

    def get_hotp(self, interval_no, token_length=6):
        """
        struct pack
        fmt: >Q, > big-endian, Q unsigned long long
        Docs: https://docs.python.org/3/library/struct.html#module-struct
        """
        msg = struct.pack('>Q', interval_no)
        hmac_digest = hmac.new(self.key, msg, self.DIGEST_METHOD).digest()
        ob = hmac_digest[19] if six.PY3 else ord(hmac_digest[19])
        o = ob & 15
        token_base = struct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff
        token = token_base % (10 ** token_length)
        return token

    def get_totp(self, interval_length=30, token_length=6, clock=None):
        if clock is None:
            clock = time.time()

        interval_no = int(clock) // interval_length
        return self.get_hotp(interval_no,
                token_length=token_length)

    def valid_hotp(self, token, last=1, trials=1000, token_length=6):
        token = self._smart_str(token)
        if not self._is_valid_token(token, token_length):
            return False

        for i in six.moves.xrange(last + 1, last + trials + 1):
            token_candidate = self.get_hotp(interval_no=i,
                    token_length=token_length)
            if token_candidate == int(token):
                return i

        return False

    def valid_totp(self, token, token_length=6, clock=None,
                interval_length=30, window=0):
        token = self._smart_str(token)
        if not self._is_valid_token(token, token_length):
            return False

        if clock is None:
            clock = time.time()

        for w in range(-window, window+1):
            token_candidate = self.get_totp(interval_length=interval_length,
                    token_length=token_length,
                    clock=int(clock)+(w*interval_length))
            if token_candidate == int(token):
                return True

        return False
