# -*- coding: utf-8 -*-

import unittest

from onetimepass import OneTimePass


class Test(unittest.TestCase):

    def test_genrate_secret(self):
        self.assertFalse(OneTimePass.generate_secret(size=-1))
        secret = OneTimePass.generate_secret(size=1000)
        self.assertTrue(secret)
        self.assertTrue(len(secret) == 1000)
        self.assertTrue(OneTimePass._generate_qrcode(secret))
        self.assertTrue(OneTimePass._generate_qrcode(secret, b64=True))

    def test_hotp(self):
        otp = OneTimePass()
        token = otp.get_hotp(1000)
        self.assertTrue(token)
        self.assertTrue(otp.valid_hotp(token, last=1000))


if __name__ == '__main__':
    unittest.main()
