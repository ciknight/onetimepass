# -*- coding: utf-8 -*-

from flask import Flask

from onetimepass import OneTimePass

app = Flask(__name__)

img = "<center><img src='data:image/png;base64,%s' /></center>"

@app.route('/qrcode')
def qrcode():
    secret = OneTimePass.generate_secret()
    b64_img = OneTimePass.generate_qrcode(secret, 'ci_knight@msn.cn', b64=True)
    return img % b64_img

if __name__ == '__main__':
    app.run()
