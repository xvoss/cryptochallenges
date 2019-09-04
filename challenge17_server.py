"""
Set 3: The CBC padding oracle

Implementation of the flawed encryption server. When requested at
'/encrypt' the server proved an encrypted phrase. The client may decrypt
this phrase, however if the padding is incorrect an "ERROR" message is
given.

Of course with this oracle, by telling the client if the padding is
correct or not, the client can decrypt the phrase we gave.
"""
from flask import Flask, json, request
from Crypto.Cipher import AES
import binascii
import challenge15
import challenge9
import os
import random
import base64

app = Flask(__name__)
tokens = []


@app.route("/encrypt")
def encrypt():
    """
    provide encrypted phrase to client via JSON
    """
    token = random.choice(tokens)
    IV = os.urandom(16)
    global KEY
    KEY = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    token = challenge9.pkcs7_pad(token, 16)

    ciphertext = cipher.encrypt(token)

    data, iv = base64.b64encode(ciphertext), base64.b64encode(IV)
    return json.dumps([{"token": data.decode()}, {"IV": iv.decode()}])


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    """
    Decrypt phrase client has and report if padding is correct or not
    """
    global KEY
    if request.method == "POST":
        data = base64.b64decode(request.form["token"].encode())
        IV = base64.b64decode(request.form["IV"].encode())
        cipher = AES.new(KEY, AES.MODE_CBC, IV)

        token = cipher.decrypt(data)
        try:
            challenge15.strip_pkcs7(token)
        except ValueError:
            return "ERROR"

        return "SUCCESS"


def main():
    with open("data/17.txt", "r") as fp:
        for line in fp:
            tokens.append(base64.b64decode(line.rstrip()))

    app.run(debug=True, port=5001)


if __name__ == '__main__':
    main()
