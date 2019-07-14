"""
Set 2: An ECB/CBC detection oracle

A crude implementation of an oracle server. Randomly encrypts data under AES
EBC or CBC and tells the client if their guess was correct.

The protocol is as follows:
the server asks for text to encrypt. The text is then randomly encrypted under
AES in ECB mode or in CBC mode. Then the ciphertext is sent with it's length
prefixed to it (4 bytes little endian || ciphertext). The server then asks
whether that ciphertext is in ECB or CBC mode. Based on that response, "yes" or
"no", the server indicates if that was correct or incorrect to the client.
"""

import os
import random
import socket
import struct
from challenge9 import pkcs7_pad
from Crypto.Cipher import AES
from challenge10 import AES_CBC


def encryption_oracle(text):
    # random key
    key = os.urandom(16)
    # random encryption
    flip = random.randint(0, 1)
    if flip:
        IV = os.urandom(16)
        cipher = AES_CBC(key, IV)
        cbc = True
    else:
        cipher = AES.new(key, AES.MODE_ECB)
        cbc = False

    prefix = random.randint(5, 10)
    postfix = random.randint(5, 10)
    random_text = os.urandom(prefix + postfix)
    new_text = random_text[:prefix] + text + random_text[postfix:]

    end = len(new_text) % 16
    pad = pkcs7_pad(new_text[-end:], 16)
    new_text = new_text[:-end] + pad

    return (cipher.encrypt(new_text), cbc)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # allows kernel to reuse socket even in TIME_WAIT state
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 3333))
    print("[*] Server initialized")
    s.listen()
    conn, addr = s.accept()

    print("[*] Client connected")
    with conn:
        try:
            while True:

                conn.send(b"Encrypt?>")
                msg_len = 1
                msg = b""
                while msg_len:
                    data = conn.recv(4096)
                    msg_len = len(data)
                    msg += data

                    if msg_len < 4096:
                        break

                ciphertext, is_cbc = encryption_oracle(msg)

                conn.send(b"Output>")

                # send length of ciphertext
                csize = struct.pack("I", int(len(ciphertext)))
                conn.send(csize)
                conn.send(ciphertext)

                conn.send(b"Is CBC? [yes/no]>")
                res = conn.recv(32)

                if is_cbc and b"yes" in res:
                    print("[*] Client is correct")
                    conn.send(b"correct")
                elif not is_cbc and b"no" in res:
                    conn.send(b"correct")
                    print("[*] Client is correct")
                else:
                    conn.send(b"incorrect")
                    print("[*] Client has made an error")
        except BrokenPipeError as e:
            print("[*] Client Disconnected")


if __name__ == '__main__':
    main()
