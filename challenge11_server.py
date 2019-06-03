"""
Set 2: An ECB/CBC detection oracle
"""
import os
import random
import socket
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
    return cipher.encrypt(new_text), cbc


def main():
    # open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #s.connect(("127.0.0.1", 3333))
    #s.send(...)

    s.bind(("127.0.0.1", 3333))

    s.listen()
    conn, addr = s.accept()

    with conn:
        while True:

            conn.send(b"Encrypt?> ")

            msg_len = 1
            msg = b""
            while msg_len:
                data = conn.recv(4096)
                msg_len = len(data)
                msg += data

                if msg_len < 4096:
                    break

            ciphertext, is_cbc = encryption_oracle(msg)
            conn.send("Output> ")
            conn.send(ciphertext)

            conn.send(b"\nIs CBC? [yes/no]> ")
            res = conn.recv(4096)

            if is_cbc and res == b"yes":
                conn.send(b"correct")
            else:
                conn.send(b"incorrect")



    # while true: ask for input
    # send output ask if correct
    # confirm


if __name__ == '__main__':
    main()
