"""
Set 2: An ECB/CBC detection oracle

As a test, this script connects to the challenge11_server several times and
tries to detect if the server uses ECB or CBC block chain mode each time.
be sure to execute challenge11_server.py before running this script.

How to detect ECB mode in AES?
Well, every block encrypted under AES always maps to the same ciphertext
when it uses the same key. So, we send many blocks worth of the same bytes
and if there are that many repeating cipher blocks, we can assume it is using
ECB.
"""
from collections import Counter
import socket
import struct


def is_ecb(ctext, bsize=16, percent=0.80):
    """
    determine if ciphertext uses AES ECB mode. The original plaintext
    must have been repeating bytes (e.g. text is all A's: AAAAAAAAA...)

    :param ctext: text ciphered by AES and with repeating characters
    :param bsize: block size (usually 16 in AES)
    :param percent: ratio of common block / all blocks to be considered common
    """
    blocks = [ctext[i:i+bsize] for i in range(0, len(ctext), bsize)]

    repeat_count = Counter(blocks).most_common()[0][1]
    occur = repeat_count / len(blocks)

    if occur >= percent:
        return True
    else:
        return False


def recv_until(conn, text):
    buf = b""
    while True:
        data = conn.recv(1)
        buf += data

        if text in buf:
            break


def recv_all(conn):
        msg_len = 1
        msg = b""
        while msg_len:
            data = conn.recv(4096)
            msg_len = len(data)
            msg += data

            if msg_len < 4096:
                break

        return msg


def main():
    BLOCKSIZE = 16
    CHECK = 100
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        plaintext = b"A" * BLOCKSIZE * 40
        s.connect(("127.0.0.1", 3333))

        for i in range(CHECK):
            recv_until(s, b"Encrypt?>")
            s.send(plaintext)

            recv_until(s, b"Output>")
            size_int = s.recv(4)
            cipher_size = struct.unpack("I", size_int)[0]
            ciphertext = s.recv(cipher_size)
            recv_until(s, b"Is CBC? [yes/no]>")

            if is_ecb(ciphertext):
                print("[*] CASE {}: ECB mode detected".format(i))
                s.send(b"no")
            else:
                print("[*] CASE {}: CBC mode detected".format(i))
                s.send(b"yes")

            status = recv_all(s)
            assert status == b"correct"

    print("[*] Detected block chain mode with 100% accuracy")


if __name__ == '__main__':
    main()
