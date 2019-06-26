"""
Set 2: Byte-at-a-time ECB decryption (simple)

"""
import os
import socket
import base64
import struct
from challenge9 import pkcs7_pad
from Crypto.Cipher import AES


class EcbOracle():
    def __init__(self, host, port, key, unknown):
        self.__host = host
        self.__port = port
        self.__cipher = AES.new(key, AES.MODE_ECB)
        self.__unknown = unknown

    def __get_response(self, connection):
        """
        continually wait for a response from a client
        :param connection: socket object of client
        """
        buf = b""
        #connection.settimeout(2)
        try:
            while True:
                data = connection.recv(4096)
                buf += data
                if len(data) < 4096:
                    break
        except:
            pass

        return buf

    def __handle_client(self, conn):
        print("[*] Got client: waiting for text to encrypt")
        text = self.__get_response(conn)
        print("[*] Got plaintext, encrypting...")

        # AES(user_text || unknown text)
        text += self.__unknown
        new_text = pkcs7_pad(text, 16)
        ctext = self.__cipher.encrypt(new_text)

        clen = struct.pack("I", int(len(ctext)))
        conn.send(clen)
        conn.send(ctext)
        print("[*] Sent encrypted data, closing")
        conn.close()


    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # allows kernel to reuse socket even in TIME_WAIT state
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.__host, self.__port))
            s.listen()
            print("[*] Server now listening on {}:{}"
                  .format(self.__host, self.__port))
            while True:
                conn, addr = s.accept()
                self.__handle_client(conn)


def main():
    HOST = "127.0.01"
    PORT = 4444

    given_input = \
        b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
        b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
        b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
        b"YnkK"

    secret_text = base64.b64decode(given_input)
    secret_key = os.urandom(16)

    oracle = EcbOracle(HOST, PORT, secret_key, secret_text)
    oracle.start()


if __name__ == '__main__':
    main()
