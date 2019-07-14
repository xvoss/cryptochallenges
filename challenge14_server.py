"""
Set 2: Byte-at-a-time ECB decryption (Harder)

Sets up oracle server. Same as challenge 12, only that the oracle appends
random amount of bytes BEFORE client's text while still appending unknown
text. i.e. AES_ECB(random bytes || attacker text || unknown text)
"""
import os
import random
import base64
import challenge12_server


class EcbOracleHarder(challenge12_server.EcbOracle):
    """
    Oracle to encrypt under AES_ECB and send ciphertext back while prefixing
    constant, but randomly chosen length of bytes before client's text.
    """
    def __init__(self, host, port, key, unknown):
        amt = random.randint(10, 101)
        self.__prefix = os.urandom(amt)
        super().__init__(host, port, key, unknown)

    def __handle_client(self, conn):
        print("[*] Got client: waiting for text to encrypt")
        text = self.__prefix
        text += self.__get_response(conn)
        print("[*] Got plaintext, encrypting...")

        # AES(random bytes || user_text || unknown text)
        text += self.__unknown
        new_text = pkcs7_pad(text, 16)
        ctext = self.__cipher.encrypt(new_text)

        clen = struct.pack("I", int(len(ctext)))
        conn.send(clen)
        conn.send(ctext)
        print("[*] Sent encrypted data, closing")
        conn.close()


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

    oracle = EcbOracleHarder(HOST, PORT, secret_key, secret_text)
    oracle.start()


if __name__ == '__main__':
    main()
