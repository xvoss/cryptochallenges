"""
"""

import challenge12_server

class EcbOracleHarder(challenge12_server.EcbOracle):
    def __init__(self):
        amt = random.randint(10, 101)
        self.__prefix = os.urandom(amt)
        super().__init__(self)

    def __handle_client(self, conn):
        print("[*] Got client: waiting for text to encrypt")
        text += self.__prefix
        text += self.__get_response(conn)
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
