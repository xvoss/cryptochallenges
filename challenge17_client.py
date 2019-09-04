"""
Set 3: The CBC padding oracle

Implement attack to decrypt unknown ciphertexts in AES_CBC mode. This is
possible on servers that report an error when a ciphertext sent has an invalid
PKCS#7 padding setup.

The attacker may send dummytexts, changing the last byte(s) of a block, so when
the server checks it's padding it will say if it is valid or invalid. When the
server reports invalid, the attacker can deduce what byte it decrypted to, and
thus repeat for the entire message and decrypt the entire thing.

"""
import requests
import base64


class CBC_Oracle_Attack():
    """
    Proof of concept decryption for servers that use AES_CBC and an oracle
    that reports if a ciphertext's padding is true or false.

    :param ciphertext: secret that server has given, it can be sent to server
    :param IV: initalization vector, also given by server
    :param blocksize: block size of server encryption algorithm
    :param lowerbound: smallest byte value to use for bruteforce
    :param upperbound: largest byte value for bruteforce
    """
    def __init__(self, ciphertext, IV, blocksize, client, lowerbound,
                 upperbound):
        self._ciphertext = ciphertext
        self._corrupt = CorruptText(ciphertext, IV, blocksize)
        self._IV = IV
        self._blocksize = blocksize
        self._oracle = client.send
        self._guess = [byte for byte in range(lowerbound, upperbound+1)]
        self.plaintext = bytearray()

    def start(self):
        """
        Begin decryption. Keep track of previous cipher blocks and ciphertext
        that is sent to server
        """
        cblocks = [list(self._ciphertext[i: i + self._blocksize])
                   for i in range(0, len(self._ciphertext), 16)]

        # cipherblocks needed to be manipulated to change plaintext
        if len(cblocks) == 1:
            dummies = [list(self._IV)]
        else:
            cblocks.pop()
            cblocks.insert(0, list(self._IV))
            dummies = cblocks

        for block in dummies[::-1]:
            plainblock = self._break_block(block)
            self._corrupt.reset()
            self._corrupt.pop()
            self.plaintext = bytearray(plainblock) + self.plaintext

    def _break_block(self, prev):
        """
        Prepare dummy block so that is has padding when decrypted. Calculate
        the plaintext byte based on bruteforce() attempts.

        :param prev: ciphertext block BEFORE the block trying to be decrypted.
                     this block affects the current ciphertext block
        """

        dummytext = prev.copy()
        plaintext = []
        decrypted = []

        self._guess.remove(prev[-1])
        byte = self._bruteforce(dummytext, 1)
        if byte == -1:
            raise RuntimeError("Oracle returned incorrect"
                               "padding for all bruteforce bytes")

        # Pn = C`n XOR Cn XOR pad
        debyte = byte ^ 0x1
        plainbyte = byte ^ 0x1 ^ prev[-1]

        decrypted.insert(0, debyte)
        plaintext.insert(0, plainbyte)

        dummytext = prev.copy()
        self._guess.append(prev[-1])

        # where b is for the pad number e.g. 0x3 0x3 0x3
        for b in range(2, self._blocksize + 1):
            # create proper padding for bruteforcing the last byte
            for i in range(1, b):
                dummytext[-i] = decrypted[-i] ^ b

            byte = self._bruteforce(dummytext, b)
            if byte == -1:
                raise RuntimeError("Oracle returned incorrect"
                                   "padding for all bruteforce bytes")

            debyte = byte ^ b
            plainbyte = byte ^ b ^ prev[-b]
            decrypted.insert(0, debyte)
            plaintext.insert(0, plainbyte)
            dummytext = prev.copy()

        return plaintext

    def _bruteforce(self, dummytext, index):
        """
        Replace the byte before padding with every possibility, and ask the
        server if it has correct padding until one does.

        :param index: location of byte (relative to end of list)
        """
        for b in self._guess:
            dummytext[-index] = b
            for i in dummytext:
                print("0x{:02} ".format(i), end='')
            print(end="       \r")
            self._corrupt.update(bytes(dummytext))
            if self._oracle(self._corrupt.text):
                return b
        return -1


class CorruptText():
    """
    Maintain corrupted ciphertexts and keep only necessary blocks
    """
    def __init__(self, ciphertext, IV, blocksize):
        self.text = IV + ciphertext
        self._bs = blocksize
        self.orig = self.text

    def pop(self):
        """
        Remove last block of ciphertext for text block to be decrypted
        """
        self.text = self.text[:-self._bs]
        self.orig = self.text

    def update(self, dummytext):
        """
        Replace second last block with dummytext
        """
        mod = list(self.text)
        for i in range(1, len(dummytext)+1):
            mod[-i - 16] = dummytext[-i]
        self.text = bytes(mod)

    def reset(self):
        """
        Return text to original state from last dummytext writes
        """
        self.text = self.orig


class OracleClient():
    """
    Send any message to the encryption server. The server has '/encrypt' and
    '/decrypt' urls.
    """
    def __init__(self, url):
        self._url = url
        r = requests.get(url + "/encrypt")
        self.tok, self.IV = r.json()[0]["token"], r.json()[1]["IV"]

    def send(self, text):
        """
        :param text: send bytes to server for encryption. First 16 bytes must
        be the IV. Boolean is returned based on if the padding is correct.
        """
        self.IV = base64.b64encode(text[:16])
        token = base64.b64encode(text[16:])
        payload = {"token": token, "IV": self.IV}
        r = requests.post(self._url + "/decrypt", data=payload)
        if r.text == "SUCCESS":
            return True
        else:
            return False

    def refresh(self):
        """
        Obtain a token
        """
        r = requests.get(url + "/encrypt")
        self.tok, self.IV = r.json()[0]["token"], r.json()[1]["IV"]


def main():
    URL = "http://127.0.0.1:5001"
    client = OracleClient(URL)
    ciphertext, IV = base64.b64decode(client.tok), base64.b64decode(client.IV)

    decryption_engine = CBC_Oracle_Attack(ciphertext, IV, 16, client, 0, 255)
    print("[->] Sending Server Dummy Text:")
    decryption_engine.start()

    print("\n\n[*] Ciphertext Detected:")
    print(decryption_engine.plaintext.decode('utf-8'), end='\n')


if __name__ == '__main__':
    main()
