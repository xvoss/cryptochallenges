"""
libraries for programs that create or talk to an oracle server

NOTE: only challenges after 14 use these libraries.
"""
class SimpleOracle():
    def __init__(self, host, port, cipher):
        self._host = host
        self._port = port
        self._cipher = cipher

    def _get_response(self, connection):
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

    def _handle_client(self, conn):
        text = self._get_response(conn)
        new_text = pkcs7_pad(text, 16)
        ctext = self._cipher.encrypt(new_text)

        clen = struct.pack("I", int(len(ctext)))
        conn.send(clen)
        conn.send(ctext)
        print("[*] Sent encrypted data, closing")
        conn.close()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # allows kernel to reuse socket even in TIME_WAIT state
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self._host, self._port))
            s.listen()
            print("[*] Server now listening on {}:{}"
                  .format(self._host, self._port))
            while True:
                conn, addr = s.accept()
                self._handle_client(conn)


class OracleClient():
    """
    Communication between the decryption algorithm and the oracle server

    :param host: IP of encryption server
    :param port: port of encryption server
    """
    def __init__(self, host, port):
        self._host = host
        self._port = port

    def send(self, msg):
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((self._host, self._port))
        self._s.send(msg)
        header = self._s.recv(4)
        csize = struct.unpack("I", header)[0]
        ciphertext = self._s.recv(csize)
        self._s.close()

        return ciphertext
