"""
Set 2: ECB cut-and-paste

The idea behind this attack is to rearrange the cipherblocks around to create
uninteded text. Specifically adding 'admin...' after '...role=' to gain
priviledge execution.

This script provides a corrupt username to achieve this and rearranges the
cipherblocks. To do this we need to encrypt block: admin || pkcs#7 padding.
Additionally, padding is addded to username to ensure 'role=' is at the end of
the block. Finally, admin || pkcs#7 is removed from the middle and placed at
the end of the ciphertext, to be sent to the server.

ATTACK STRING: user= ... | admin ... | ... padding ... &uid=10&role= |
take the ciphertext from | admin ... | add to end of attack string
"""
import socket


class AdminRoleAttack():
    """
    Manipulate profile user=...&uid=...&role=... so that role equals 'admin'.
    The role must be encrypted under AES ECB mode.

    :param username: bytes(), email address for admin role
    :param oracle: class, get profile via .create_user() and send profile via
    .send_profile()
    :param blocksize: int, blocksize of server's encryption
    """
    def __init__(self, username, oracle, blocksize=16):
        self.__oracle = oracle
        self.__username = username
        self.__blocksize = blocksize

    def __attack_string(self):
        """
        Assemble string to obtain encrypted admin string. Also, adding padding
        so that 'role=' is at end of block
        """
        uid_field = b"&uid=10&role="
        assert(len(self.__username) + 5 == self.__blocksize)

        # admin block
        admin_field = b"admin"
        byte = self.__blocksize - len(admin_field)
        admin_field += bytes([byte for _ in range(byte)])

        # padding before uid field and after username
        assert(len(uid_field) < self.__blocksize)
        space = self.__blocksize - len(uid_field)
        # 41 value is arbitrary
        padding = bytes([41 for _ in range(space)])

        return self.__username + admin_field + padding

    def start(self):
        """
        Assemble encrypted profile, to create admin account and verify with
        server.
        """
        attack = self.__attack_string()

        # sends a username thats turns into a encrypted profile
        ctext = self.__oracle.create_user(attack)

        n1 = self.__blocksize  # admin field
        n2 = n1 * 2  # uid field and role field
        # admin profile encrypted
        en_admin = ctext[n1:n1+self.__blocksize]
        fake = ctext[:n1] + ctext[n2:n2+self.__blocksize] + en_admin

        if self.__oracle.send_profile(fake):
            print("[*] Success: admin {} created".format(self.__username))
        else:
            print("[*] Failure: unable to create username")


class OracleClient():
    """
    Communicate with encryption server
    """
    def __init__(self, host, port):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.connect((host, port))

    def __get_response(self, connection):
        """
        continually wait for a response from a client
        :param connection: socket object of client
        """
        buf = b""
        # connection.settimeout(2)
        try:
            while True:
                data = connection.recv(4096)
                buf += data
                if len(data) < 4096:
                    break
        except:
            pass

        return buf

    def create_user(self, username):
        """
        Sends name to server so an 'account' is created

        :param username: bytes() email address
        :return: encrypted profile, AES_ECB(user=username|uid=...||role=...)
        """
        self.__s.send(username)
        en_profile = self.__get_response(self.__s)
        return en_profile

    def send_profile(self, prof):
        self.__s.send(prof)
        status = self.__s.recv(7)

        if status == b"success":
            return True
        else:
            return False


def main():
    username = b"de@test.com"
    oracle = OracleClient("127.0.0.1", 5555)
    cut_and_paste = AdminRoleAttack(username, oracle, 16)
    cut_and_paste.start()


if __name__ == '__main__':
    main()
