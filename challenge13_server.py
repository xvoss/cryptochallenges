"""
Set 2: ECB cut-and-paste

Simple socket server. Takes a username and creates a profile, then encrypts
(AES ECB) the profile sending it to the client. An account is created when
client sends back profile. Metacharacters are filtered out, so users cannot
send 'role=admin' to create admin account. The underlying crypto must be
attacked.

NOTE: it is assumed that the attacker knows the length of uid value.
"""
import socket
import re
import os
import sys
import string
import challenge12_server
import challenge9   # pkcs#7 padding
from Crypto.Cipher import AES


class OracleCutPaste():
    """
    Server to create profiles when sent a username. A profile is:
    user=givenUserName&uid=10&role=user. The profile is encrypted, then
    send to client. The client sends back the encrypted profile, which is then
    processed and creates an account, verifying if it is a 'user' or 'admin'
    account.
    """
    def __init__(self, host, port, key):
        self.__host = host
        self.__port = port
        self.__cipher = AES.new(key, AES.MODE_ECB)

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

    def __kv_parse(self, string):
        """
        Convert profile into dictionary
        """
        obj = {}
        for kv in string.split("&"):
            k, v = kv.split("=")

            obj[k] = v

        return obj

    def __profile_for(self, user):
        """
        Create profile with user, uid, and role fields

        :param user: email address of user
        """
        profile = []
        # email (stripped of metacharacters)
        profile.append("user=" + re.sub('&=', '', user))
        uid = "uid=10"
        profile.append(uid)
        role = "role=user"
        profile.append(role)

        return "&".join(profile)

    def __profile_encrypt(self, username):
        """
        :return: encrypted profile to send out to client
        """
        prof_str = self.__profile_for(username.decode())
        profile = challenge9.pkcs7_pad(prof_str.encode("utf-8"), 16)

        ctext = self.__cipher.encrypt(profile)
        return ctext

    def __profile_decrypt(self, ciphertext):
        """
        :return: data from clients encrypted profile, for account creation
        """
        profile = self.__cipher.decrypt(ciphertext)
        byte = profile[-1]

        # convert bytes to string to create key value pairs
        parsed_prof = profile[:-byte].decode()
        json = self.__kv_parse(parsed_prof)

        return json

    def __handle_client(self, conn):
        """
        Recieve username, create profile, encrypt and send it out, recieve
        profile, decrypt it and make account

        :param conn: socket, talk to client
        """
        print("[*] Accepting Profiles")
        username = self.__get_response(conn)
        en_profile = self.__profile_encrypt(username)
        print("[*] user account created")
        conn.send(en_profile)

        ctext = self.__get_response(conn)
        json = self.__profile_decrypt(ctext)
        if json["role"] == "admin":
            print("[*] admin acccount created")
            conn.send(b"success")
        else:
            conn.send(b"failure")

        print("[*] Exiting")
        conn.close()
        sys.exit()

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
    key = os.urandom(16)
    oracle = OracleCutPaste("127.0.0.1", 5555, key)
    oracle.start()


if __name__ == '__main__':
    main()
