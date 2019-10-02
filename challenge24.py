"""
Set 3: Create the MT19937 stream cipher and break it

TODO: Finish challenge
Because I am limited on time, I've decided to move to the next set.
"""
import challenge21

class MT19937_Stream_Cipher():
    def __init__(self, key)
        if (key < 0 or key > 0xff):
            raise ValueError("Key must be a 16 bit value")
        self._key = key


    def encrypt(self, msg):
        rng = challenge21.Mersenne_Twister(self._key)

        keysteam = rng.rand()



    def decrypt(self, msg):
        rng = challenge21.Mersenne_Twister(self._key)

        keysteam = rng.rand()
