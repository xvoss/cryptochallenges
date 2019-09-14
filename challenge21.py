"""
Set 3: Implement the MT19937 Mersenne Twister RNG

Implementation of the MT19937 random number generator for future attacks.
DO NOT USE for serious applications.

Used pseudocode from:
https://en.wikipedia.org/wiki/Mersenne_Twister

Helpful reference for implementation into python:
https://github.com/bmurray7/mersenne-twister-examples/blob/master/python-mersenne-twister.py
"""
def last32(num):
    return int(0xffffffff & num)


class MersenneTwister():
    def __init__(self, seed):
        self._lowermask = (1 << 31) - 1
        self._uppermask = last32(~self._lowermask)
        self._MT = [0] * 624
        self._index = 624
        self._MT[0] = seed
        for i in range(1, 624):
            self._MT[i] = last32(1812433253 *
                (self._MT[i-1] ^ (self._MT[i-1] >> (32 - 2))) + i)

    def rand(self):
        if self._index >= 624:
            if self._index > 624:
                raise RuntimeError("Error: Seed not initalized")

            self._twist()

        y = self._MT[self._index]
        y = y ^ ((y >> 11) & 0xffffffff)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (y >> 18)

        self._index += 1
        return last32(y)

    def _twist(self):
        for i in range(624):
            x = last32((self._MT[i] & self._uppermask) + (self._MT[(i+1) % 624] & self._lowermask))
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ 0x9908b0df

            self._MT[i] = self._MT[(i + 397) % 624] ^ xA

        self._index = 0

def main():
    gen = MersenneTwister(0xdeadbeef)
    for _ in range(20):
        print(gen.rand())

if __name__ == '__main__':
    main()
