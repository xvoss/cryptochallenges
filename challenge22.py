"""
Set 3: Crack an MT19937 seed

There is not efficient way to recover the seed from only on 32bit value. So,
assuming the victim uses a unix time stamp as the seed (which isn't
unreasonable), we will bruteforce the times starting from the time of request.
"""
from datetime import datetime
import time
import random
import challenge21

class UnixTimeCrackRNG():
    """
    Bruteforce possible seeds from FIRST initial value of RNG. The victim is
    assumed to be using unix time for their seeds values.
    """
    def __init__(self, start_time, value):
        self._start_time = start_time
        self._end_time = int(time.time())
        self._value = value

    def bruteforce(self):
        for s in range(self._start_time, self._end_time+1):
            print("SEED: 0x{:02X}".format(s), end="\r")
            generator = challenge21.MersenneTwister(s)
            first = generator.rand()

            if first == self._value:
                return s

        return -1


def main():
    delay1 = random.randint(50, 1500)
    delay2 = random.randint(50, 1500)

    print("[*] Generating Seed...")
    time.sleep(delay1)
    t = int(time.time())
    generator = challenge21.MersenneTwister(t)

    time.sleep(delay2)
    num = generator.rand()

    print("[*] Got seed, bruteforcing...")
    c = UnixTimeCrackRNG(t, num)
    seed = c.bruteforce()

    print("[*] Seed", seed)

if __name__ == '__main__':
    main()
