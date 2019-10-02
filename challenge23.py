"""
Set 3: Clone an MT19937 RNG from its output

The crux of this challenge was reversing the Shift-Xor operations at every
'twist' of the MT algorithm. Mathematically, this inloves linear recurrence
and matrices. However all that is neccessary is to take the last shift bits,
and XOR them with the next shift bits. Then, that result and XOR with the
next shift bits again and so on.

The following code was re-implemented for reversing the Shift-Xor operations
https://gist.github.com/PhoeniXkrypT/22b978dee79f3092d63f

NOTE: In the future I would like to know the mathematics (linear recurrence)
that the MT uses.

"""
import challenge21

def untemper_right(word, shift, magic=0xffffffff):
    value = 0
    i = 0

    while i * shift < 32:
        key_mask = ((0xffffffff << (32 - shift)) & 0xffffffff) >> (i * shift)
        key = word & key_mask
        word ^= (key >> shift) & magic
        value |= key

        i += 1

    return value

def untemper_left(word, shift, magic=0xffffffff):
    value = 0
    i = 0

    while i * shift < 32:
        key_mask = ((0xffffffff >> (32 - shift)) << (i * shift)) & 0xffffffff
        key = word & key_mask
        word ^= (key << shift) & magic
        value |= key

        i += 1

    return value

def untwist(word):
    x = untemper_right(word, 18)
    x = untemper_left(x, 15, 0xefc60000)
    x = untemper_left(x, 7, 0x9d2c5680)
    x = untemper_right(x, 11)
    return x


def cloneMT(outputs):
    """
    :param: outputs must be list of 624 consecutive MT outputs
    """
    clone = challenge21.MersenneTwister(0x0)
    state = [untwist(x) for x in outputs]
    clone.MT = state
    return clone


def main():
    rng = challenge21.MersenneTwister(0x1337)

    original = []
    print("[*] Generating Random Numbers")
    for i in range(624):
        num = rng.rand()
        original.append(num)
        print("{}: 0x{:08X}".format(i, num))

    clone_rng = cloneMT(original)

    new_outputs = []
    for _ in range(200):
        num1 = rng.rand()
        num2 = clone_rng.rand()
        new_outputs.append((num1, num2))

    print("\nOriginal RNG\t\t\tClone RNG")
    for num in new_outputs:
        print("0x{:08X}\t\t\t0x{:08X}".format(num[0], num[1]))



if __name__ == '__main__':
    main()
