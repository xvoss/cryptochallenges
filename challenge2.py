"""
set1: Fixed XOR
xor two hexstrings together
"""
from binascii import unhexlify
from binascii import hexlify


def xor(buf1, buf2):
    if (len(buf1) != len(buf2)):
        raise ValueError("xor: buffers are of different lengths")
    else:
        res = []
        for c1, c2 in zip(buf1, buf2):
            res.append(c1 ^ c2)

        return bytes(res)


def main():
    # given test values
    input1 = b"1c0111001f010100061a024b53535009181c"
    input2 = b"686974207468652062756c6c277320657965"
    output = b"746865206b696420646f6e277420706c6179"

    result = xor(unhexlify(input1), unhexlify(input2))
    print(hexlify(result))

    assert(output == hexlify(result))

if __name__ == '__main__':
    main()
