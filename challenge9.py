"""
Set 2: Implement PKCS#7 padding

Test pkcs#7 method
"""

def pkcs7_pad(block, bsize):
    psize = bsize - len(block)
    if psize == 0:
        return block
    pad = bytes([psize for _ in range(psize)])
    return block + pad

def main():
    input1 = b"YELLOW SUBMARINE"
    output1 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    test = pkcs7_pad(input1, 20)

    assert(test == output1)

if __name__ == '__main__':
    main()
