"""
Set 2: Implement PKCS#7 padding

Test pkcs#7 method
"""

def pkcs7_pad(block, bsize):
    if len(block) == bsize:
        return block
    elif len(block) < bsize:
        psize = bsize - len(block)
        pad = bytes([psize for _ in range(psize)])
        return block + pad
    elif len(block) > bsize:
        end = len(block) % bsize
        if end > 0:
            pad = pkcs7_pad(block[-end:], bsize)
            return block[:-end] + pad
        else:
            return block


def main():
    input1 = b"YELLOW SUBMARINE"
    output1 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    test = pkcs7_pad(input1, 20)

    assert(test == output1)

if __name__ == '__main__':
    main()
