"""
Set 2: Implement PKCS#7 padding

PKCS#7 is a padding scheme to ensure text is in increments of block size.
The scheme will add x amount of bytes of value x, where x is the amount of
space remaining in the incomplete block (blocksize - length of text)
"""


def pkcs7_pad(block, bsize):
    """
    Use PKCS#7 padding scheme to any text less than or more than blocksize
    if text is equal to blocksize an entire block is added with just padding

    :param block: text in bytes
    :param bsize: block size
    """
    if len(block) == bsize:
        return block + bytes([bsize for _ in range(bsize)])
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
            return block + bytes([bsize for _ in range(bsize)])


def main():
    input1 = b"YELLOW SUBMARINE"
    output1 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    test = pkcs7_pad(input1, 20)

    assert(test == output1)

if __name__ == '__main__':
    main()
