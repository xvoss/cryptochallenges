"""
Set 2: PkCS#7 padding validation

Method used for later code, specifically removing padding from decrypted text
"""


def strip_pkcs7(plaintext, blocksize=16):
    """
    Strip the end padding of a pkcs#7 padded block
    It is assumed that the plaintext should only consist of ascii characters
    :param plaintext: bytes() object with pkcs#7 padding
    """
    lastblock = plaintext[-16:]
    end = lastblock[-1]
    print(end)
    if end > 15:
        return plaintext

    text, padding = lastblock[:-end], lastblock[-end:]
    padsize = blocksize - len(text)

    if len(padding) != padsize:
        raise ValueError("Incorrect amount of bytes in padding")

    for b in padding:
        if b != padsize:
            raise ValueError("Padding byte is incorrect value")

    return text
