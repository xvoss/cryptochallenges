def strip_pkcs7(plaintext, blocksize=16):
    """
    Strip the end padding of a pkcs#7 padded block
    It is assumed that the plaintext should only consist of ascii charactesr
    :param plaintext: bytes() object with pkcs#7 padding
    """
    end = plaintext[-1]
    text, padding = plaintext[:-end], plaintext[-end:]
    padsize = blocksize - len(text)

    if len(padding) != padsize:
        raise ValueError("Incorrect amount of bytes in padding")

    for b in padding:
        if b != padsize:
            raise ValueError("Padding byte is incorrect value")

    return text
