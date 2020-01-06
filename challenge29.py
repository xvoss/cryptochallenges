"""
Set 4: Break a SHA-1 keyed MAC using length extension

Valid signatures of the form sha1(key || message) can be created given the
message is known and the hash is known. The key is not required. The exploit
goes as follows:

Find the padding of the message. There will be several since the key length is
unknown. Then compute sha1(key || message), break the signature into its five
states and input them into the algorithm to have sha1`(). Again compute the
padding but for the entire message: pad(key || message || pad1 || exploit). Let
this padding be pad2. Next, compute sha1`(exploit || pad2), ensure no additional
padding is added. Now, with that hash computed, it will be the signature of the
exploit: key || message || pad1 || exploit || pad2, thus the server will accept
it as a valid message.
"""
import struct
import hash
import random
import sys



def mdpadding(data):
    """Return finalized digest variables for the data processed so far."""
    # Pre-processing:

    if len(data) <= 64:
        message = data
    else:
        message = data[64:]

    message_byte_length = len(data)
    #message = self._unprocessed
    #message_byte_length = self._message_byte_length + len(message)

    # append the bit '1' to the message
    padding = b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    padding += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message_bit_length = message_byte_length * 8
    padding += struct.pack(b'>Q', message_bit_length)

    # Process the final chunk
    # At this point, the length of the message is either 64 or 128 bytes.
    return padding
    """
    h = _process_chunk(message[:64], *self._h)
    if len(message) == 64:
        return h
    return _process_chunk(message[64:], *h)
    """


def sha1_states(signature):
    states = []
    for i in range(0, 40, 8):
        states.append(int(signature[i:i+8], 16))

    return tuple(states)

def sha1_mac(message):
    keys = []
    with open("/usr/share/dict/words", "r") as fd:
        for line in fd: keys.append(line.rstrip())

    key = random.choice(keys).encode()
    signature = hash.sha1(key + message)

    return signature, key


def main():
    """ Test the algorithm """

    # create original signature
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    sign_orig, key = sha1_mac(msg)

    # create a forged signature ending with exploit
    exploit = b";admin=true"

    forgery = []
    # we don't know the key length, so the padding size must be bruteforced
    for key_len in range(1, 0x20):
        dummy_key = b"A" * key_len
        pad1 = mdpadding(dummy_key + msg)
        pad2 = mdpadding(dummy_key + msg + pad1 + exploit)
        assert(len(exploit + pad2) == 64)

        # send message to server with exploit
        message = msg + pad1 + exploit


        # now find the hash of our exploit to ensure it's valid
        new_h = sha1_states(sign_orig)
        state = hash._process_chunk(exploit + pad2, *new_h)
        signature = '%08x%08x%08x%08x%08x' % state
        forgery.append((signature, message))

    # send forgeries to 'server'. Check signature is correct
    for signature, message in forgery:
        validation = hash.sha1(key + message)

        if validation == signature:
            print("Valid Sha1 Mac: ", message)
            print("Signature", signature)
            sys.exit()

    print("No successful forgeries created.")



if __name__ == '__main__':
    main()
