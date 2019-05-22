"""
set1: Implement repeating-key XOR
"""
import binascii


def xor(ptext, key):
    ctext = []
    for i, b in enumerate(ptext):
        c = b ^ key[i % len(key)]
        ctext.append(c)

    return bytes(ctext)

def main():
    # given test input
    input1 = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"

    output1 = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    text1 = binascii.hexlify(xor(input1, key))

    assert(text1 == output1)



if __name__ == '__main__':
    main()
