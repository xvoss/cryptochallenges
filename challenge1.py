"""
set1: Convert hex to base64
decode a base64 encode hex string
"""
import base64
import binascii

string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706" \
         b"f69736f6e6f7573206d757368726f6f6d"
output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG11pc29ub3VzIG11c2hyb29t"

res = base64.b64encode(binascii.unhexlify(string))

assert(res == output)
