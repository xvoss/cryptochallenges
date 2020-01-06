"""
Implement a SHA-1 keyed MAC
"""
import hash


def main():

    a = input()
    print(hash.sha1(a.encode('utf-8 ')))

    """ Attempt to break hash
    for x in range(0, 2 ** 16):
        h = sha1(x + msg)
        if s == h:
            print(x)
    """


if __name__ == '__main__':
    main()
