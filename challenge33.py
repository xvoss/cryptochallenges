import random
import hashlib

def mod_exp(x, e, n):
    ebin = bin(e)[2:]
    y = x
    for i in ebin[1:]:
        y = y * y % n
        if i == "1":
            y = y * x % n

    return y

def main():
    # initial test
    #p = 37
    #g = 5

    # test with large numbers as in the wild
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    a = random.randint(0, 10 ** 6)
    b = random.randint(0, 10 ** 6)

    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)

    s1 = mod_exp(B, a, p)
    s2 = mod_exp(A, b, p)
    assert(s1 == s2)


    key = hashlib.sha256(str(s1).encode('utf-8')).hexdigest()
    print("Created symmetric key:", key)


if __name__ == '__main__':
    main()
