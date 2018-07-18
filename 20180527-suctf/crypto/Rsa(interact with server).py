from Crypto.Random import random
import binascii
import hashlib

def invmod(a, n):
    t = 0
    new_t = 1
    r = n
    new_r = a
    while new_r != 0:
        q = r // new_r
        (t, new_t) = (new_t, t - q * new_t)
        (r, new_r) = (new_r, r - q * new_r)
    if r > 1:
        raise Exception('unexpected')
    if t < 0:
        t += n
    return t

smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19]

def primefactor(p):
    for x in smallPrimes:
        if p % x == 0:
            return True
    return False

def isprime(p, n):
    for i in range(n):
        a = random.randint(1, p)
        if pow(a, p - 1, p) != 1:
            return False
    return True

def getprime(bit):
    while True:
        p = random.randint(2**(bit - 1), 2**bit - 1)
        if not primefactor(p) and isprime(p, 5):
            return p

def genKey(keybits):
    e = 3
    bit = (keybits + 1) // 2 + 1

    p = 7
    while (p - 1) % e == 0:
        p = getprime(bit)

    q = p
    while q == p or (q - 1) % e == 0:
        q = getprime(bit)

    n = p * q
    et = (p - 1) * (q - 1)
    d = invmod(e, et)
    pub = (e, n)
    priv = (d, n)

    return (pub, priv)



pub, priv = genKey(2048)
(e,n) = pub
(d,n) = priv
de_hash = set()



def b2n(s):
    return int.from_bytes(s, byteorder='big')

def n2b(k):
    return k.to_bytes((k.bit_length() + 7) // 8, byteorder='big')

def decrypt(cipher):
    md5 = hashlib.md5()
    md5.update(cipher)
    digest = md5.digest()
    if digest in de_hash:
        raise ValueError('Already decrypted')
    de_hash.add(digest)
    return n2b(pow(b2n(cipher), d, n))

if __name__ == '__main__':
    plain = 
    cipher = n2b(pow(b2n(plain), e, n))
    r = random.randint(2, n - 1)
    c = b2n(cipher)
    c2 = (pow(r, e, n) * c) % n
    print (e)
    print (d)
    print (c2,r,n)
    

