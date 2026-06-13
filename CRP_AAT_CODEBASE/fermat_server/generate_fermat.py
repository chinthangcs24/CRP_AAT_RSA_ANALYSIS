from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from sympy import nextprime

bits = 512

p = getPrime(bits)

# intentionally close primes
q = nextprime(p + 1000)

n = p * q

e = 65537

phi = (p - 1) * (q - 1)

d = inverse(e, phi)

key = RSA.construct((n, e, d, p, q))

with open("fermat.pem", "wb") as f:
    f.write(key.export_key())

print("Fermat vulnerable RSA key generated")