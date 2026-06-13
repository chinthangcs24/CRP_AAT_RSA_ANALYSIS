from Crypto.Util.number import *
from Crypto.PublicKey import RSA

bits = 512

p = getPrime(bits)
q = getPrime(bits)

n = p * q

e = 65537

phi = (p - 1) * (q - 1)

d = inverse(e, phi)

key = RSA.construct((n, e, d, p, q))

with open("wiener.pem", "wb") as f:
    f.write(key.export_key())

print("Wiener-style TLS key generated")