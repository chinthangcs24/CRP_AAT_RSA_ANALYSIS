from Crypto.Util.number import *
from Crypto.PublicKey import RSA

bits = 512

shared_p = getPrime(bits)

q1 = getPrime(bits)
q2 = getPrime(bits)

e = 65537

# KEY 1
n1 = shared_p * q1
phi1 = (shared_p - 1) * (q1 - 1)
d1 = inverse(e, phi1)

key1 = RSA.construct((n1, e, d1, shared_p, q1))

with open("gcd1.pem", "wb") as f:
    f.write(key1.export_key())

# KEY 2
n2 = shared_p * q2
phi2 = (shared_p - 1) * (q2 - 1)
d2 = inverse(e, phi2)

key2 = RSA.construct((n2, e, d2, shared_p, q2))

with open("gcd2.pem", "wb") as f:
    f.write(key2.export_key())

print("Shared-prime vulnerable keys created")