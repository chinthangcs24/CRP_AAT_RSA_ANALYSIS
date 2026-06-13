import ssl
import socket
from math import isqrt

from cryptography import x509
from cryptography.hazmat.backends import default_backend


# ======================================
# TLS SERVER DETAILS
# ======================================

HOST = "localhost"
PORT = 4443


# ======================================
# CONNECT TO TLS SERVER
# ======================================

ctx = ssl.create_default_context()

ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


with ctx.wrap_socket(
    socket.socket(),
    server_hostname=HOST
) as s:

    s.connect((HOST, PORT))

    der = s.getpeercert(True)


# ======================================
# LOAD CERTIFICATE
# ======================================

cert = x509.load_der_x509_certificate(
    der,
    default_backend()
)

pub = cert.public_key()

numbers = pub.public_numbers()


# ======================================
# DISPLAY CERTIFICATE DETAILS
# ======================================

print("\n===== TLS ANALYZER =====\n")

print("Key Size:", pub.key_size)

print("Exponent (e):", numbers.e)

print("\nModulus n:\n")
print(numbers.n)

print("\nSignature Algorithm:",
      cert.signature_hash_algorithm.name)


# ======================================
# BASIC SECURITY CHECKS
# ======================================

print("\n===== SECURITY CHECKS =====\n")

if pub.key_size < 2048:
    print("[WARNING] Weak RSA key detected")

if cert.issuer == cert.subject:
    print("[WARNING] Self-signed certificate")


# ======================================
# FERMAT FACTORIZATION FUNCTION
# ======================================

def fermat_factor(n):

    a = isqrt(n)

    if a * a < n:
        a += 1

    b2 = a*a - n

    while isqrt(b2)**2 != b2:

        a += 1
        b2 = a*a - n

    b = isqrt(b2)

    p = a - b
    q = a + b

    return p, q


# ======================================
# MODULAR INVERSE FUNCTION
# ======================================

def mod_inverse(e, phi):

    def egcd(a, b):

        if a == 0:
            return (b, 0, 1)

        g, y, x = egcd(b % a, a)

        return (g, x - (b // a) * y, y)

    g, x, y = egcd(e, phi)

    if g != 1:
        return None

    return x % phi


# ======================================
# FERMAT ATTACK
# ======================================

print("\n===== FERMAT ATTACK =====\n")

try:

    # Recover primes
    p, q = fermat_factor(numbers.n)

    print("Recovered primes:\n")

    print("p =")
    print(p)

    print("\nq =")
    print(q)

    # Verify factorization
    if p * q == numbers.n:

        print("\n[!] Fermat Vulnerability Detected")

        # Compute phi(n)
        phi = (p - 1) * (q - 1)

        print("\nphi(n) =")
        print(phi)

        # Recover private exponent d
        d = mod_inverse(numbers.e, phi)

        print("\nRecovered private exponent d:\n")
        print(d)

    else:

        print("\nFactorization failed")


except Exception as ex:

    print("\nFermat attack failed:")
    print(ex)