import ssl
import socket
from math import isqrt
from fractions import Fraction

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ======================================
# TLS SERVER DETAILS
# ======================================

HOST = "localhost"
PORT = 4444

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

print("Exponent (e):")
print(numbers.e)

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
# CONTINUED FRACTION
# ======================================

def continued_fraction(n, d):

    cf = []

    while d:

        q = n // d

        cf.append(q)

        n, d = d, n % d

    return cf

# ======================================
# CONVERGENTS
# ======================================

def convergents(cf):

    conv = []

    for i in range(len(cf)):

        frac = Fraction(0)

        for x in reversed(cf[:i + 1]):

            if frac.numerator == 0:

                frac = Fraction(x, 1)

            else:

                frac = x + Fraction(1, frac)

        conv.append(
            (frac.numerator, frac.denominator)
        )

    return conv

# ======================================
# WIENER ATTACK
# ======================================

def wiener_attack(e, n):

    cf = continued_fraction(e, n)

    convs = convergents(cf)

    for k, d in convs:

        if k == 0:
            continue

        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        b = n - phi + 1

        discr = b * b - 4 * n

        if discr >= 0:

            sq = isqrt(discr)

            if sq * sq == discr:

                return d

    return None

# ======================================
# RUN WIENER ATTACK
# ======================================

print("\n===== WIENER ATTACK =====\n")

d = wiener_attack(
    numbers.e,
    numbers.n
)

if d:

    print("[!] Wiener Vulnerability Detected")

    print("\nRecovered private exponent d:\n")

    print(d)

    print("\n=====================================")
    print("Private key successfully recovered")
    print("using Wiener's Attack")
    print("=====================================")

else:

    print("No Wiener vulnerability detected")