import ssl
import socket
from math import gcd

from cryptography import x509
from cryptography.hazmat.backends import default_backend


# ======================================
# TLS SERVERS
# ======================================

HOST = "localhost"

# Correct ports
PORT1 = 4445
PORT2 = 4446


# ======================================
# EXTRACT RSA PUBLIC KEY
# ======================================

def get_rsa_key(port):

    ctx = ssl.create_default_context()

    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with ctx.wrap_socket(
        socket.socket(),
        server_hostname=HOST
    ) as s:

        s.connect((HOST, port))

        der = s.getpeercert(True)

    cert = x509.load_der_x509_certificate(
        der,
        default_backend()
    )

    pub = cert.public_key()

    numbers = pub.public_numbers()

    return numbers.n, numbers.e


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
# EXTRACT RSA KEYS
# ======================================

print("\n===== TLS ANALYZER =====\n")

n1, e1 = get_rsa_key(PORT1)

n2, e2 = get_rsa_key(PORT2)


# ======================================
# DISPLAY PUBLIC PARAMETERS
# ======================================

print("Server 1 Public Key:\n")

print("Exponent e1:")
print(e1)

print("\nModulus n1:")
print(n1)


print("\n=====================================\n")


print("Server 2 Public Key:\n")

print("Exponent e2:")
print(e2)

print("\nModulus n2:")
print(n2)


# ======================================
# BATCH GCD ATTACK
# ======================================

print("\n===== BATCH GCD ATTACK =====\n")

shared_prime = gcd(n1, n2)

print("gcd(n1, n2) =\n")
print(shared_prime)


# ======================================
# CHECK VULNERABILITY
# ======================================

if shared_prime > 1:

    print("\n[!] Shared Prime Vulnerability Detected")


    # Recover q values
    q1 = n1 // shared_prime

    q2 = n2 // shared_prime


    print("\n===== FACTORIZATION =====\n")


    print("Server 1 Factors:\n")

    print("p =")
    print(shared_prime)

    print("\nq =")
    print(q1)


    print("\n-------------------------------------\n")


    print("Server 2 Factors:\n")

    print("p =")
    print(shared_prime)

    print("\nq =")
    print(q2)


    # ======================================
    # COMPUTE phi(n)
    # ======================================

    phi1 = (shared_prime - 1) * (q1 - 1)

    phi2 = (shared_prime - 1) * (q2 - 1)


    print("\n===== phi(n) VALUES =====\n")

    print("phi1 =")
    print(phi1)

    print("\nphi2 =")
    print(phi2)


    # ======================================
    # RECOVER PRIVATE EXPONENTS
    # ======================================

    d1 = mod_inverse(e1, phi1)

    d2 = mod_inverse(e2, phi2)


    print("\n===== PRIVATE KEY RECOVERY =====\n")

    print("Recovered d1:\n")
    print(d1)

    print("\nRecovered d2:\n")
    print(d2)


else:

    print("\nNo shared prime vulnerability found")