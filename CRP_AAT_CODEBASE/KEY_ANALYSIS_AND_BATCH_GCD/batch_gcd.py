import mysql.connector
from math import gcd
from tqdm import tqdm

# CONNECT TO MYSQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="chinthan123",
    database="mydb"
)

cursor = conn.cursor()

# GET HOST + MODULUS
cursor.execute(
    "SELECT host, modulus FROM rsa_keys"
)

rows = cursor.fetchall()

moduli = []

# LOAD MODULI
for host, modulus in rows:

    try:
        moduli.append((host, int(modulus)))
    except:
        pass

# REMOVE DUPLICATE MODULI
seen = set()
unique_moduli = []

for host, n in moduli:

    if n not in seen:
        seen.add(n)
        unique_moduli.append((host, n))

moduli = unique_moduli

print("TOTAL UNIQUE MODULI:", len(moduli))

found = False

# BATCH GCD
for i in tqdm(range(len(moduli))):

    host1, n1 = moduli[i]

    for j in range(i + 1, len(moduli)):

        host2, n2 = moduli[j]

        # skip identical modulus
        if n1 == n2:
            continue

        g = gcd(n1, n2)

        # REAL shared-prime vulnerability
        if g != 1:

            print("\n======================")
            print("REAL SHARED PRIME FOUND")
            print("======================")

            print("HOST 1:", host1)
            print("HOST 2:", host2)

            print("\nSHARED PRIME:")
            print(g)

            print("\nBIT LENGTH:", g.bit_length())

            found = True

if not found:
    print("\nNo shared primes detected.")