# RSA Vulnerability Analysis Toolkit

## Overview

This project analyzes RSA public keys extracted from TLS certificates and checks whether they are vulnerable to known cryptographic attacks.

The toolkit collects TLS certificates from servers, extracts RSA public keys, stores them in a MySQL database, and performs vulnerability analysis using:

* Batch GCD Attack
* Fermat's Factorization Attack
* Wiener's Attack

The project uses only publicly available certificate information and does not require access to private keys.

---

## Project Workflow

### Step 1: TLS Certificate Collection

The system connects to target servers using TLS and retrieves their X.509 certificates.

The certificate contains:

* Domain information
* Issuer information
* Validity period
* RSA public key

The RSA public key consists of:

* Modulus (n)
* Public Exponent (e)

These values are extracted and stored for analysis.

---

### Step 2: Database Storage

Extracted RSA keys are stored in a MySQL database.

Example table:

| Host        | Modulus | Exponent |
| ----------- | ------- | -------- |
| example.com | n       | e        |

---

### Step 3: Data Cleanup

Before performing attacks, duplicate moduli are removed.

```python
keys = keys.drop_duplicates(subset=['modulus'])
```

This prevents:

* Duplicate computations
* False positives
* Unnecessary processing

---

## Attack 1: Batch GCD Attack

### Objective

Detect RSA keys that share a common prime factor.

### Theory

Suppose:

n₁ = p × q₁

n₂ = p × q₂

Both moduli share the same prime p.

Computing:

gcd(n₁, n₂)

reveals:

p

Once p is known:

q₁ = n₁ / p

q₂ = n₂ / p

Both RSA keys can be factored.

### Implementation

The program compares every modulus against every other modulus.

```python
g = gcd(n1, n2)
```

If:

```python
g != 1
```

a shared-prime vulnerability is detected.

---

## Attack 2: Fermat's Factorization Attack

### Objective

Detect RSA keys generated using very close prime numbers.

### Theory

Fermat's factorization uses:

n = a² - b²

which can be rewritten as:

n = (a + b)(a - b)

If:

p ≈ q

then:

a = (p + q)/2

is extremely close to:

√n

The algorithm searches for:

a² - n = b²

Once found:

p = a - b

q = a + b

The modulus is successfully factored.

### Vulnerable Condition

The attack becomes efficient when:

|p - q|

is very small.

Example:

|p - q| = 334

Such keys are intentionally generated in this project for demonstration purposes.

---

## Attack 3: Wiener's Attack

### Objective

Detect RSA keys with unusually small private exponents.

### Theory

RSA security requires a sufficiently large private exponent d.

If d is too small:

d < n^(1/4) / 3

Wiener's continued fraction attack can recover d using only:

* Public modulus (n)
* Public exponent (e)

No factorization of n is required.

### Vulnerability

Keys generated with small private exponents are susceptible to complete private key recovery.

---

## Technologies Used

* Python
* MySQL
* OpenSSL
* Pandas
* Cryptography
* tqdm

---

## Database Setup

Create a database:

```sql
CREATE DATABASE mydb;
```

Create a table:

```sql
CREATE TABLE rsa_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host VARCHAR(255),
    modulus LONGTEXT,
    exponent VARCHAR(50)
);
```

---

## Running the Project

### Install Dependencies

```bash
pip install pandas mysql-connector-python tqdm cryptography
```

### Run Data Cleanup

```bash
python cleanup.py
```

### Run Batch GCD Attack

```bash
python batch_gcd.py
```

### Run Fermat Attack

```bash
python fermat_attack.py
```

### Run Wiener's Attack

```bash
python wiener_attack.py
```

---

## Educational Purpose

This project was developed for educational and research purposes to demonstrate common RSA implementation weaknesses and the importance of secure key generation practices.
