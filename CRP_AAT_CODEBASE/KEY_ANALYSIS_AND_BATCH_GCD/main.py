import pandas as pd
import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="chinthan123",
    database="mydb"
)

query = "SELECT * FROM rsa_keys"

keys = pd.read_sql(query, conn)

print("Before cleanup:", len(keys))

keys = keys.drop_duplicates(subset=['modulus'])

print("After cleanup:", len(keys))