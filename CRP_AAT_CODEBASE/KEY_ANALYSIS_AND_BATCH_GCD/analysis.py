import mysql.connector
import pandas as pd
import matplotlib.pyplot as plt
# CONNECT TO MYSQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="chinthan123",
    database="mydb"
)

# SQL QUERY
query = "SELECT * FROM rsa_keys"

# LOAD INTO DATAFRAME
keys = pd.read_sql(query, conn)

# SHOW TOTAL ROWS
print("TOTAL ROWS:", len(keys))

# KEY SIZE DISTRIBUTION
print("\nKEY SIZE DISTRIBUTION:")
print(keys['key_size'].value_counts())

# EXPONENT DISTRIBUTION
print("\nEXPONENT DISTRIBUTION:")
print(keys['exponent'].value_counts())

# SIGNATURE ALGORITHMS
print("\nSIGNATURE ALGORITHMS:")
print(keys['signature_algorithm'].value_counts())

keys['key_size'].value_counts().plot(kind='bar')

#keysize graph
plt.xlabel("RSA Key Size")
plt.ylabel("Count")
plt.title("RSA Key Size Distribution")
plt.show()
#signature algo
keys['signature_algorithm'].value_counts().head(10).plot(kind='bar')
plt.xlabel("Signature Algorithm")
plt.ylabel("Count")
plt.title("Signature Algorithm Distribution")
plt.show()
#exponent graph
keys['exponent'].value_counts().plot(kind='bar')
plt.xlabel("Exponent")
plt.ylabel("Count")
plt.title("RSA Exponent Distribution")
plt.show()