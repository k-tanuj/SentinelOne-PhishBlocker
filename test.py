from hdbcli import dbapi

conn = dbapi.connect(
    address="754db17e-af16-4009-9baa-1bca994a48de.hana.trial-us10.hanacloud.ondemand.com",
    port=443,
    user="DBADMIN",
    password="Tcs@18420",
    encrypt=True,
    sslValidateCertificate=False
)
cursor = conn.cursor()
cursor.execute("SELECT CURRENT_USER FROM DUMMY")
print(cursor.fetchone())
