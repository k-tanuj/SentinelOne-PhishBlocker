# quick_test.py
from hdbcli import dbapi

try:
    print("🔍 Testing HANA connection with current password...")
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
    user = cursor.fetchone()[0]
    print(f"✅ SUCCESS! Connected as: {user}")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Connection failed: {e}")
    if "authentication failed" in str(e):
        print("🔧 Try updating password in db.py")
    elif "password" in str(e).lower():
        print("🔧 Password change may be required")