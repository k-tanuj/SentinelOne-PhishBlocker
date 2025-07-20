# add_missing_columns.py
from hdbcli import dbapi

def get_connection():
    return dbapi.connect(
        address="754db17e-af16-4009-9baa-1bca994a48de.hana.trial-us10.hanacloud.ondemand.com",
        port=443,
        user="DBADMIN",
        password="Tcs@18420",
        encrypt=True,
        sslValidateCertificate=False
    )

def add_missing_columns():
    """Add all missing columns to existing table"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        print("🔍 Checking current table structure...")
        
        # Check existing columns
        cursor.execute("""
            SELECT COLUMN_NAME 
            FROM TABLE_COLUMNS 
            WHERE SCHEMA_NAME = 'SENTINELONE' 
            AND TABLE_NAME = 'PHISHING_LOGS'
        """)
        
        existing_columns = [row[0] for row in cursor.fetchall()]
        print(f"📋 Current columns: {existing_columns}")
        
        # Define all required columns
        required_columns = {
            'RISK_LEVEL': 'NVARCHAR(20)',
            'RISK_FACTORS': 'NCLOB',
            'URL_LENGTH': 'INTEGER',
            'DOMAIN_LENGTH': 'INTEGER',
            'SPECIAL_CHARS': 'INTEGER',
            'URL_ENTROPY': 'DECIMAL(5,3)',
            'DOMAIN_ENTROPY': 'DECIMAL(5,3)',
            'SUBDOMAINS': 'INTEGER',
            'USER_AGENT': 'NVARCHAR(500)',
            'IP_ADDRESS': 'NVARCHAR(45)'
        }
        
        # Add missing columns
        print("\n➕ Adding missing columns...")
        for column_name, column_type in required_columns.items():
            if column_name not in existing_columns:
                try:
                    alter_sql = f"ALTER TABLE SENTINELONE.PHISHING_LOGS ADD ({column_name} {column_type})"
                    cursor.execute(alter_sql)
                    conn.commit()
                    print(f"✅ Added: {column_name} ({column_type})")
                except Exception as e:
                    print(f"❌ Failed to add {column_name}: {e}")
            else:
                print(f"✅ Already exists: {column_name}")
        
        # Verify final structure
        print("\n🔍 Final table structure:")
        cursor.execute("""
            SELECT COLUMN_NAME, DATA_TYPE_NAME 
            FROM TABLE_COLUMNS 
            WHERE SCHEMA_NAME = 'SENTINELONE' 
            AND TABLE_NAME = 'PHISHING_LOGS'
            ORDER BY POSITION
        """)
        
        final_columns = cursor.fetchall()
        for col_name, col_type in final_columns:
            print(f"   📋 {col_name}: {col_type}")
        
        cursor.close()
        conn.close()
        
        print("\n🎉 Schema update completed successfully!")
        print("🚀 Your PhishGuard Pro can now log to HANA with all features!")
        
    except Exception as e:
        print(f"❌ Error updating schema: {e}")

if __name__ == "__main__":
    print("🔧 Adding missing columns to SAP HANA table...")
    print("=" * 60)
    add_missing_columns()