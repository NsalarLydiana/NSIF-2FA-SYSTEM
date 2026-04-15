# test_ldap.py
from ldap3 import Server, Connection, ALL, SUBTREE

LDAP_SERVER = "192.168.1.124"
BASE_DN = "DC=nsif-local,DC=test"

# Use the new simple password
ADMIN_DN = "CN=Administrator,CN=Users,DC=nsif-local,DC=test"
ADMIN_PASSWORD = "Admin123"  # Simple password, no special chars

print("="*60)
print("TEST: ADMIN CONNECTION")
print("="*60)
print(f"Server: {LDAP_SERVER}")
print(f"Admin DN: {ADMIN_DN}")
print(f"Password: (hidden)\n")

try:
    server = Server(LDAP_SERVER, get_info=ALL)
    
    print("Attempting to connect...")
    
    conn = Connection(
        server,
        user=ADMIN_DN,
        password=ADMIN_PASSWORD,
        auto_bind=True
    )
    
    print("✅ CONNECTION SUCCESSFUL!\n")
    
    # Try to search for a user
    print("Searching for hr_user1...")
    conn.search(
        search_base=BASE_DN,
        search_filter="(sAMAccountName=hr_user1)",
        search_scope=SUBTREE,
        attributes=["cn", "displayName"]
    )
    
    if conn.entries:
        print("✅ Search successful!")
        for entry in conn.entries:
            print(f"   Found: {entry.displayName}")
    else:
        print("❌ User not found")
    
    conn.unbind()
    
except Exception as e:
    print(f"❌ ERROR: {e}")
    import traceback
    traceback.print_exc()