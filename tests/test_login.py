import os
import sqlite3
os.chdir('c:/Scripts/Apps/Software-Portal')

# Test database connection
conn = sqlite3.connect('software_portal.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Test users table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
if cursor.fetchone():
    print('✓ Users table exists')
else:
    print('✗ Users table missing')
    exit(1)

# Test user query
cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
user = cursor.fetchone()
if user:
    print(f'✓ User found: {user["username"]}')
    print(f'✓ Password hash exists: {bool(user["password_hash"])}')
else:
    print('✗ Admin user not found')
    exit(1)

conn.close()
print('✓ All database operations completed successfully')
print('\nDatabase is ready! You can now start the app.')
