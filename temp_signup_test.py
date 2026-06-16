import urllib.request
import urllib.error
import json
import time

base = 'http://127.0.0.1:8000'
backend = 'http://127.0.0.1:3000'
print('Checking local page...')
try:
    with urllib.request.urlopen(base + '/admin-signup.html') as resp:
        html = resp.read().decode('utf-8', errors='replace')
        print('PAGE STATUS', resp.status)
        print('PAGE TITLE FOUND:', 'Admin Registration' in html)
except Exception as e:
    print('PAGE ERROR:', e)

print('\nChecking backend signup endpoint...')
username = 'testadmin_' + str(int(time.time()))
data = json.dumps({
    'username': username,
    'password': 'TestPass123',
    'role': 'admin',
    'displayName': username,
    'secretCode': 'ADMIN2026'
}).encode('utf-8')
req = urllib.request.Request(
    backend + '/api/admin/signup',
    data=data,
    headers={'Content-Type': 'application/json'},
    method='POST'
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode('utf-8', errors='replace')
        print('BACKEND STATUS', resp.status)
        print('BACKEND RESPONSE', body)
except urllib.error.HTTPError as e:
    print('BACKEND HTTP ERROR', e.code)
    print(e.read().decode('utf-8', errors='replace'))
except Exception as e:
    print('BACKEND ERROR:', e)
