(async () => {
  const base = 'http://localhost:3000';
  const username = `testadmin_${Date.now()}`;
  const password = 'Passw0rd!';
  const payload = { username, password, role: 'admin', displayName: 'Test Admin', secretCode: 'ADMIN2026' };

  function pretty(obj) { try { return JSON.stringify(obj, null, 2); } catch(e) { return String(obj); } }

  try {
    console.log('==> Signing up:', username);
    let res = await fetch(base + '/api/admin/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const signup = await res.json().catch(() => ({ status: res.status, text: 'No JSON' }));
    console.log('Signup status:', res.status);
    console.log(pretty(signup));

    if (!res.ok) {
      console.log('Signup failed; aborting further tests.');
      process.exit(res.status || 1);
    }

    // Now login
    console.log('\n==> Logging in');
    res = await fetch(base + '/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, secretCode: 'ADMIN2026' })
    });
    const login = await res.json().catch(() => ({ status: res.status, text: 'No JSON' }));
    console.log('Login status:', res.status);
    console.log(pretty(login));

    if (!res.ok || !login.token) {
      console.log('Login failed; aborting.');
      process.exit(1);
    }

    const token = login.token;
    console.log('\n==> Validating token with /api/admin/me');
    res = await fetch(base + '/api/admin/me', { headers: { Authorization: `Bearer ${token}` } });
    const me = await res.json().catch(() => ({ status: res.status, text: 'No JSON' }));
    console.log('Me status:', res.status);
    console.log(pretty(me));

    if (res.ok) {
      console.log('\nTEST PASSED: signup -> login -> /api/admin/me all returned OK');
      process.exit(0);
    } else {
      console.log('\nTEST FAILED: /api/admin/me returned non-OK');
      process.exit(1);
    }
  } catch (err) {
    console.error('Test script error:', err);
    process.exit(2);
  }
})();
