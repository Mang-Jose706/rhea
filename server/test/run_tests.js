const fetch = global.fetch || require('node-fetch');
const EventSource = require('eventsource');

const BASE = process.env.BASE || 'http://localhost:3001';

async function wait(ms){ return new Promise(r=>setTimeout(r,ms)); }

async function signupStudent() {
  const payload = { studentId: 'STEST1', studentName: 'Test Student', type: 'Student ID', photoName: 'id.jpg' };
  const res = await fetch(BASE + '/api/requests', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
  });
  const json = await res.json().catch(()=>null);
  console.log('POST /api/requests', res.status, json);
  return json && json.request && json.request.request_id;
}

async function adminLogin(username='admin', password='admin123'){
  const res = await fetch(BASE + '/api/admin/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username, password, secretCode: 'ADMIN2026' })});
  const json = await res.json().catch(()=>null);
  console.log('admin login', res.status, json && json.token);
  return json && json.token;
}

async function patchStatus(id, token, status){
  const res = await fetch(BASE + `/api/requests/${id}/status`, { method: 'PATCH', headers: { 'Content-Type':'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify({ status, actorRole: 'admin', updatedBy: 'test-run' }) });
  const json = await res.json().catch(()=>null);
  console.log('PATCH status', res.status, json);
  return json;
}

async function run(){
  console.log('Starting tests...');
  // Listen via SSE
  const sse = new EventSource(BASE + '/api/requests/stream?userId=STEST1&role=student');
  let sseEvents = [];
  sse.onmessage = (e)=>{ try{ const d=JSON.parse(e.data); sseEvents.push(d); console.log('SSE event', d.type, d.request); }catch(err){ console.log('SSE raw', e.data); } };

  // Listen via WebSocket
  const ws = new (require('ws'))(`ws://localhost:3000/ws`);
  ws.on('open', ()=>{ ws.send(JSON.stringify({ type:'identify', role:'student', userId:'STEST1' })); });
  ws.on('message', (m)=>{ try{ const d=JSON.parse(m); console.log('WS event', d.type, d.request);}catch(e){console.log('WS raw', m.toString())} });

  // Submit a request
  const reqId = await signupStudent();
  if (!reqId) { console.error('Request creation failed'); process.exit(1); }

  await wait(500);

  // Admin logs in and updates
  const token = await adminLogin();
  if (!token) { console.error('Admin login failed'); process.exit(1); }

  await wait(300);
  await patchStatus(reqId, token, 'Processing');
  await wait(300);
  await patchStatus(reqId, token, 'Ready');

  // allow events to be received
  await wait(1000);
  sse.close();
  ws.close();

  if (sseEvents.length >= 1) {
    console.log('SSE received events, test PASSED');
    process.exit(0);
  } else {
    console.error('No SSE events received, test FAILED');
    process.exit(2);
  }
}

run().catch(err=>{ console.error('Test run error', err); process.exit(2); });
