const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.options('*', cors({ origin: true, credentials: true }));
app.use(bodyParser.json());

const sessions = new Map();
// SQLite persistence (optional)
let db = null;
let sqliteAvailable = false;
try {
  const sqlite3 = require('sqlite3').verbose();
  db = new sqlite3.Database('./data.sqlite');
  sqliteAvailable = true;

  // Initialize database tables
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS students (
      student_id TEXT PRIMARY KEY UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      mobile_number TEXT UNIQUE NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      department TEXT,
      program TEXT,
      password_hash TEXT NOT NULL,
      created_at TEXT,
      updated_at TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS requests (
      request_id TEXT PRIMARY KEY,
      student_id TEXT,
      type TEXT,
      status TEXT,
      last_updated TEXT,
      raw JSON
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
      id TEXT PRIMARY KEY,
      action TEXT,
      details JSON,
      timestamp TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS duplicate_audit (
      id TEXT PRIMARY KEY,
      field_name TEXT,
      field_value TEXT,
      attempt_count INTEGER,
      ip_address TEXT,
      user_agent TEXT,
      first_attempt TEXT,
      last_attempt TEXT
    )`);
  });
} catch (err) {
  console.warn('SQLite not available, running without persistent storage.');
}

function persistRequest(record) {
  if (!sqliteAvailable || !db) return;
  const stmt = db.prepare(`INSERT OR REPLACE INTO requests (request_id, student_id, type, status, last_updated, raw) VALUES (?,?,?,?,?,?)`);
  stmt.run(record.request_id, record.student_id, record.type, record.status, record.last_updated, JSON.stringify(record));
  stmt.finalize();
}

function persistAdminLog(entry) {
  if (!sqliteAvailable || !db) return;
  const stmt = db.prepare(`INSERT INTO admin_logs (id, action, details, timestamp) VALUES (?,?,?,?)`);
  stmt.run(entry.id, entry.action, JSON.stringify(entry.details || {}), entry.timestamp);
  stmt.finalize();
}

function loadRequestsFromDb(callback) {
  if (!sqliteAvailable || !db) return callback(null, []);
  db.all(`SELECT raw FROM requests`, (err, rows) => {
    if (err) return callback(err);
    try {
      const out = rows.map(r => JSON.parse(r.raw));
      return callback(null, out);
    } catch (e) {
      return callback(e);
    }
  });
}

function persistStudent(student) {
  if (!sqliteAvailable || !db) return;
  const stmt = db.prepare(`INSERT OR REPLACE INTO students (student_id, email, mobile_number, first_name, last_name, department, program, password_hash, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`);
  stmt.run(
    student.student_id,
    student.email,
    student.mobile_number,
    student.first_name,
    student.last_name,
    student.department || '',
    student.program || '',
    student.password_hash,
    student.created_at,
    student.updated_at
  );
  stmt.finalize();
}

function findStudentByIdDb(studentId, callback) {
  if (!sqliteAvailable || !db) return callback(null, null);
  db.get(`SELECT * FROM students WHERE student_id = ?`, [studentId], callback);
}

function findStudentByEmailDb(email, callback) {
  if (!sqliteAvailable || !db) return callback(null, null);
  db.get(`SELECT * FROM students WHERE email = ?`, [email], callback);
}

function findStudentByMobileDb(mobileNumber, callback) {
  if (!sqliteAvailable || !db) return callback(null, null);
  db.get(`SELECT * FROM students WHERE mobile_number = ?`, [mobileNumber], callback);
}

function logDuplicateAttempt(fieldName, fieldValue, ipAddress, userAgent) {
  if (!sqliteAvailable || !db) {
    console.log('[DUPLICATE_AUDIT]', { fieldName, fieldValue, ipAddress, timestamp: new Date().toISOString() });
    return;
  }

  const auditId = `DUP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const now = new Date().toISOString();
  const compositeKey = `${fieldName}:${fieldValue}`;

  db.get(
    `SELECT * FROM duplicate_audit WHERE field_name = ? AND field_value = ?`,
    [fieldName, fieldValue],
    (err, row) => {
      if (err) {
        console.error('Error querying duplicate_audit:', err);
        return;
      }

      if (row) {
        // Update existing record
        const newCount = (row.attempt_count || 0) + 1;
        db.run(
          `UPDATE duplicate_audit SET attempt_count = ?, last_attempt = ? WHERE field_name = ? AND field_value = ?`,
          [newCount, now, fieldName, fieldValue]
        );
      } else {
        // Create new record
        const stmt = db.prepare(
          `INSERT INTO duplicate_audit (id, field_name, field_value, attempt_count, ip_address, user_agent, first_attempt, last_attempt) VALUES (?,?,?,?,?,?,?,?)`
        );
        stmt.run(auditId, fieldName, fieldValue, 1, ipAddress || 'unknown', userAgent || 'unknown', now, now);
        stmt.finalize();
      }
    }
  );

  console.log('[DUPLICATE_AUDIT]', { auditId, fieldName, fieldValue, ipAddress, timestamp: now });
}
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

function hashPassword(password, salt = null) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, usedSalt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2$${usedSalt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  if (stored.startsWith('pbkdf2$')) {
    const parts = stored.split('$');
    if (parts.length !== 3) return false;
    const [, salt, expectedHash] = parts;
    const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return computedHash === expectedHash;
  }
  return password === stored;
}

function createAdminSession(admin) {
  const token = `admin-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const expiresAt = Date.now() + SESSION_DURATION_MS;
  sessions.set(token, { admin, token, createdAt: new Date().toISOString(), expiresAt });
  return token;
}

function getAdminSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function parseAuthorizationToken(req) {
  const header = req.headers['authorization'] || req.headers['x-admin-token'];
  if (!header) return null;
  if (header.toString().toLowerCase().startsWith('bearer ')) {
    return header.toString().slice(7).trim();
  }
  return header.toString().trim();
}

function optionalAdminAuth(req, res, next) {
  const token = parseAuthorizationToken(req);
  if (token) {
    const session = getAdminSession(token);
    if (!session) {
      return res.status(401).json({ error: 'unauthorized', message: 'Admin token invalid or expired.' });
    }
    req.adminSession = session;
    req.adminUser = session.admin;
  }
  return next();
}

function authenticateAdmin(req, res, next) {
  const token = parseAuthorizationToken(req);
  const session = getAdminSession(token);
  if (!session) {
    return res.status(401).json({ error: 'unauthorized', message: 'Admin token invalid or missing.' });
  }
  req.adminSession = session;
  req.adminUser = session.admin;
  return next();
}

function createStudentSession(student) {
  const token = `student-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const expiresAt = Date.now() + SESSION_DURATION_MS;
  studentSessions.set(token, { student, token, createdAt: new Date().toISOString(), expiresAt });
  return token;
}

function getStudentSession(token) {
  if (!token) return null;
  const session = studentSessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    studentSessions.delete(token);
    return null;
  }
  return session;
}

function authenticateStudent(req, res, next) {
  const token = parseAuthorizationToken(req);
  const session = getStudentSession(token);
  if (!session) {
    return res.status(401).json({ error: 'unauthorized', message: 'Student token invalid or missing.' });
  }
  req.studentSession = session;
  req.studentUser = session.student;
  return next();
}

// In-memory presence store: userId -> timestamp (ms)
const presence = new Map();
const PRESENCE_THRESHOLD_MS = 60000; // 60s

app.post('/presence/heartbeat', (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'missing userId' });
  const now = Date.now();
  presence.set(userId.toString(), now);
  return res.json({ ok: true, userId, lastSeen: new Date(now).toISOString() });
});

app.get('/presence/:userId', (req, res) => {
  const userId = req.params.userId;
  const t = presence.get(userId);
  if (!t) return res.json({ userId, online: false, lastSeen: null });
  const online = (Date.now() - t) < PRESENCE_THRESHOLD_MS;
  return res.json({ userId, online, lastSeen: new Date(t).toISOString() });
});

app.get('/presence', (req, res) => {
  const out = [];
  for (const [userId, t] of presence.entries()) {
    out.push({ userId, lastSeen: new Date(t).toISOString(), online: (Date.now() - t) < PRESENCE_THRESHOLD_MS });
  }
  res.json(out);
});

// In-memory notification store for IDEAS activity events.
const notifications = [];
// SSE clients set
const sseClients = new Set();

function sendSseEvent(client, event) {
  try {
    client.write(`data: ${JSON.stringify(event)}\n\n`);
  } catch (e) {
    // ignore
  }
}

// In-memory admin user store for basic authentication.
const admins = [
  { id: 'admin-001', username: 'admin', password: 'admin123', displayName: 'IDEase Admin', secretCode: 'ADMIN2026', role: 'admin' },
  { id: 'superadmin', username: 'superadmin', password: 'supersecure', displayName: 'Super Admin', secretCode: 'ADMIN2026', role: 'superadmin' }
];

// In-memory student store for basic authentication (mirrors database).
const students = [];

// In-memory student sessions: token -> session
const studentSessions = new Map();

// In-memory admin requests store for superadmin approval workflow.
const adminRequests = [];

// In-memory request store for IDEAS request lifecycle.
const requests = [];
// In-memory audit log for admin actions
const auditLogs = [];

function findRequestById(requestId) {
  return requests.find((req) => req.id === requestId) || null;
}

function normalizeName(name) {
  return (name || '').toString().trim().replace(/\s+/g, ' ').toLowerCase();
}

function createRequestRecord(data) {
  const now = new Date().toISOString();
  const fullName = data.fullName || data.studentName || 'Student';
  const record = {
    // canonical request shape for real-time sync
    id: data.id || `REQ-${Date.now()}`,
    request_id: data.id || `REQ-${Date.now()}`,
    studentId: (data.studentId || data.userId || 'unknown').toString(),
    student_id: (data.studentId || data.userId || 'unknown').toString(),
    studentName: data.studentName || fullName,
    fullName,
    type: data.type || 'Student ID',
    status: data.status || 'Submitted',
    createdAt: data.createdAt || now,
    updatedAt: now,
    last_updated: now,
    photoFilename: data.photoFilename || data.photoName || '',
    createdBy: data.createdBy || data.userId || 'student',
    rejectionReason: data.rejectionReason || null,
    details: data.details || ''
  };
  requests.unshift(record);
  // persist
  persistRequest(record);
  return record;
}

function updateRequestStatusRecord(requestId, newStatus, additionalData = {}) {
  const request = findRequestById(requestId);
  if (!request) return null;
  request.status = newStatus;
  request.updatedAt = new Date().toISOString();
  request.last_updated = request.updatedAt;
  Object.assign(request, additionalData);

  // persist update
  persistRequest(request);

  if (newStatus === 'Processing') {
    request.processingStartedAt = request.processingStartedAt || new Date().toISOString();
  }
  if (newStatus === 'Ready' || newStatus === 'Completed') {
    request.completedAt = new Date().toISOString();
  }
  if (newStatus === 'Rejected') {
    request.rejectedAt = new Date().toISOString();
  }

  return request;
}

function logAdminAction(action, details = {}) {
  const entry = {
    id: `AUDIT-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    action,
    details,
    timestamp: new Date().toISOString()
  };
  auditLogs.unshift(entry);
  console.log('[AUDIT]', entry);
  try { persistAdminLog(entry); } catch(e) { /* ignore persistence errors */ }
  return entry;
}

function isActiveRequest(status) {
  const lower = (status || '').toLowerCase();
  // Active statuses: Submitted, Pending/Verification, Processing
  return ['submitted', 'pending', 'verification', 'processing'].includes(lower);
}

function hasActiveRequest(studentId) {
  if (!studentId) return false;
  return requests.some((req) => req.studentId === studentId.toString() && isActiveRequest(req.status));
}

function hasActiveDuplicateRequest(studentId, fullName) {
  if (!studentId || !fullName) return false;
  const normalizedFullName = normalizeName(fullName);
  return requests.some((req) => {
    const matchesStudent = req.studentId === studentId.toString();
    const matchesName = normalizeName(req.fullName || req.studentName) === normalizedFullName;
    return matchesStudent && matchesName && isActiveRequest(req.status);
  });
}

// Middleware to prevent students creating overlapping active requests
function enforceSingleActiveRequest(req, res, next) {
  const payload = req.body || {};
  const studentId = payload.studentId;
  const fullName = payload.fullName || payload.studentName;
  if (!studentId) return res.status(400).json({ error: 'missing required request data' });

  if (!fullName) {
    return res.status(400).json({ error: 'missing required request data', message: 'Student ID and full name are required.' });
  }

  // Allow admins to create requests on behalf of students
  if (payload.createdBy && payload.createdBy === 'admin') return next();

  if (hasActiveRequest(studentId)) {
    return res.status(409).json({
      error: 'active_request_exists',
      message: 'You already have an active request. Please wait for completion or update if rejected.'
    });
  }

  if (hasActiveDuplicateRequest(studentId, fullName)) {
    return res.status(409).json({
      error: 'duplicate_active_request',
      message: 'You already have an active request. Please wait for completion or update if rejected.'
    });
  }
  return next();
}

function createRequestNotificationEvent(request, type, extra = {}) {
  const eventType = type;
  const titles = {
    'request.new': 'New ID Request Submitted',
    'request.verification': 'Request Verification Started',
    'request.processing': 'Request Processing',
    'request.ready': 'Request Ready',
    'request.completed': 'Request Completed',
    'request.rejected': 'Request Rejected'
  };
  const messages = {
    'request.new': 'Your ID request has been received and is now under review.',
    'request.verification': 'Your request is now under verification.',
    'request.processing': 'Your request is now being processed.',
    'request.ready': 'Your request has been completed and is ready.',
    'request.completed': 'Your request has been completed successfully.',
    'request.rejected': 'Your request has been rejected.'
  };
  const tones = {
    'request.new': 'orange',
    'request.verification': 'blue',
    'request.processing': 'blue',
    'request.ready': 'green',
    'request.completed': 'green',
    'request.rejected': 'red'
  };
  const icons = {
    'request.new': 'fa-file-circle-plus',
    'request.verification': 'fa-shield-check',
    'request.processing': 'fa-spinner',
    'request.ready': 'fa-circle-check',
    'request.completed': 'fa-circle-check',
    'request.rejected': 'fa-circle-xmark'
  };

  const event = {
    userId: request.studentId,
    type: eventType,
    category: 'Request Updates',
    title: titles[eventType] || 'Request Update',
    message: extra.message || messages[eventType] || 'Your request status changed.',
    details: extra.details || `Your request ${request.id} is now ${request.status}.`,
    tone: tones[eventType] || 'gray',
    icon: icons[eventType] || 'fa-bell',
    sourceId: request.id,
    timestamp: new Date().toISOString(),
    status: 'unread',
    // include canonical request payload for clients
    request: {
      request_id: request.request_id || request.id,
      student_id: request.student_id || request.studentId,
      type: request.type,
      status: request.status,
      last_updated: request.last_updated || request.updatedAt
    }
  };

  createNotification(event);
  // broadcast to websocket clients
  broadcast(event);
  // broadcast to SSE clients
  for (const client of sseClients) {
    try {
      sendSseEvent(client, event);
    } catch (e) {
      // ignore
    }
  }

  const statusPayload = {
    type: 'requestStatusUpdate',
    requestId: request.id,
    studentId: request.studentId,
    status: request.status,
    updatedBy: extra.updatedBy || request.updatedBy || 'system',
    timestamp: new Date().toISOString(),
    request: { id: request.id, studentId: request.studentId, status: request.status, updatedAt: request.updatedAt }
  };
  broadcast(statusPayload);

  return event;
}

const ADMIN_SECRET_CODE = 'ADMIN2026';

// Real-time duplicate check endpoints
app.get('/api/student/check-student-id', (req, res) => {
  const { student_id } = req.query;

  if (!student_id || !/^\d{6}$/.test(student_id.toString())) {
    return res.json({ available: true, message: 'Invalid student ID format' });
  }

  const existingInMemory = students.find(s => s.student_id === student_id.toString());
  if (existingInMemory) {
    logDuplicateAttempt('student_id', student_id, req.ip, req.get('user-agent'));
    return res.json({ available: false, message: 'Student ID already registered' });
  }

  if (sqliteAvailable && db) {
    findStudentByIdDb(student_id.toString(), (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'database_error' });
      }
      if (row) {
        logDuplicateAttempt('student_id', student_id, req.ip, req.get('user-agent'));
        return res.json({ available: false, message: 'Student ID already registered' });
      }
      return res.json({ available: true, message: 'Student ID is available' });
    });
  } else {
    return res.json({ available: true, message: 'Student ID is available' });
  }
});

app.get('/api/student/check-email', (req, res) => {
  const { email } = req.query;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.json({ available: true, message: 'Invalid email format' });
  }

  const existingInMemory = students.find(s => s.email === email.toLowerCase());
  if (existingInMemory) {
    logDuplicateAttempt('email', email, req.ip, req.get('user-agent'));
    return res.json({ available: false, message: 'Email already registered' });
  }

  if (sqliteAvailable && db) {
    findStudentByEmailDb(email.toLowerCase(), (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'database_error' });
      }
      if (row) {
        logDuplicateAttempt('email', email, req.ip, req.get('user-agent'));
        return res.json({ available: false, message: 'Email already registered' });
      }
      return res.json({ available: true, message: 'Email is available' });
    });
  } else {
    return res.json({ available: true, message: 'Email is available' });
  }
});

app.get('/api/student/check-mobile', (req, res) => {
  const { mobile_number } = req.query;

  if (!mobile_number) {
    return res.json({ available: true, message: 'Enter mobile number' });
  }

  const existingInMemory = students.find(s => s.mobile_number === mobile_number.toString());
  if (existingInMemory) {
    logDuplicateAttempt('mobile_number', mobile_number, req.ip, req.get('user-agent'));
    return res.json({ available: false, message: 'Mobile number already registered' });
  }

  if (sqliteAvailable && db) {
    findStudentByMobileDb(mobile_number.toString(), (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'database_error' });
      }
      if (row) {
        logDuplicateAttempt('mobile_number', mobile_number, req.ip, req.get('user-agent'));
        return res.json({ available: false, message: 'Mobile number already registered' });
      }
      return res.json({ available: true, message: 'Mobile number is available' });
    });
  } else {
    return res.json({ available: true, message: 'Mobile number is available' });
  }
});

// Student Signup Endpoint
app.post('/api/student/signup', (req, res) => {
  const { student_id, email, mobile_number, first_name, last_name, department, program, password, confirmPassword } = req.body || {};

  // Validate required fields
  if (!student_id || !email || !mobile_number || !first_name || !last_name || !password || !confirmPassword) {
    return res.status(400).json({ error: 'missing_fields', message: 'All fields are required.' });
  }

  // Validate passwords match
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'password_mismatch', message: 'Passwords do not match.' });
  }

  // Validate password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters long.' });
  }
  if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must contain uppercase letters and numbers.' });
  }

  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'invalid_email', message: 'Invalid email format.' });
  }

  // Validate student_id is 6 digits
  if (!/^\d{6}$/.test(student_id.toString())) {
    return res.status(400).json({ error: 'invalid_student_id', message: 'Student ID must be 6 digits.' });
  }

  // Check for duplicate student_id (memory)
  const existingById = students.find(s => s.student_id === student_id.toString());
  if (existingById) {
    logDuplicateAttempt('student_id', student_id, req.ip, req.get('user-agent'));
    return res.status(409).json({ error: 'duplicate_student_id', message: 'A student account with this ID already exists.' });
  }

  // Check for duplicate email (memory)
  const existingByEmail = students.find(s => s.email === email.toLowerCase());
  if (existingByEmail) {
    logDuplicateAttempt('email', email, req.ip, req.get('user-agent'));
    return res.status(409).json({ error: 'duplicate_email', message: 'A student account with this email already exists.' });
  }

  // Check for duplicate mobile number (memory)
  const existingByMobile = students.find(s => s.mobile_number === mobile_number.toString());
  if (existingByMobile) {
    logDuplicateAttempt('mobile_number', mobile_number, req.ip, req.get('user-agent'));
    return res.status(409).json({ error: 'duplicate_mobile', message: 'A student account with this mobile number already exists.' });
  }

  // If database available, also check in database
  if (sqliteAvailable && db) {
    let dbError = null;
    let checksPassed = 0;
    const checksNeeded = 3;

    findStudentByIdDb(student_id.toString(), (err, row) => {
      if (err) dbError = err;
      if (row) {
        logDuplicateAttempt('student_id', student_id, req.ip, req.get('user-agent'));
        return res.status(409).json({ error: 'duplicate_student_id', message: 'A student account with this ID already exists.' });
      }
      checksPassed++;
      if (checksPassed === checksNeeded && !dbError) proceedWithSignup();
    });

    findStudentByEmailDb(email.toLowerCase(), (err, row) => {
      if (err) dbError = err;
      if (row) {
        logDuplicateAttempt('email', email, req.ip, req.get('user-agent'));
        return res.status(409).json({ error: 'duplicate_email', message: 'A student account with this email already exists.' });
      }
      checksPassed++;
      if (checksPassed === checksNeeded && !dbError) proceedWithSignup();
    });

    findStudentByMobileDb(mobile_number.toString(), (err, row) => {
      if (err) dbError = err;
      if (row) {
        logDuplicateAttempt('mobile_number', mobile_number, req.ip, req.get('user-agent'));
        return res.status(409).json({ error: 'duplicate_mobile', message: 'A student account with this mobile number already exists.' });
      }
      checksPassed++;
      if (checksPassed === checksNeeded && !dbError) proceedWithSignup();
    });

    function proceedWithSignup() {
      if (dbError) {
        return res.status(500).json({ error: 'database_error', message: 'An error occurred during signup.' });
      }
      createNewStudent();
    }
  } else {
    createNewStudent();
  }

  function createNewStudent() {
    const now = new Date().toISOString();
    const passwordHash = hashPassword(password);
    const newStudent = {
      id: `student-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      student_id: student_id.toString(),
      email: email.toLowerCase(),
      mobile_number: mobile_number.toString(),
      first_name: first_name.toString().trim(),
      last_name: last_name.toString().trim(),
      department: department || '',
      program: program || '',
      password_hash: passwordHash,
      created_at: now,
      updated_at: now,
      accountType: 'student'
    };

    students.push(newStudent);
    persistStudent(newStudent);

    logAdminAction('student_signup', { student_id: newStudent.student_id, email: newStudent.email });

    return res.status(201).json({
      ok: true,
      message: 'Student account created successfully. Please log in with your credentials.',
      student: {
        id: newStudent.id,
        student_id: newStudent.student_id,
        email: newStudent.email,
        first_name: newStudent.first_name,
        last_name: newStudent.last_name
      }
    });
  }
});

// Student Login Endpoint
app.post('/api/student/login', (req, res) => {
  const { student_id, password } = req.body || {};

  if (!student_id || !password) {
    return res.status(400).json({ error: 'missing_credentials', message: 'Student ID and password are required.' });
  }

  const student = students.find(s => s.student_id === student_id.toString());
  if (!student) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid student ID or password.' });
  }

  if (!verifyPassword(password, student.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid student ID or password.' });
  }

  const token = createStudentSession(student);
  const responsePayload = {
    ok: true,
    token,
    redirect: '/student-dashboard.html',
    user: {
      id: student.id,
      student_id: student.student_id,
      email: student.email,
      first_name: student.first_name,
      last_name: student.last_name,
      department: student.department,
      program: student.program,
      accountType: 'student'
    }
  };

  logAdminAction('student_login', { student_id: student.student_id, email: student.email });
  return res.status(200).json(responsePayload);
});

// Student Me Endpoint
app.get('/api/student/me', authenticateStudent, (req, res) => {
  return res.json({ ok: true, user: req.studentUser });
});

// Duplicate audit logs endpoint (admin access)
app.get('/api/admin/duplicate-audit-logs', authenticateAdmin, (req, res) => {
  if (sqliteAvailable && db) {
    db.all(`SELECT * FROM duplicate_audit ORDER BY last_attempt DESC`, (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'database_error', message: 'Failed to retrieve audit logs.' });
      }
      return res.json({ ok: true, duplicateAttempts: rows || [] });
    });
  } else {
    return res.json({ ok: true, duplicateAttempts: [] });
  }
});

// Get duplicate attempts for a specific field (admin access)
app.get('/api/admin/duplicate-audit-logs/:fieldName/:fieldValue', authenticateAdmin, (req, res) => {
  const { fieldName, fieldValue } = req.params;

  if (sqliteAvailable && db) {
    db.all(
      `SELECT * FROM duplicate_audit WHERE field_name = ? AND field_value = ? ORDER BY last_attempt DESC`,
      [fieldName, fieldValue],
      (err, rows) => {
        if (err) {
          return res.status(500).json({ error: 'database_error', message: 'Failed to retrieve audit logs.' });
        }
        return res.json({ ok: true, duplicateAttempts: rows || [] });
      }
    );
  } else {
    return res.json({ ok: true, duplicateAttempts: [] });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { username, password, secretCode } = req.body || {};
  if (!username || !password || !secretCode) {
    return res.status(400).json({ error: 'missing_credentials', message: 'Username, password, and secret code are all required.' });
  }

  const admin = admins.find((entry) => entry.username === username.toString().trim());
  if (!admin) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid admin username or password.' });
  }

  if (admin.secretCode !== secretCode) {
    return res.status(401).json({ error: 'invalid_secret_code', message: 'Invalid admin secret code.' });
  }

  if (!verifyPassword(password, admin.passwordHash || admin.password)) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid admin username or password.' });
  }

  const token = createAdminSession(admin);
  const responsePayload = {
    ok: true,
    token,
    redirect: '/admin-dashboard.html',
    user: {
      id: admin.id,
      username: admin.username,
      displayName: admin.displayName,
      role: admin.role || 'admin',
      accountType: 'admin'
    }
  };

  logAdminAction('admin_login', { username: admin.username, adminId: admin.id });
  return res.status(200).json(responsePayload);
});

app.get('/api/admin/me', authenticateAdmin, (req, res) => {
  return res.json({ ok: true, user: req.adminUser });
});

app.post('/api/admin/signup', (req, res) => {
  const { username, password, role, displayName, secretCode } = req.body || {};

  if (secretCode !== ADMIN_SECRET_CODE) {
    return res.status(401).json({ error: 'invalid_secret_code', message: 'Invalid admin secret code.' });
  }

  // Validate required fields
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'missing_fields', message: 'Username, password, and role are required.' });
  }

  // Validate password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 8 characters long.' });
  }
  if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'weak_password', message: 'Password must contain uppercase letters and numbers.' });
  }

  // Check if username already exists (in current admins or pending requests)
  const usernameExists = admins.some(a => a.username.toLowerCase() === username.toLowerCase());
  const pendingRequest = adminRequests.some(ar => ar.username.toLowerCase() === username.toLowerCase() && ar.status === 'pending');
  
  if (usernameExists) {
    return res.status(409).json({ error: 'username_taken', message: 'Username already exists.' });
  }
  if (pendingRequest) {
    return res.status(409).json({ error: 'pending_request', message: 'A registration request for this username is already pending.' });
  }

  // Validate role
  if (!['admin', 'superadmin'].includes(role)) {
    return res.status(400).json({ error: 'invalid_role', message: 'Invalid role specified.' });
  }

  // Superadmin role cannot be self-registered
  if (role === 'superadmin') {
    return res.status(403).json({ error: 'forbidden', message: 'Superadmin role must be assigned by existing superadmin.' });
  }

  // Create active admin account immediately so the registration form can be used.
  const passwordHash = hashPassword(password);
  const newAdmin = {
    id: 'admin-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    username: username.trim(),
    passwordHash,
    displayName: displayName || username,
    role: role,
    secretCode: ADMIN_SECRET_CODE,
    createdAt: new Date().toISOString(),
    createdBy: 'self_signup'
  };

  admins.push(newAdmin);

  const requestId = 'admin-req-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
  const adminRequest = {
    id: requestId,
    username: newAdmin.username,
    passwordHash,
    displayName: newAdmin.displayName,
    role: newAdmin.role,
    status: 'approved',
    requestedAt: newAdmin.createdAt,
    approvedAt: new Date().toISOString(),
    approvedBy: 'self_signup',
    adminId: newAdmin.id,
    ipAddress: req.ip || 'unknown'
  };

  adminRequests.push(adminRequest);
  logAdminAction('admin_signup_auto_approved', { username: newAdmin.username, role: newAdmin.role, requestId });

  return res.status(201).json({
    ok: true,
    message: 'Admin account created successfully. Please log in with your new credentials.',
    admin: {
      id: newAdmin.id,
      username: newAdmin.username,
      displayName: newAdmin.displayName,
      role: newAdmin.role
    }
  });
});

// Admin requests management (for superadmin approval workflow)
app.get('/api/admin/requests', authenticateAdmin, (req, res) => {
  const isSuperAdmin = req.adminUser && req.adminUser.role === 'superadmin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'forbidden', message: 'Only superadmin can view admin requests.' });
  }
  return res.json(adminRequests);
});

app.post('/api/admin/requests/:id/approve', authenticateAdmin, (req, res) => {
  const isSuperAdmin = req.adminUser && req.adminUser.role === 'superadmin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'forbidden', message: 'Only superadmin can approve admin requests.' });
  }

  const requestId = req.params.id;
  const adminReq = adminRequests.find(r => r.id === requestId);
  if (!adminReq) {
    return res.status(404).json({ error: 'not_found', message: 'Admin request not found.' });
  }

  // Check if username already taken (shouldn't happen, but safety check)
  if (admins.some(a => a.username.toLowerCase() === adminReq.username.toLowerCase())) {
    return res.status(409).json({ error: 'username_taken', message: 'Username was already created by another request.' });
  }

  // Create the actual admin account
  const newAdmin = {
    id: 'admin-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    username: adminReq.username,
    passwordHash: adminReq.passwordHash || hashPassword(adminReq.password || ''),
    displayName: adminReq.displayName,
    role: adminReq.role || 'admin',
    createdAt: new Date().toISOString(),
    createdBy: req.adminUser.username
  };

  admins.push(newAdmin);

  // Update request status
  adminReq.status = 'approved';
  adminReq.approvedAt = new Date().toISOString();
  adminReq.approvedBy = req.adminUser.username;
  adminReq.adminId = newAdmin.id; // Link to created admin account
  
  logAdminAction('admin_request_approved', { 
    requestId, 
    username: adminReq.username, 
    approvedBy: req.adminUser.username, 
    newAdminId: newAdmin.id 
  });
  
  return res.json({ 
    ok: true, 
    message: 'Admin account created successfully.',
    adminRequest: adminReq,
    newAdmin: { id: newAdmin.id, username: newAdmin.username, displayName: newAdmin.displayName }
  });
});

app.post('/api/admin/requests/:id/reject', authenticateAdmin, (req, res) => {
  const isSuperAdmin = req.adminUser && req.adminUser.role === 'superadmin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'forbidden', message: 'Only superadmin can reject admin requests.' });
  }

  const requestId = req.params.id;
  const adminReq = adminRequests.find(r => r.id === requestId);
  if (!adminReq) {
    return res.status(404).json({ error: 'not_found', message: 'Admin request not found.' });
  }

  const reason = (req.body && req.body.reason) || 'No reason provided';
  adminReq.status = 'rejected';
  adminReq.rejectedAt = new Date().toISOString();
  adminReq.rejectedBy = req.adminUser.username;
  adminReq.rejectionReason = reason;
  
  logAdminAction('admin_request_rejected', { requestId, username: adminReq.username, rejectedBy: req.adminUser.username, reason });
  return res.json({ ok: true, adminRequest: adminReq });
});

app.use('/api/requests', optionalAdminAuth);

app.post('/api/requests/reset', authenticateAdmin, (req, res) => {
  requests.length = 0;
  notifications.length = 0;
  return res.json({ ok: true, message: 'All requests and notifications cleared.' });
});

app.get('/api/requests', (req, res) => {
  const userId = req.query.userId;
  if (userId) {
    return res.json(requests.filter((reqItem) => reqItem.studentId === userId.toString()));
  }
  return res.json(requests);
});

app.get('/api/requests/status-summary', (req, res) => {
  const userId = req.query.userId;
  const filteredRequests = userId ? requests.filter((reqItem) => reqItem.studentId === userId.toString()) : requests;
  const summary = {
    submitted: 0,
    pending: 0,
    completed: 0,
    rejected: 0,
    total: filteredRequests.length,
    latestStatus: null
  };

  const latestRequest = filteredRequests
    .slice()
    .sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt))[0];

  if (latestRequest) {
    summary.latestStatus = latestRequest.status;
  }

  filteredRequests.forEach((reqItem) => {
    const status = (reqItem.status || '').toLowerCase();
    if (status === 'submitted') {
      summary.submitted += 1;
    } else if (status === 'verification' || status === 'processing') {
      summary.pending += 1;
    } else if (status === 'ready' || status === 'completed') {
      summary.completed += 1;
    } else if (status === 'rejected') {
      summary.rejected += 1;
    }
  });

  return res.json(summary);
});

app.get('/api/requests/:id', (req, res) => {
  const request = findRequestById(req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  // Note: In production, validate that requester is either admin or owns this request via userId/auth token
  return res.json(request);
});

app.get('/api/requests/:id/status', (req, res) => {
  const request = findRequestById(req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  // Note: In production, validate that requester is either admin or owns this request via userId/auth token
  return res.json({ id: request.id, status: request.status, updatedAt: request.updatedAt });
});

app.post('/api/requests', optionalAdminAuth, (req, res) => {
  // Check if student is authenticated
  const token = parseAuthorizationToken(req);
  const studentSession = getStudentSession(token);
  
  const payload = req.body || {};
  if (!payload.studentId || !(payload.studentName || payload.fullName) || !payload.type) {
    return res.status(400).json({ error: 'missing required request data' });
  }

  // If student is authenticated, ensure they're creating a request for themselves
  if (studentSession) {
    const studentId = studentSession.student.student_id;
    if (payload.studentId.toString() !== studentId) {
      return res.status(403).json({ error: 'forbidden', message: 'Students can only create requests for themselves.' });
    }
  }

  // Run the single active request enforcement
  return enforceSingleActiveRequest(req, res, () => {
    const record = createRequestRecord(payload);
    createRequestNotificationEvent(record, 'request.new');
    return res.status(201).json({ ok: true, request: record });
  });
});

app.patch('/api/requests/:id/status', authenticateAdmin, (req, res) => {
  const { status, rejectionReason, details, actorRole } = req.body || {};
  const allowedStatuses = ['Submitted', 'Verification', 'Processing', 'Ready', 'Rejected'];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'missing or invalid status' });
  }

  // Enforce role-based status transitions: only admins may move requests into verification/processing/ready/rejected
  const adminOnlyStatuses = ['Verification', 'Processing', 'Ready', 'Rejected'];
  const role = (actorRole || 'student').toString().toLowerCase();
  if (adminOnlyStatuses.includes(status) && role !== 'admin') {
    return res.status(403).json({ error: 'forbidden', message: 'Only admin users can change request status to the requested value.' });
  }

  if (role === 'admin' && !req.adminUser) {
    return res.status(401).json({ error: 'unauthorized', message: 'Valid admin token required for admin status changes.' });
  }

  // Capture who updated the status for audit and broadcast
  const updatedBy = (req.body.updatedBy || req.body.actorId || 'admin').toString();
  const request = updateRequestStatusRecord(req.params.id, status, { rejectionReason, details, updatedBy });
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  // Log admin action for audit trail
  if (role === 'admin') {
    logAdminAction('status_change', {
      requestId: request.id,
      studentId: request.studentId,
      status,
      updatedBy,
      details: details || request.rejectionReason || ''
    });
  }
  const eventType = status === 'Submitted' ? 'request.new' :
                    status === 'Verification' ? 'request.verification' :
                    status === 'Processing' ? 'request.processing' :
                    status === 'Ready' ? 'request.completed' :
                    status === 'Completed' ? 'request.completed' :
                    status === 'Rejected' ? 'request.rejected' :
                    'request.update';
  createRequestNotificationEvent(request, eventType, { details: details || request.rejectionReason });
  return res.json({ ok: true, request });
});

app.patch('/api/requests/:id', optionalAdminAuth, (req, res) => {
  const request = findRequestById(req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  const updates = req.body || {};
  // Prevent students from changing status via the general update endpoint
  if (updates.status) {
    const actorRole = (updates.actorRole || 'student').toString().toLowerCase();
    if (actorRole !== 'admin') {
      return res.status(403).json({ error: 'forbidden', message: 'Only admin users may change request status.' });
    }
    if (!req.adminUser) {
      return res.status(401).json({ error: 'unauthorized', message: 'Valid admin token required for admin status changes.' });
    }
  }
  Object.assign(request, updates);
  request.updatedAt = new Date().toISOString();
  return res.json({ ok: true, request });
});

function createNotification(data) {
  const now = new Date().toISOString();
  const notification = {
    notification_id: `NOTIF-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    user_id: (data.userId || data.user_id || 'unknown').toString(),
    title: data.title,
    message: data.message,
    status: data.status || 'unread',
    timestamp: data.timestamp || now,
    category: data.category || 'System Alerts',
    type: data.type || 'notification',
    tone: data.tone || 'gray',
    icon: data.icon || 'fa-bell',
    details: data.details || '',
    sourceId: data.sourceId || data.requestId || null
  };

  notifications.unshift(notification);
  return notification;
}

app.get('/notifications', (req, res) => {
  const userId = req.query.userId;
  let out = notifications;
  if (userId) {
    out = notifications.filter((item) => item.user_id === userId.toString());
  }
  return res.json(out);
});

app.post('/notifications', authenticateAdmin, (req, res) => {
  const { userId, title, message } = req.body || {};
  if (!userId || !title || !message) {
    return res.status(400).json({ error: 'missing userId, title, or message' });
  }

  const notification = createNotification(req.body);
  broadcast(notification);
  return res.status(201).json({ ok: true, notification });
});

app.post('/notifications/mark-all-read', (req, res) => {
  const { userId } = req.body || {};
  if (!userId) {
    return res.status(400).json({ error: 'missing userId' });
  }

  const updated = notifications.filter((item) => item.user_id === userId.toString());
  updated.forEach((item) => { item.status = 'read'; });
  return res.json({ ok: true, updatedCount: updated.length });
});

// Audit logs (admin access expected in production)
app.get('/api/audit-logs', authenticateAdmin, (req, res) => {
  return res.json(auditLogs);
});

// Live IDEAS event streaming via WebSocket
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();

function broadcast(event) {
  const payload = JSON.stringify(event);
  for (const ws of clients) {
    if (ws.readyState !== ws.OPEN) continue;
    try {
      // Admin clients receive all events
      if (ws.role === 'admin' || (ws.accountType && ws.accountType === 'admin')) {
        ws.send(payload);
        continue;
      }

      // For student clients, only forward events that target their studentId
      const targetId = event.userId || event.user_id || event.studentId || event.student_id || (event.request && (event.request.studentId || event.request.student_id));
      if (targetId && ws.userId && targetId.toString() === ws.userId.toString()) {
        ws.send(payload);
      }
    } catch (e) {
      console.warn('Broadcast failed for a client', e);
    }
  }
}

// Server-Sent Events endpoint for request streams
app.get('/api/requests/stream', (req, res) => {
  // Set headers for SSE
  res.writeHead(200, {
    Connection: 'keep-alive',
    'Cache-Control': 'no-cache',
    'Content-Type': 'text/event-stream'
  });

  // Immediately send a comment to keep connection alive
  res.write(': connected\n\n');

  // Add to clients
  sseClients.add(res);

  // Optionally filter by ?userId= or ?role=admin
  req.on('close', () => {
    sseClients.delete(res);
  });
});

wss.on('connection', (ws) => {
  clients.add(ws);
  // default metadata
  ws.userId = null;
  ws.role = null;

  ws.send(JSON.stringify({
    type: 'system',
    category: 'System Alerts',
    title: 'Live activity feed connected',
    message: 'Your IDEAS notification center is now receiving real-time updates. Please identify using { type: "identify", role, userId }',
    timestamp: new Date().toISOString(),
    tone: 'info'
  }));

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data && data.type === 'identify') {
        ws.userId = data.userId ? data.userId.toString() : null;
        ws.role = data.role ? data.role.toString() : null;
        // acknowledge
        ws.send(JSON.stringify({ type: 'identified', userId: ws.userId, role: ws.role, timestamp: new Date().toISOString() }));
      }
    } catch (e) {
      // ignore non-json or unexpected messages
    }
  });

  ws.on('close', () => clients.delete(ws));
});

app.post('/events', (req, res) => {
  const event = req.body || {};
  if (!event.type || !event.title) {
    return res.status(400).json({ error: 'missing event type or title' });
  }

  const payload = {
    ...event,
    timestamp: new Date().toISOString(),
  };
  broadcast(payload);
  return res.json({ ok: true, event: payload });
});

app.post('/events/simulate', (req, res) => {
  const event = req.body.event || {
    type: 'request.new',
    category: 'Request Updates',
    title: 'New ID Request Submitted',
    message: 'A student has submitted a new ID request for processing.',
    tone: 'orange'
  };
  const payload = { ...event, timestamp: new Date().toISOString() };
  broadcast(payload);
  return res.json({ ok: true, event: payload });
});

const sampleEvents = [
  {
    type: 'request.new',
    category: 'Request Updates',
    title: 'New ID Request Submitted',
    message: 'A student has submitted a new ID request for processing in IDEAS.',
    tone: 'orange'
  },
  {
    type: 'request.review',
    category: 'Request Updates',
    title: 'Request Under Review',
    message: 'An admin is validating the submitted documents and matching them to your profile.',
    tone: 'blue'
  },
  {
    type: 'request.approved',
    category: 'Request Updates',
    title: 'Request Approved',
    message: 'Your ID request has been approved. The next step is fulfillment and dispatch.',
    tone: 'green'
  },
  {
    type: 'request.rejected',
    category: 'Request Updates',
    title: 'Request Rejected',
    message: 'The request was rejected due to missing documentation. Please resubmit the missing items.',
    tone: 'red'
  },
  {
    type: 'account.security',
    category: 'Account Actions',
    title: 'Security alert',
    message: 'A new sign-in attempt occurred from a device we do not recognize.',
    tone: 'red'
  },
  {
    type: 'system.maintenance',
    category: 'System Alerts',
    title: 'Maintenance scheduled',
    message: 'Scheduled maintenance will start Sunday at 2:00 AM. Some services may be temporarily unavailable.',
    tone: 'blue'
  }
];

let sampleIndex = 0;
setInterval(() => {
  if (clients.size > 0) {
    const event = { ...sampleEvents[sampleIndex], timestamp: new Date().toISOString() };
    broadcast(event);
    sampleIndex = (sampleIndex + 1) % sampleEvents.length;
  }
}, 18000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Presence and events server listening on http://localhost:${PORT}`));
