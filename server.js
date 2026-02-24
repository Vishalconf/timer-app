const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({ host: 'localhost', database: 'timerapp', port: 5432 });
const JWT_SECRET = 'timetrack-secret-2024-change-in-production';
const SALT_ROUNDS = 10;

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      username VARCHAR(100) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS project_members (
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (project_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS time_entries (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
      started_at TIMESTAMP NOT NULL,
      stopped_at TIMESTAMP,
      duration_seconds INTEGER
    );
  `);

  const adminCheck = await pool.query('SELECT id FROM users WHERE is_admin = TRUE LIMIT 1');
  if (adminCheck.rows.length === 0) {
    const hash = await bcrypt.hash('admin123', SALT_ROUNDS);
    await pool.query(
      'INSERT INTO users (name, username, password_hash, is_admin) VALUES ($1, $2, $3, $4)',
      ['Admin', 'admin', hash, true]
    );
    console.log('Default admin created: username=admin password=admin123');
    console.log('IMPORTANT: Change this password after first login!');
  }
  console.log('Database initialized');
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// AUTH
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: user.id, name: user.name, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, username: user.username, is_admin: user.is_admin } });
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const { current_password, new_password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];
  const valid = await bcrypt.compare(current_password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
  const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
  res.json({ success: true });
});

// USERS
app.get('/api/users', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT id, name, username, is_admin, created_at FROM users ORDER BY name');
  res.json(result.rows);
});

app.post('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, username, password, is_admin } = req.body;
  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO users (name, username, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, name, username, is_admin',
      [name, username, hash, is_admin || false]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.put('/api/users/:id/reset-password', authMiddleware, adminMiddleware, async (req, res) => {
  const { new_password } = req.body;
  const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// PROJECTS
app.get('/api/projects', authMiddleware, async (req, res) => {
  const result = await pool.query(`
    SELECT p.*, array_agg(pm.user_id) FILTER (WHERE pm.user_id IS NOT NULL) as member_ids
    FROM projects p LEFT JOIN project_members pm ON p.id = pm.project_id
    GROUP BY p.id ORDER BY p.name
  `);
  res.json(result.rows);
});

app.post('/api/projects', authMiddleware, async (req, res) => {
  const { name, description, member_ids } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query('INSERT INTO projects (name, description) VALUES ($1, $2) RETURNING *', [name, description]);
    const project = result.rows[0];
    if (member_ids && member_ids.length > 0) {
      for (const uid of member_ids) {
        await client.query('INSERT INTO project_members (project_id, user_id) VALUES ($1, $2)', [project.id, uid]);
      }
    }
    await client.query('COMMIT');
    res.json(project);
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.delete('/api/projects/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM projects WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/projects/mine', authMiddleware, async (req, res) => {
  const result = await pool.query(`
    SELECT p.* FROM projects p
    JOIN project_members pm ON p.id = pm.project_id
    WHERE pm.user_id = $1 ORDER BY p.name
  `, [req.user.id]);
  res.json(result.rows);
});

// TIMER
app.post('/api/timer/start', authMiddleware, async (req, res) => {
  const { project_id } = req.body;
  const user_id = req.user.id;
  await pool.query(`
    UPDATE time_entries SET stopped_at = NOW(), duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER
    WHERE user_id = $1 AND stopped_at IS NULL
  `, [user_id]);
  const result = await pool.query(
    'INSERT INTO time_entries (user_id, project_id, started_at) VALUES ($1, $2, NOW()) RETURNING *',
    [user_id, project_id]
  );
  res.json(result.rows[0]);
});

app.post('/api/timer/stop', authMiddleware, async (req, res) => {
  const result = await pool.query(`
    UPDATE time_entries SET stopped_at = NOW(), duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER
    WHERE user_id = $1 AND stopped_at IS NULL RETURNING *
  `, [req.user.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'No active timer' });
  res.json(result.rows[0]);
});

app.get('/api/timer/active', authMiddleware, async (req, res) => {
  const result = await pool.query(`
    SELECT te.*, p.name as project_name FROM time_entries te
    JOIN projects p ON te.project_id = p.id
    WHERE te.user_id = $1 AND te.stopped_at IS NULL
  `, [req.user.id]);
  res.json(result.rows[0] || null);
});

// REPORTS
app.get('/api/reports', authMiddleware, async (req, res) => {
  const { start_date, end_date } = req.query;
  const result = await pool.query(`
    SELECT p.name as project_name, u.name as user_name,
      COUNT(te.id) as session_count,
      COALESCE(SUM(te.duration_seconds), 0) as total_seconds
    FROM time_entries te
    JOIN projects p ON te.project_id = p.id
    JOIN users u ON te.user_id = u.id
    WHERE te.stopped_at IS NOT NULL
      AND te.started_at >= $1::date
      AND te.started_at <= ($2::date + interval '1 day')
    GROUP BY p.name, u.name ORDER BY p.name, u.name
  `, [start_date, end_date]);
  res.json(result.rows);
});

initDB().then(() => {
  app.listen(3000, () => console.log('Timer app running at http://localhost:3000'));
}).catch(console.error);
