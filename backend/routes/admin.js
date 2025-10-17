const express = require('express');
const pool = require('../db');
const jwt = require('jsonwebtoken');

module.exports = function(io) {
  const router = express.Router();

  const verifyAdmin = (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'no token' });
    const [scheme, token] = auth.split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'invalid token' });
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      if (!payload.isAdmin) return res.status(403).json({ error: 'not admin' });
      req.admin = payload; next();
    } catch (err) { return res.status(401).json({ error: 'token invalid' }); }
  };

  router.get('/users', verifyAdmin, async (req, res) => {
    try {
      const { q, from, to, active } = req.query;
      let sql = 'SELECT id, username, email, created_at, last_activity, deleted_at, active FROM users WHERE 1=1';
      const params = [];
      if (q) { sql += ' AND username LIKE ?'; params.push('%' + q + '%'); }
      if (from) { sql += ' AND created_at >= ?'; params.push(from); }
      if (to) { sql += ' AND created_at <= ?'; params.push(to); }
      if (typeof active !== 'undefined') { sql += ' AND active = ?'; params.push(active == '1' ? 1 : 0); }
      sql += ' ORDER BY created_at DESC LIMIT 1000';
      const [rows] = await pool.query(sql, params);
      res.json({ users: rows });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // list refresh tokens for a user
  router.get('/users/:id/refresh-tokens', verifyAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const [rows] = await pool.query('SELECT id, created_at, expires_at, revoked, ip, user_agent FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC', [id]);
      res.json({ tokens: rows });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // revoke refresh token by id
  router.post('/refresh-tokens/:id/revoke', verifyAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?', [id]);
      res.json({ ok: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  router.delete('/users/:id', verifyAdmin, async (req, res) => {
    try { const { id } = req.params; await pool.query('UPDATE users SET deleted_at = NOW(), active = 0 WHERE id = ?', [id]); io.emit('user-deleted', { id }); res.json({ ok: true }); } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  router.post('/users/:id/deactivate', verifyAdmin, async (req, res) => {
    try { const { id } = req.params; await pool.query('UPDATE users SET active = 0 WHERE id = ?', [id]); io.emit('user-deactivated', { id }); res.json({ ok: true }); } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  router.get('/stats', verifyAdmin, async (req, res) => {
    try {
      const [[{ total }]] = await pool.query('SELECT COUNT(*) as total FROM users');
      const [[{ deleted }]] = await pool.query('SELECT COUNT(*) as deleted FROM users WHERE deleted_at IS NOT NULL');
      const [[{ active }]] = await pool.query('SELECT COUNT(*) as active FROM users WHERE active = 1');
      const [activity] = await pool.query(`SELECT DATE(last_activity) as day, COUNT(*) as cnt FROM users WHERE last_activity IS NOT NULL GROUP BY DATE(last_activity) ORDER BY day DESC LIMIT 30`);
      res.json({ total, deleted, active, activity });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  return router;
};
