const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const router = express.Router();

module.exports = function(io) {
  const limiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
  router.use(limiter);

  function genTokenHex(len = 32) { return crypto.randomBytes(len).toString('hex'); }
  function hashToken(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

  async function sendEmail(to, subject, html) {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: +process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({ from: process.env.SMTP_FROM, to, subject, html });
  }

  // register
  router.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    try {
      const [rows] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
      if (rows.length) return res.status(409).json({ error: 'username already taken' });
      const hash = await bcrypt.hash(password, 12);
      const [result] = await pool.query('INSERT INTO users (username, password_hash, email, created_at, last_activity, active, email_verified) VALUES (?, ?, ?, NOW(), NOW(), 1, 0)', [username, hash, email || null]);
      const userId = result.insertId;
      // create email verification token
      if (email) {
        const token = genTokenHex(32);
        const expires = new Date(Date.now() + 24*60*60*1000);
        await pool.query('INSERT INTO email_verifications (user_id, token, expires_at) VALUES (?, ?, ?)', [userId, token, expires]);
        const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
        try { await sendEmail(email, 'Verify your account', `Click <a href="${verifyUrl}">here</a> to verify`); } catch(e){ console.warn('email send failed', e.message); }
      }
      const token = jwt.sign({ id: userId, username }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '10m' });
      io.emit('user-registered', { id: userId, username, created_at: new Date() });
      res.json({ token, user: { id: userId, username } });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // login -> issues access token and refresh token via cookie (cookie-only flow)
  router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    try {
      const [rows] = await pool.query('SELECT id, password_hash, active, email_verified FROM users WHERE username = ?', [username]);
      if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });
      const user = rows[0];
      if (!user.active) return res.status(403).json({ error: 'account deactivated' });
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'invalid credentials' });
      // generate tokens
      const accessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '10m' });
      const refreshToken = genTokenHex(32);
      const hashed = hashToken(refreshToken);
      const expires = new Date(Date.now() + 30*24*60*60*1000);
      await pool.query('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?)', [user.id, hashed, expires, req.ip, req.get('User-Agent')]);
      // set cookie
      res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 30*24*60*60*1000 });
      await pool.query('UPDATE users SET last_activity = NOW() WHERE id = ?', [user.id]);
      io.emit('user-logged-in', { id: user.id, username, at: new Date() });
      res.json({ token: accessToken, user: { id: user.id, username, email_verified: user.email_verified } });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // verify email
  router.get('/verify-email', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'no token' });
    try {
      const [rows] = await pool.query('SELECT user_id, expires_at, used FROM email_verifications WHERE token = ?', [token]);
      if (!rows.length) return res.status(400).json({ error: 'invalid token' });
      const rec = rows[0];
      if (rec.used) return res.status(400).json({ error: 'token used' });
      if (new Date(rec.expires_at) < new Date()) return res.status(400).json({ error: 'token expired' });
      await pool.query('UPDATE users SET email_verified = 1 WHERE id = ?', [rec.user_id]);
      await pool.query('UPDATE email_verifications SET used = 1 WHERE token = ?', [token]);
      res.json({ ok: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // request password reset
  router.post('/request-password-reset', async (req, res) => {
    const { emailOrUsername } = req.body;
    try {
      const [u] = await pool.query('SELECT id, email FROM users WHERE username = ? OR email = ? LIMIT 1', [emailOrUsername, emailOrUsername]);
      if (!u.length) return res.json({ ok: true });
      const user = u[0];
      const token = genTokenHex(32);
      const expires = new Date(Date.now() + 60*60*1000);
      await pool.query('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expires]);
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
      try { await sendEmail(user.email, 'Password reset', `Click <a href="${resetUrl}">here</a> to reset your password`); } catch(e){ console.warn('email fail', e.message); }
      res.json({ ok: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // reset password
  router.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'missing' });
    try {
      const [rows] = await pool.query('SELECT user_id, expires_at, used FROM password_resets WHERE token = ?', [token]);
      if (!rows.length) return res.status(400).json({ error: 'invalid token' });
      const rec = rows[0];
      if (rec.used) return res.status(400).json({ error: 'token used' });
      if (new Date(rec.expires_at) < new Date()) return res.status(400).json({ error: 'token expired' });
      const hash = await bcrypt.hash(password, 12);
      await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [hash, rec.user_id]);
      await pool.query('UPDATE password_resets SET used = 1 WHERE token = ?', [token]);
      await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?', [rec.user_id]);
      res.json({ ok: true });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // middleware to verify access token
  const verify = (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'no token' });
    const [scheme, token] = auth.split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'invalid token format' });
    try { const payload = jwt.verify(token, process.env.JWT_SECRET); req.user = payload; next(); } catch (err) { return res.status(401).json({ error: 'token invalid' }); }
  };

  // keepalive
  router.post('/keepalive', verify, async (req, res) => {
    try { await pool.query('UPDATE users SET last_activity = NOW() WHERE id = ?', [req.user.id]); io.emit('user-activity', { id: req.user.id, at: new Date() }); res.json({ ok: true }); } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // refresh-token (cookie-only flow)
  router.post('/refresh-token', async (req, res) => {
    const token = req.cookies?.refreshToken;
    if (!token) return res.status(401).json({ error: 'no refresh token' });
    const hashed = hashToken(token);
    try {
      const [rows] = await pool.query('SELECT id, user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?', [hashed]);
      if (!rows.length) return res.status(401).json({ error: 'invalid token' });
      const rec = rows[0];
      if (rec.revoked) return res.status(401).json({ error: 'token revoked' });
      if (new Date(rec.expires_at) < new Date()) return res.status(401).json({ error: 'token expired' });
      // rotate
      const newToken = genTokenHex(32);
      const newHash = hashToken(newToken);
      const newExpires = new Date(Date.now() + 30*24*60*60*1000);
      await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?', [rec.id]);
      await pool.query('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?)', [rec.user_id, newHash, newExpires, req.ip, req.get('User-Agent')]);
      const accessToken = jwt.sign({ id: rec.user_id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '10m' });
      res.cookie('refreshToken', newToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 30*24*60*60*1000 });
      res.json({ token: accessToken });
    } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  // logout - revoke cookie token
  router.post('/logout', async (req, res) => {
    const token = req.cookies?.refreshToken;
    if (token) {
      const hashed = hashToken(token);
      await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?', [hashed]);
    }
    res.clearCookie('refreshToken');
    res.json({ ok: true });
  });

  // delete account (soft delete)
  router.delete('/me', verify, async (req, res) => {
    try { await pool.query('UPDATE users SET deleted_at = NOW(), active = 0 WHERE id = ?', [req.user.id]); io.emit('user-deleted', { id: req.user.id }); res.json({ ok: true }); } catch (err) { console.error(err); res.status(500).json({ error: 'internal error' }); }
  });

  return router;
};
