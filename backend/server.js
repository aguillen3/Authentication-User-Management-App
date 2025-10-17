const express = require('express');
const http = require('http');
const cors = require('cors');
const dotenv = require('dotenv');
const socketio = require('socket.io');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');

dotenv.config();
const app = express();
const server = http.createServer(app);
const io = socketio(server, { cors: { origin: true, credentials: true } });

app.use(cors({ origin: process.env.FRONTEND_URL || true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', authRoutes(io));
app.use('/api/admin', adminRoutes(io));

app.get('/', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Server listening on ${PORT}`));

// basic socket tracking
const connectedUsers = new Map();
io.on('connection', (socket) => {
  socket.on('identify', (payload) => {
    if (payload && payload.userId) {
      connectedUsers.set(payload.userId, { socketId: socket.id, connectedAt: new Date() });
      io.emit('connected-users', Array.from(connectedUsers.keys()));
    }
  });
  socket.on('disconnect', () => {
    for (const [userId, meta] of connectedUsers.entries()) {
      if (meta.socketId === socket.id) connectedUsers.delete(userId);
    }
    io.emit('connected-users', Array.from(connectedUsers.keys()));
  });
});
