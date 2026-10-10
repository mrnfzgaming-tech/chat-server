require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// ---- Connect to MongoDB ----
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ---- Models ----
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  publicKey: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
  from: String,
  to: String,
  ciphertext: String,
  nonce: String,
  timestamp: { type: Date, default: Date.now },
   delivered: { type: Boolean, default: false },
  readAt: { type: Date, default: null }
});
const Message = mongoose.model('Message', MessageSchema);
const FriendSchema = new mongoose.Schema({
  user1: { type: String, required: true },
  user2: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
FriendSchema.index({ user1: 1, user2: 1 }, { unique: true });
const Friend = mongoose.model('Friend', FriendSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-please';

// ---- Routes ----
app.post('/register', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;
    if (!username || !password || !publicKey)
      return res.status(400).json({ error: 'Missing fields' });

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'Username taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ username, passwordHash, publicKey });

    const token = jwt.sign({ username }, JWT_SECRET);
    res.json({ token, username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ username }, JWT_SECRET);
    res.json({ token, username, publicKey: user.publicKey });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/users/:username/pubkey', async (req, res) => {
  const user = await User.findOne({ username: req.params.username });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ publicKey: user.publicKey });
});

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// --- Add a friend ---
app.post('/friends/add', authenticate, async (req, res) => {
  const me = req.user.username;
  const { friendUsername } = req.body;

  if (!friendUsername || friendUsername === me)
    return res.status(400).json({ error: 'Invalid username' });

  const friendUser = await User.findOne({ username: friendUsername });
  if (!friendUser) return res.status(404).json({ error: 'User not found' });

  // store in sorted order so (a,b) === (b,a)
  const [u1, u2] = [me, friendUsername].sort();

  try {
    await Friend.create({ user1: u1, user2: u2 });
  } catch (e) {
    // already friends — ignore
  }
  res.json({ success: true });
});

// --- List my friends ---
app.get('/friends', authenticate, async (req, res) => {
  const me = req.user.username;
  const friendships = await Friend.find({
    $or: [{ user1: me }, { user2: me }]
  });
  const friendNames = friendships.map(f => f.user1 === me ? f.user2 : f.user1);
  res.json({ friends: friendNames });
});

// --- Mark messages from a friend as read ---
app.post('/messages/:friend/read', authenticate, async (req, res) => {
  const me = req.user.username;
  const friend = req.params.friend;
  await Message.updateMany(
    { from: friend, to: me, readAt: null },
    { $set: { readAt: new Date() } }
  );
  res.json({ success: true });
});
app.get('/messages/:friend', authenticate, async (req, res) => {
  const me = req.user.username;
  const friend = req.params.friend;
  const messages = await Message.find({
    $or: [
      { from: me, to: friend },
      { from: friend, to: me }
    ]
  }).sort({ timestamp: 1 });
  res.json(messages);
});

// ---- Socket.io ----
const onlineUsers = new Map();

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers.set(username, socket.id);
  console.log('🟢 ' + username + ' connected');

  socket.on('send_message', async ({ to, ciphertext, nonce }) => {
    const msg = await Message.create({
      from: username, to, ciphertext, nonce,
      delivered: onlineUsers.has(to)
    });

    const recipientSocket = onlineUsers.get(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('new_message', {
        from: username, ciphertext, nonce,
        timestamp: msg.timestamp, _id: msg._id
      });
    }
    socket.emit('message_sent', { _id: msg._id, timestamp: msg.timestamp });
  });

    socket.on('typing', ({ to, isTyping }) => {
    const recipientSocket = onlineUsers.get(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('friend_typing', { from: username, isTyping });
    }
  });

  socket.on('mark_read', async ({ from }) => {
    await Message.updateMany(
      { from, to: username, readAt: null },
      { $set: { readAt: new Date() } }
    );
    const senderSocket = onlineUsers.get(from);
    if (senderSocket) {
      io.to(senderSocket).emit('messages_read', { by: username });
    }
  });
  socket.on('disconnect', () => {
    onlineUsers.delete(username);
    console.log('🔴 ' + username + ' disconnected');
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log('🚀 Server on http://localhost:' + PORT));