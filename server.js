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

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB error:', err));

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
  from: String,
  to: String,
  text: String,
  timestamp: { type: Date, default: Date.now },
  delivered: { type: Boolean, default: false },
  readAt: { type: Date, default: null },
});
const Message = mongoose.model('Message', MessageSchema);

const FriendSchema = new mongoose.Schema({
  user1: { type: String, required: true },
  user2: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
FriendSchema.index({ user1: 1, user2: 1 }, { unique: true });
const Friend = mongoose.model('Friend', FriendSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-please';

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  const token = header ? header.split(' ')[1] : null;
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

app.post('/register', async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const existing = await User.findOne({ username: username });
    if (existing) {
      return res.status(400).json({ error: 'Username taken' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ username: username, passwordHash: passwordHash });

    const token = jwt.sign({ username: username }, JWT_SECRET);
    return res.json({ token: token, username: username });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const user = await User.findOne({ username: username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: username }, JWT_SECRET);
    return res.json({ token: token, username: username });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/friends/add', authenticate, async (req, res) => {
  const me = req.user.username;
  const friendUsername = req.body.friendUsername;

  if (!friendUsername || friendUsername === me) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  const friendUser = await User.findOne({ username: friendUsername });
  if (!friendUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  const pair = [me, friendUsername].sort();
  const u1 = pair[0];
  const u2 = pair[1];

  try {
    await Friend.create({ user1: u1, user2: u2 });
  } catch (err) {
    // already friends - ignore
  }

  return res.json({ success: true });
});

app.get('/friends', authenticate, async (req, res) => {
  const me = req.user.username;

  const friendships = await Friend.find({
    $or: [{ user1: me }, { user2: me }],
  });

  const friendNames = friendships.map((f) => {
    if (f.user1 === me) return f.user2;
    return f.user1;
  });

  return res.json({ friends: friendNames });
});

app.get('/messages/:friend', authenticate, async (req, res) => {
  const me = req.user.username;
  const friend = req.params.friend;

  const messages = await Message.find({
    $or: [
      { from: me, to: friend },
      { from: friend, to: me },
    ],
  }).sort({ timestamp: 1 });

  return res.json(messages);
});

// Get unread counts for all friends
app.get('/messages/unread', authenticate, async (req, res) => {
  const me = req.user.username;

  try {
    // Get all friends
    const friendships = await Friend.find({
      $or: [{ user1: me }, { user2: me }]
    });

    const friendNames = friendships.map((f) =>
      f.user1 === me ? f.user2 : f.user1
    );

    // Get unread count for each friend
    const unreadCounts = {};
    for (const friend of friendNames) {
      const count = await Message.countDocuments({
        from: friend,
        to: me,
        readAt: null
      });
      unreadCounts[friend] = count;
    }

    return res.json({ unreadCounts: unreadCounts });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/messages/:friend/read', authenticate, async (req, res) => {
  const me = req.user.username;
  const friend = req.params.friend;

  await Message.updateMany(
    { from: friend, to: me, readAt: null },
    { $set: { readAt: new Date() } }
  );

  return res.json({ success: true });
});

const onlineUsers = new Map();

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET);
    next();
  } catch (err) {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers.set(username, socket.id);
  console.log(username + ' connected');

  socket.on('send_message', async (data) => {
    const to = data.to;
    const text = data.text;

    if (!to || !text) return;

    const msg = await Message.create({
      from: username,
      to: to,
      text: text,
      delivered: onlineUsers.has(to),
    });

    const recipientSocket = onlineUsers.get(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('new_message', {
        from: username,
        text: text,
        timestamp: msg.timestamp,
        _id: msg._id,
      });
    }

    socket.emit('message_sent', {
      _id: msg._id,
      timestamp: msg.timestamp,
    });
  });

  socket.on('typing', (data) => {
    const to = data.to;
    const isTyping = data.isTyping;

    const recipientSocket = onlineUsers.get(to);
    if (recipientSocket) {
      io.to(recipientSocket).emit('friend_typing', {
        from: username,
        isTyping: isTyping,
      });
    }
  });

  socket.on('mark_read', async (data) => {
    const from = data.from;

    await Message.updateMany(
      { from: from, to: username, readAt: null },
      { $set: { readAt: new Date() } }
    );

    const senderSocket = onlineUsers.get(from);
    if (senderSocket) {
      io.to(senderSocket).emit('messages_read', { by: username });
    }
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(username);
    console.log(username + ' disconnected');
  });
});

// ============================================================
// ---- ADMIN ROUTES (SECRET) ----
// ============================================================

function adminOnly(req, res, next) {
  const adminUsername = process.env.ADMIN_USERNAME;
  const adminSecret = req.headers['x-admin-secret'];

  if (!adminUsername) {
    return res.status(404).json({ error: 'Not found' });
  }

  if (req.user.username !== adminUsername) {
    return res.status(404).json({ error: 'Not found' });
  }

  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(404).json({ error: 'Not found' });
  }

  next();
}

app.post('/admin/auth', authenticate, async (req, res) => {
  const adminUsername = process.env.ADMIN_USERNAME;
  const secret = req.body.secret;

  if (!adminUsername || req.user.username !== adminUsername) {
    return res.status(404).json({ error: 'Not found' });
  }

  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(404).json({ error: 'Not found' });
  }

  return res.json({ authorized: true });
});

app.get('/admin/users', authenticate, adminOnly, async (req, res) => {
  const users = await User.find({}, { passwordHash: 0 });
  return res.json(users);
});

app.get('/admin/messages', authenticate, adminOnly, async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const skip = parseInt(req.query.skip) || 0;

  const messages = await Message.find({})
    .sort({ timestamp: -1 })
    .limit(limit)
    .skip(skip);

  const total = await Message.countDocuments();
  return res.json({ messages: messages, total: total });
});

app.get('/admin/search', authenticate, adminOnly, async (req, res) => {
  const q = req.query.q || '';
  if (!q) return res.json({ messages: [] });

  const messages = await Message.find({
    text: { $regex: q, $options: 'i' }
  }).sort({ timestamp: -1 }).limit(100);

  return res.json(messages);
});

app.delete('/admin/message/:id', authenticate, adminOnly, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: 'Delete failed' });
  }
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});