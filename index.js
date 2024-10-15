const dotenv = require('dotenv');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const cookieParser = require('cookie-parser');

dotenv.config();

app.use(express.json());
app.use(cookieParser());

const users = [
  { id: 1, name: 'admin', role: 'admin', password: '$2b$10$TWFs5FJdpFSK.Cdq2HJzp.CQST0MCLJ8kUg8pRBRGvXSTN.B8/.DS' },
  { id: 2, name: 'user', role: 'user', password: '$2b$10$tlFhvkscFO/uw2wZMbHq4uQO4ZGfmg3bHsd9o2TkdoxxK4CFNUBMC' }
];

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  const parsedToken = token.split(' ')[1];
  jwt.verify(parsedToken, process.env.SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.post('/login', (req, res) => {
  const { name, password } = req.body;
  const user = users.find(u => u.name === name);
  if (!user) return res.status(404).json({ error: 'User not found' });

  bcrypt.compare(password, user.password, (err, result) => {
    if (!result) return res.status(403).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id}, process.env.SECRET_KEY, { expiresIn: '2h' });
    res.cookie('role', user.role, { signed: true, secret: process.env.SECRET_KEY_ROLE });
    res.json({ token });
  });
});

app.get('/admin', authenticateToken, (req, res) => {
  if (req.cookies.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  res.json({ message: 'Welcome, Admin' });
});

app.get('/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({ name: user.name, role: user.role });
});

app.listen(3000, () => console.log('Server running on port 3000'));