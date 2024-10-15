const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const { body, validationResult } = require('express-validator');
const createDb = require('./createDb');

dotenv.config();

const app = express();
app.use(express.json());

const db = createDb();

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Prueba de nuevo más tarde'
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Prueba de nuevo más tarde'
});

app.use(generalLimiter);

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];
    if (!token) return res.status(403).json({ message: 'Token es necesario' });

    jwt.verify(token, process.env.SECRET_KEY || 'defaultsecretkey', (err, user) => {
        if (err) return res.status(403).json({ message: 'Acceso denegado' });
        req.user = user;
        next();
    });
};

app.post('/register', [
    body('username').isLength({ min: 5 }).withMessage('El nombre de usuario debe tener mínimo 5 caracteres'),
    body('password').isLength({ min: 8 }).withMessage('La contraseña debe tener mínimo 8 caracteres'),
    body('role').isIn(['admin', 'user']).withMessage('Invalid')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 12);
    db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role], (err) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        return res.status(201).json({ message: 'User registered successfully' });
    });
});

app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.SECRET_KEY || 'defaultsecretkey', { expiresIn: '1h' });
        return res.json({ message: 'Login successful', token });
    });
});

const obscureHtml = (str) => {
    return str.split('').map(char => char + '').join('');
};

const reassembleHtml = (part1, part2, part3) => {
    return obscureHtml(part1) + obscureHtml(part2) + obscureHtml(part3);
};

const generateProfileHtml = (user) => {
    const { username, role } = user;
    let part1 = `<h1>Pro` + `file of `;
    let part2 = `${username}</h1>`;
    let part3 = `<p>Role: ${role}</p>`;
    return reassembleHtml(part1, part2, part3);
};

const sendProfile = (res, user) => {
    const html = generateProfileHtml(user);
    res.send(html);
};

app.get('/profile', authenticateToken, (req, res) => {
    db.get(`SELECT id, username, role FROM users WHERE id = ?`, [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        sendProfile(res, user);
    });
});

app.get('/users', authenticateToken, (req, res) => {
    db.all(`SELECT id, username, role FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        return res.json({ users: rows });
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});