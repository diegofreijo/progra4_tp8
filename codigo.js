// app.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const axios = require('axios');
const app = express();
const port = 3000;


const JWT_SECRET = 'supersecretkey';

app.use(bodyParser.json());

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    next();
});

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pin TEXT, role TEXT DEFAULT 'user')");
    db.run("CREATE TABLE orders (id INTEGER PRIMARY KEY, userId INTEGER, product TEXT, quantity INTEGER, total REAL)");
});

app.post('/api/auth', async (req, res) => {
    const { username, pin } = req.body;

    if (!username || !pin) {
        return res.status(400).send('Username and pin are required.');
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).send('Database error.');
        }
        if (user) {
            return res.status(409).send('User already exists.');
        }


        const hashedPin = await bcrypt.hash(pin, 8);

        const role = username.startsWith('admin') ? 'admin' : 'user';

        db.run("INSERT INTO users (username, pin, role) VALUES (?, ?, ?)", [username, hashedPin, role], function(err) {
            if (err) {
                return res.status(500).send('Error creating user.');
            }

            const token = jwt.sign({ id: this.lastID, role }, JWT_SECRET);
            res.status(201).send({ token });
        });
    });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/api/orders', authenticateToken, async (req, res) => {
    const { product, quantity, callbackUrl } = req.body;
    const userId = req.user.id;

    if (!product || !quantity || typeof quantity !== 'number') {
        return res.status(400).send('Invalid order data.');
    }

    const total = quantity * 10; 

    db.run("INSERT INTO orders (userId, product, quantity, total) VALUES (?, ?, ?, ?)", [userId, product, quantity, total], async function(err) {
        if (err) {
            return res.status(500).send('Error creating order.');
        }

        try {
            const response = await axios.post(callbackUrl, { orderId: this.lastID, status: 'created' });
            res.status(201).send({ orderId: this.lastID, product, quantity, total, callbackResponse: response.data });
        } catch (error) {
            res.status(500).send('Order created, but callback failed.');
        }
    });
});

app.listen(port, () => {
    console.log(`API escuchando en http://localhost:${port}`);
});