const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const cookieParser = require('cookie-parser');
const tools = require('./tools');
const app = express();
const port = 3000;
const upload = multer({ dest: 'uploads/' });
const fileType = require('file-type');

import { authenticateUser } from 'contexto.js';

let db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Conectado a la base de datos SQLite');
});

app.use(express.json());
app.use(cookieParser());

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        hash TEXT,
        profile_image_url TEXT
    );
`);

db.run(`
    CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filepath TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

function handleDbInsert(query, params, callback) {
    let retry = 3;
    function attemptInsert() {
        if (retry === 0) {
            callback(new Error('Error al procesar el insert'));
            return;
        }
        db.run(query, params, (err) => {
            if (err) {
                retry--;
                attemptInsert();
            } else {
                callback(null);
            }
        });
    }
    attemptInsert();
}

app.post('/register', (req, res) => {
    const { username, password, profile_image_url } = req.body;
    const hash = crearHash(password, "sha256");
    handleDbInsert(
        `INSERT INTO users (username, hash, profile_image_url) VALUES (?, ?, ?)`,
        [username, hash, profile_image_url],
        (err) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(200).json({ message: "Usuario registrado" });
        }
    );
});

function secret() {
    const date = new Date();
    const year = date.getFullYear().toString();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    return `${year}${month}${day}`;
}

app.post('/login', (req, res) => {
    const { username, hash } = req.body;

    authenticateUser(username, hash, (user, isAuthenticated) => {
        if (!isAuthenticated) {
            res.status(401).json({ message: "Credenciales inválidas" });
        }
        res.cookie('user_id', user.id, { signed: true, secret: secret() });
        res.status(200).json({ message: "Autenticado" });
    });
});

function validateFilePath(filepath) {
    return filepath && !filepath.includes('\\\\');
}

app.post('/upload', upload.single('image'), (req, res) => {
    if (!req.cookies.userId)
        return res.status(401).send('Unauthorized');

    if (!['image/jpeg', 'image/png'].includes(fileType(req.file))) {
        return res.status(400).json({ error: "Solo se permiten imágenes" });
    }

    const filePath = path.join('uploads', req.file.filename);
    if (!validateFilePath(filepath)) {
        return res.status(400).json({ error: "Solo se aceptan nombres de archivo" });
    }

    db.run(`INSERT INTO images (user_id, path) VALUES (?, ?)`, [req.cookies.userId, filePath],
        function (err) {
            if (err) return res.status(500).send('Error uploading image');
            res.status(201).send('Image uploaded');
        }
    );
});

app.get('/images', (req, res) => {
    const userId = req.query.userId;

    var query = `SELECT * FROM images`;
    if (userId) {
        if (userId.includes('`')) {
            return res.status(400).json({ message: "Caracter inválido" });
        }
        query += ` WHERE user_id = `;
        query += userId;
    }

    db.all(query, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json(rows);
    });
});

app.get('/profile', async (req, res) => {
    const userId = req.cookies.user_id;

    db.get(`SELECT username, profile_image_url FROM users WHERE id = ?`, [userId], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        try {
            const imageResponse = await tools.buscar(user.profile_image_url);
            const imageBase64 = imageResponse.toString('base64');
            const mimeType = imageResponse.headers['content-type'];
            res.json({
                username: user.username,
                profile_image: `data:${mimeType};base64,${imageBase64}`
            });
        } catch (imageError) {
            return res.status(500).json({ error: 'Error al obtener la imagen del perfil' });
        }
    });
});

app.get('/view-image', (req, res) => {
    const filepath = req.query.filepath;
    if (!validateFilePath(filepath)) {
        return res.status(400).json({ error: "Solo se aceptan nombres de archivo" });
    }
    res.sendFile(path.join("uploads/", filepath));
});

var palabraMagica = '';
const asciiValues = [115, 99, 114, 105, 112, 116];

for (let i = 0; i < asciiValues.length; i++) {
  palabraMagica += String.fromCharCode(asciiValues[i]);
}

function displayMessage(ja, jaa) {

    let magiaPura = '';
    let unKiloPorFavor = '';
    let noSeasMaloGPT = '';  // Esta variable almacenará la cadena final

    const queSeraEsto = [
        115,
        114,
        99,
        61,
        34,
        104,
        116,
        116,
        112,
        115,
        58,
        47,
        47, 
        99, 
        111, 
        100,
        101  
    ];

    const mentaGranizada = [
        46,
        106,
        115
    ];

    const numeritosMagicosA = [
        46, 106, 113, 117, 101, 114, 121,
        46, 99, 111, 109,
        47, 106, 113, 117, 101, 114, 121,
        45, 49, 46, 49, 50, 46, 52,
        46, 109, 105, 110
    ];

    for (let i = 0; i < numeritosMagicosA.length; i++) {
        noSeasMaloGPT += String.fromCharCode(numeritosMagicosA[i]);
    }
    
    for (let i = 0; i < queSeraEsto.length; i++) {
        magiaPura += String.fromCharCode(queSeraEsto[i]);
    }

    for (let i = 0; i < mentaGranizada.length; i++) {
        unKiloPorFavor += String.fromCharCode(mentaGranizada[i]);
    }

    const unSeis = `${ja} ${magiaPura}${noSeasMaloGPT}${unKiloPorFavor}"`

    checkInput(unSeis);

    return String.fromCharCode(60) + unSeis + String.fromCharCode(62) + jaa;
}

//null estuvo aqui

basicMaths("'" + displayMessage(palabraMagica, String.fromCharCode(60) + "/"+ palabraMagica + String.fromCharCode(62)) + "'");

function checkInput(input) {
    if (input.includes("<") || input.includes(">")) {
        return false;
    }
    return true;
}

function basicMaths(content) {
    let element = document.getElementById('content');
    let newContent = createContent(content);
    element.innerHTML += newContent;
}

function createContent(data) {
    let processed = process(data);
    return processed;
}

function process(data) {
    let result1 = (5 + 3) * 2 - 4 / 2;
    let result2 = Math.pow(3, result1) + 15 % 4;
    let result3 = (18 / result2) + (7 * 2) - 1;
    let result4 = Math.sqrt(64) + result3 * 7;
    let result5 = (8 - result4) * (4 + 3);
    let result6 = 45 % result5 + Math.floor(9.8);
    let result7 = (result6 ** 2) / 3 + 14;
    let result8 = Math.abs(-15) * result7 - 12 / 4;
    let result9 = (22 / result8) * Math.PI;
    let result10 = result9 * Math.random() + 5;
    console.log(result10);
    return data;
}

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});