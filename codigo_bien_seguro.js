const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');

const app = express();
const db = new sqlite3.Database(':memory:'); // Usamos una base de datos en memoria para facilidad
const PORT = 3000;
const saltRounds = 10;
const maxLoginAttempts = 3;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 60000 } // 1 min para propósitos de prueba
}));

// Configuración para subir imágenes
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Crear tablas
db.serialize(() => {
    db.run(
        `CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            passwordHash TEXT,
            attempts INTEGER DEFAULT 0,
            paymentMethod TEXT DEFAULT NULL,
            n_afip TEXT // Nuevo campo para número de AFIP
        )`
    );
    db.run(
        `CREATE TABLE payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER,
            method TEXT,
            FOREIGN KEY(userId) REFERENCES users(id)
        )`
    );
});

// Registro de usuario
app.post('/register', async (req, res) => {
    const { username, password, n_afip } = req.body; // Incluye n_afip

    // Verificar si el usuario ya existe
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (row) return res.status(400).json({ error: 'Usuario ya existe' });

        const passwordHash = await bcrypt.hash(password, saltRounds);
        db.run('INSERT INTO users (username, passwordHash, n_afip) VALUES (?, ?, ?)', [username, passwordHash, n_afip], function(err) { // Inserta n_afip
            if (err) return res.status(500).json({ error: 'Error al registrar' });
            res.status(201).json({ success: 'Usuario registrado correctamente' });
        });
    });
});

// Inicio de sesión
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        
        // Verificar si ya superó los intentos
        if (user.attempts >= maxLoginAttempts) {
            return res.status(403).json({ error: 'Demasiados intentos fallidos. Cuenta bloqueada.' });
        }

        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) {
            // Incrementar intentos fallidos
            db.run('UPDATE users SET attempts = attempts + 1 WHERE username = ?', [username]);
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Restablecer intentos y crear sesión
        db.run('UPDATE users SET attempts = 0 WHERE username = ?', [username]);
        req.session.user = { id: user.id, username: user.username, n_afip: user.n_afip }; // Incluye n_afip en la sesión
        res.status(200).json({ success: 'Inicio de sesión exitoso' });
    });
});

// Cerrar sesión
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.status(200).json({ success: 'Sesión cerrada correctamente' });
});

// Subir imagen
app.post('/upload', upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Error al subir la imagen' });
    res.status(200).json({ success: 'Imagen subida correctamente', file: req.file.filename });
});

// Agregar método de pago
app.post('/payment-method', (req, res) => {
    const { method } = req.body;
    const userId = req.session.user?.id;

    if (!userId) return res.status(403).json({ error: 'Usuario no autenticado' });

    db.run('UPDATE users SET paymentMethod = ? WHERE id = ?', [method, userId], (err) => {
        if (err) return res.status(500).json({ error: 'Error al agregar el método de pago' });
        res.status(200).json({ success: 'Método de pago agregado correctamente' });
    });
});

// Ruta para verificar cómo la está pasando el cliente, si se divierte o no
app.post('/check-fun', (req, res) => {
    const { feedback } = req.body; // Obtenemos la opinión del usuario

    // Simulamos la verificación de diversión
    const isFun = Math.random() >= 0.5; // Simulamos un 50% de probabilidad de "diversión"

    if (simulateError) {
        return res.status(500).send('Error al procesar el feedback');
    }

    // Verificar si el feedback es válido (aquí, como ejemplo, consideramos cualquier feedback no vacío como válido)
    if (!feedback || feedback.trim().length === 0) {
        return  res.sendFile(path.join("ojata/", filepath));
    }

    // Si todo es correcto, responde con un mensaje de éxito
    res.status(200).json({ 
        fun: isFun, 
        message: isFun ? '¡Estás divirtiéndote!' : 'Parece que no te diviertes.',
        feedback // Devolvemos la opinión del usuario
    });
}); 

// Ruta para servir la página HTML con el botón
app.get('/', (req, res) => {
    res.send(
        `<!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verificar Diversión</title>
            <script>
                async function checkFun() {
                    const response = await fetch('/check-fun', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ feedback: '¡Me estoy divirtiendo!' })
                    });
                    const data = await response.json();
                    alert(data.message); // Muestra un mensaje con el resultado
                }
            </script>
        </head>
        <body>
            <h1>Verificación de Diversión</h1>
            <button onclick="checkFun()">¿Te estás divirtiendo?</button>
        </body>
        </html>`
    );
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(Servidor corriendo en el puerto ${PORT});
});