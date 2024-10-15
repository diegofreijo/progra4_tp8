import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import cors from 'cors';
import multer from 'multer';
import axios from 'axios'; 

const port = process.env.PORT || 3001;
const app = express();
app.use(express.json());
app.use(cors());

const upload = multer({ dest: 'uploads/' });

const users = [];

const checkUserId = (request, response, next) => {
    const { id } = request.params;
    const index = users.findIndex(user => user.id === id);

    if (index < 0) {
        return response.status(404).json({ message: "User not found" });
    }

    request.userIndex = index;
    request.userId = id;

    next();
};

app.get('/', (request, response) => {
    return response.json('Hello World!');
});

app.get('/users', (request, response) => {
    return response.json(users);
});

app.post('/users', upload.single('profilePhoto'), (request, response) => {
    try {
        const { name, age } = request.body;

        if (age < 12) throw new Error("Only allowed users over 12 years old!");

        const profilePhoto = request.file ? request.file.filename : null;

        const user = { id: uuidv4(), name, age, profilePhoto };
        users.push(user);

        return response.status(201).json(user);
    } catch (err) {
        return response.status(400).json({ error: err.message });
    } finally {
        console.log("Process finished!");
    }
});

app.put('/users/:id', checkUserId, (request, response) => {
    const { name, age } = request.body;
    const index = request.userIndex;
    const id = request.userId;

    const updatedUser = { id, name, age };
    users[index] = updatedUser;

    return response.json(updatedUser);
});

app.delete('/users/:id', checkUserId, (request, response) => {
    const index = request.userIndex;
    users.splice(index, 1);

    return response.status(204).json();
});

app.post('/track-visit', async (req, res) => {
    const refererUrl = req.headers.referer;

    if (refererUrl) {
        try {
            const response = await axios.get(refererUrl);
            res.status(200).send(`Content from ${refererUrl}: ${response.data}`);
        } catch (error) {
            res.status(500).send('Error fetching referer content');
        }
    } else {
        res.status(400).send('Referer not provided');
    }
});

app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self' http://example.com");
    next();
});

app.listen(port, () => console.log(`Server is running on port ${port}`));