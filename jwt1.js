const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3001;
const SECRET_KEY = 'your_strong_secret_key'; // Use a strong secret key

// Middleware
app.use(cors());
app.use(bodyParser.json());

// In-memory data storage
let students = [];
let currentId = 1;
let users = []; // In-memory user storage

// User Registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser  = { username, password: hashedPassword };
    users.push(newUser );
    res.status(201).send('User  registered successfully');
});

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send('User  not found');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Invalid password');

    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// CRUD Operations for Students

// Create a new student
app.post('/students', authenticateToken, (req, res) => {
    const student = {
        id: currentId++,
        name: req.body.name,
        age: req.body.age,
        grade: req.body.grade
    };
    students.push(student);
    res.status(201).json(student);
});

// Read all students
app.get('/students', authenticateToken, (req, res) => {
    res.json(students);
});

// Read a single student
app.get('/students/:id', authenticateToken, (req, res) => {
    const student = students.find(s => s.id === parseInt(req.params.id));
    if (!student) return res.status(404).send('Student not found');
    res.json(student);
});

// Update a student
app.put('/students/:id', authenticateToken, (req, res) => {
    const student = students.find(s => s.id === parseInt(req.params.id));
    if (!student) return res.status(404).send('Student not found');

    student.name = req.body.name;
    student.age = req.body.age;
    student.grade = req.body.grade;

    res.json(student);
});

// Delete a student
app.delete('/students/:id', authenticateToken, (req, res) => {
    const studentIndex = students.findIndex(s => s.id === parseInt(req.params.id));
    if (studentIndex === -1) return res.status(404).send('Student not found');

    const deletedStudent = students.splice(studentIndex, 1);
    res.json(deletedStudent);
});
// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
