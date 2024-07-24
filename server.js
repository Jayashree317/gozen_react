const express = require('express');
const jwt = require('jwt-simple');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 4000;
const SECRET_KEY = 'your-secret-key'; // Replace with a secure secret key

app.use(bodyParser.json());
app.use(cors()); // Enable CORS for development

let users = []; // In-memory user store
let items = []; // In-memory item store

// Middleware to protect routes
const authenticate = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).send('Unauthorized');
  }
  try {
    const decoded = jwt.decode(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).send('Unauthorized');
  }
};

// POST endpoint for user registration
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  users.push({ username, password: hashedPassword });
  res.status(201).send('User registered');
});

// POST endpoint for user login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).send('Invalid credentials');
  }
  const token = jwt.encode({ username }, SECRET_KEY);
  res.json({ token });
});

// GET endpoint to retrieve all items (protected)
app.get('/api/items', authenticate, (req, res) => {
  res.json(items);
});

// POST endpoint to create a new item (protected)
app.post('/api/items', authenticate, (req, res) => {
  const newItem = { id: Date.now(), ...req.body };
  items.push(newItem);
  res.status(201).json(newItem);
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
