require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-Memory Database (Temporary Array)
const users = [];

// MIDDLEWARE 1: Token Verification (Session Management)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access Denied! Token missing." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or Expired Token!" });
        req.user = user;
        next();
    });
};

// MIDDLEWARE 2: Role Management (Role-Based Access Control)
const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: "Forbidden! Unaku access illai." });
        }
        next();
    };
};

// 1. REGISTER ROUTE (Password Hashing Included)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!username || !password || !role) return res.status(400).json({ error: "Ellam field-ayum fill pannunga!" });

        const userExists = users.find(u => u.username === username);
        if (userExists) return res.status(400).json({ error: "Username already taken!" });

        // Password Encryption via bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ username, password: hashedPassword, role });
        res.status(201).json({ message: "Account created safely!" });
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. LOGIN ROUTE (JWT Generation Included)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = users.find(u => u.username === username);
        if (!user) return res.status(400).json({ error: "User-ah kanom! Register pannunga." });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Thappana password!" });

        const accessToken = jwt.sign(
            { username: user.username, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '15m' }
        );

        res.json({ message: "Login Successful!", token: accessToken, role: user.role });
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. PROTECTED ROUTES
app.get('/api/dashboard/user', authenticateToken, authorizeRoles('user', 'admin'), (req, res) => {
    res.json({ content: `Welcome to USER Dashboard, ${req.user.username}! Idhu unga basic panel.` });
});

app.get('/api/dashboard/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
    res.json({ content: `🚨 Welcome to ADMIN Panel, ${req.user.username}! Neenga advanced dashboard-la irukinga.` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT} 🚀`));