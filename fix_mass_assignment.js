const express = require('express');
const app = express();
app.use(express.json());

const allowedFields = ['username', 'email'];

app.post('/api/users', (req, res) => {
    const safeData = {};
    for (let field of allowedFields) {
        if (req.body[field] !== undefined) {
            safeData[field] = req.body[field];
        }
    }
    // Validate required fields
    if (!safeData.username || !safeData.email) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    // Default role to 'user' to prevent privilege escalation
    safeData.role = 'user';
    // Assuming a User model and database logic
    // const user = await User.create(safeData);
    res.status(201).json({ message: 'User created', data: safeData });
});

app.listen(3000, () => console.log('Server running on port 3000'));