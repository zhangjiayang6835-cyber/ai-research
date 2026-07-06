const express = require('express');
const app = express();
app.use(express.json());

const users = []; // In-memory store for demo

// Function to filter allowed fields (whitelist)
function filterUserUpdate(body) {
  const allowedFields = ['username', 'email'];
  const filtered = {};
  for (const key of allowedFields) {
    if (body[key] !== undefined) {
      filtered[key] = body[key];
    }
  }
  return filtered;
}

app.patch('/user/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Only update allowed fields
  const safeData = filterUserUpdate(req.body);
  Object.assign(user, safeData);

  res.json({ message: 'User updated' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
