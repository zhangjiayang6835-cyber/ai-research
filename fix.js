const express = require('express');
const app = express();
app.use(express.json());

// Assume authentication middleware sets req.userId
app.get('/profile/:userId', (req, res) => {
  const userId = parseInt(req.params.userId);
  // Check authentication
  if (!req.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // IDOR fix: only allow access to own profile
  if (req.userId !== userId) {
    return res.status(403).json({ error: 'Forbidden: You can only view your own profile' });
  }
  // Fetch and return profile data (simulated)
  const profileData = {
    userId: userId,
    username: `user_${userId}`,
    email: `user${userId}@example.com`
  };
  res.json(profileData);
});

app.listen(3000);
