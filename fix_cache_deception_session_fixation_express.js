const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

// 安全会话配置
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,          // 仅HTTPS传输
    httpOnly: true,        // 防止客户端脚本访问
    sameSite: 'strict',    // 防止CSRF
    maxAge: 24 * 60 * 60 * 1000 // 24小时过期
  }
}));

// 防止缓存欺骗：添加无缓存头
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});

// 防止会话固定：登录成功后重新生成会话
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // 验证逻辑
  if (username === 'admin' && password === 'secret') {
    // 重新生成session
    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal server error');
      }
      req.session.user = username;
      res.send('Login successful');
    });
  } else {
    res.status(401).send('Login failed');
  }
});

module.exports = app;
