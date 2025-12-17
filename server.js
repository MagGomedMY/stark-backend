// server.js - ПОЛНЫЙ КОД ДЛЯ РАБОТЫ РЕГИСТРАЦИИ
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'stark-secret-key-2024';

// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());

// Создание таблиц при запуске
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Таблица users создана');
  } catch (error) {
    console.error('❌ Ошибка создания таблиц:', error);
  }
}

initDatabase();

// ====== API МАРШРУТЫ ======

// 1. Статус сервера
app.get('/api/status', (req, res) => {
  res.json({ 
    status: 'online', 
    message: 'Stark Industries API',
    timestamp: new Date().toISOString()
  });
});

// 2. Тест базы данных
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ success: true, time: result.rows[0].time });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. Проверка имени пользователя
app.get('/api/check-username/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );
    res.json({ available: result.rows.length === 0 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. РЕГИСТРАЦИЯ (самое важное!)
app.post('/api/register', async (req, res) => {
  console.log('📝 Запрос на регистрацию:', req.body);
  
  try {
    const { username, email, password } = req.body;
    
    // Валидация
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }
    
    // Проверка существующего пользователя
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );
    
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ 
        error: 'Пользователь с таким именем или email уже существует' 
      });
    }
    
    // Хэширование пароля
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    
    // Создание пользователя
    const newUser = await pool.query(
      `INSERT INTO users (username, email, password_hash) 
       VALUES ($1, $2, $3) RETURNING id, username, email, created_at`,
      [username, email, passwordHash]
    );
    
    // Создание JWT токена
    const token = jwt.sign(
      { 
        userId: newUser.rows[0].id, 
        username: newUser.rows[0].username 
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    console.log('✅ Пользователь зарегистрирован:', username);
    
    res.status(201).json({
      message: 'Регистрация успешна!',
      token,
      user: {
        id: newUser.rows[0].id,
        username: newUser.rows[0].username,
        email: newUser.rows[0].email
      }
    });
    
  } catch (error) {
    console.error('❌ Ошибка регистрации:', error);
    res.status(500).json({ 
      error: 'Ошибка сервера при регистрации',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 5. Вход в систему
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Поиск пользователя
    const user = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $1',
      [username]
    );
    
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
    }
    
    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
    }
    
    // Создание токена
    const token = jwt.sign(
      { userId: user.rows[0].id, username: user.rows[0].username },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      message: 'Вход выполнен успешно',
      token,
      user: {
        id: user.rows[0].id,
        username: user.rows[0].username,
        email: user.rows[0].email
      }
    });
    
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// 6. Проверка токена
app.get('/api/verify-token', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.json({ valid: false, error: 'Токен не предоставлен' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch (error) {
    res.json({ valid: false, error: 'Недействительный токен' });
  }
});

// 7. Все пользователи (для теста)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, email, created_at FROM users');
    res.json({ users: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`📡 API доступно: http://localhost:${PORT}/api`);
  console.log(`🔗 FRONTEND_URL: ${process.env.FRONTEND_URL || 'не настроен'}`);
  console.log(`🗄️ DATABASE_URL: ${process.env.DATABASE_URL ? 'настроена' : 'не настроена'}`);
});
