// server.js - ВСТАВЬТЕ ВЕСЬ ЭТОТ КОД
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'stark-secret-2024';

// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Проверка подключения
pool.connect((err) => {
  if (err) {
    console.error('❌ Ошибка подключения к БД:', err.message);
  } else {
    console.log('✅ База данных подключена');
    initDatabase();
  }
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5500',
  credentials: true
}));
app.use(express.json());

// Создание таблиц
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
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_saves (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        progress TEXT DEFAULT '{}',
        stats TEXT DEFAULT '{}',
        last_saved TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ Таблицы созданы');
  } catch (error) {
    console.error('❌ Ошибка создания таблиц:', error);
  }
}

// Маршруты API
app.get('/api/status', (req, res) => {
  res.json({ status: 'online', version: '1.0.0' });
});

app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ success: true, time: result.rows[0].time });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Проверка существующего пользователя
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );
    
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ 
        error: 'Пользователь уже существует' 
      });
    }
    
    // Хэширование пароля
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    
    // Создание пользователя
    const newUser = await pool.query(
      `INSERT INTO users (username, email, password_hash) 
       VALUES ($1, $2, $3) RETURNING id, username, email`,
      [username, email, passwordHash]
    );
    
    // Создание токена
    const token = jwt.sign(
      { userId: newUser.rows[0].id, username: newUser.rows[0].username },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    // Создание сохранения игры
    await pool.query(
      'INSERT INTO game_saves (user_id) VALUES ($1)',
      [newUser.rows[0].id]
    );
    
    res.status(201).json({
      message: 'Регистрация успешна',
      token,
      user: newUser.rows[0]
    });
    
  } catch (error) {
    console.error('Ошибка регистрации:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Поиск пользователя
    const user = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $1',
      [username]
    );
    
    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Неверные данные' });
    }
    
    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Неверные данные' });
    }
    
    // Создание токена
    const token = jwt.sign(
      { userId: user.rows[0].id, username: user.rows[0].username },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      message: 'Вход выполнен',
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

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`📡 API: http://localhost:${PORT}/api`);
});