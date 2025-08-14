require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors({
  if (err) return res.status(500).json({ error: 'Ошибка базы данных' });
  if (!user) return res.status(400).json({ error: 'Неверный логин' });
  origin: "http://localhost:5173", // можно '*' для разрешения всем, но это менее безопасно
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const SECRET_KEY = process.env.SECRET_KEY || "dev-secret-key";
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
  console.log(`Swagger: http://localhost:${PORT}/api-docs`);
});

const db = new sqlite3.Database('./database.db');

// Создание таблицы пользователей
db.run(`CREATE TABLE IF NOT EXISTS todos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER,
  text TEXT,
  completed INTEGER DEFAULT 0,
  FOREIGN KEY(userId) REFERENCES users(id)
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Генерация JWT токена
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, {
    expiresIn: '1h',
  });
}

// Мидлвар для проверки токена
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Неверный токен' });
    req.user = user;
    next();
  });
}

// Регистрация
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`,
    [username, hashedPassword],
    function (err) {
      if (err) return res.status(400).json({ error: 'Пользователь уже существует' });
      res.json({ message: 'Регистрация успешна' });
    }
  );
});

// Логин
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'Неверный логин' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Неверный пароль' });

    const token = generateToken(user);
    res.json({ message: 'Успешный вход', token });
  });
});

// Защищённый маршрут
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Вы получили доступ к защищённому ресурсу!', user: req.user });
});

app.get('/todos', authenticateToken, (req, res) => {
  const userId = req.user.id; // из токена
  db.all(`SELECT * FROM todos WHERE userId = ?`, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Ошибка запроса' });
    res.json(rows);
  });
});

app.post('/todos', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { text } = req.body;

  if (!text) return res.status(400).json({ error: 'Поле text обязательно' });

  db.run(`INSERT INTO todos (userId, text) VALUES (?, ?)`,
    [userId, text],
    function (err) {
      if (err) return res.status(500).json({ error: 'Ошибка при создании задачи' });
      res.json({ message: 'Задача добавлена', id: this.lastID });
    });
});

app.put('/todos/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  const { text } = req.body;

  db.run(
    `UPDATE todos SET text = ? WHERE id = ? AND userId = ?`,
    [text, id, userId],
    function (err) {
      if (err) return res.status(500).json({ error: 'Ошибка обновления задачи' });
      if (this.changes === 0) return res.status(404).json({ error: 'Задача не найдена или не принадлежит пользователю' });
      res.json({ message: 'Задача обновлена' });
    }
  );
});

app.patch('/todos/:id/status', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  const { completed } = req.body;

  db.run(`UPDATE todos SET completed = ? WHERE id = ? AND userId = ?`,
    [completed ? 1 : 0, id, userId],
    function (err) {
      if (err) return res.status(500).json({ error: 'Ошибка обновления статуса' });
      if (this.changes === 0) return res.status(404).json({ error: 'Задача не найдена' });
      res.json({ message: 'Статус обновлён' });
    });
});

app.delete('/todos/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;

  db.run(`DELETE FROM todos WHERE id = ? AND userId = ?`,
    [id, userId],
    function (err) {
      if (err) return res.status(500).json({ error: 'Ошибка удаления' });
      if (this.changes === 0) return res.status(404).json({ error: 'Задача не найдена' });
      res.json({ message: 'Задача удалена' });
    });
});