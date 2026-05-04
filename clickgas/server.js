const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors());
app.use(express.json());

const SECRET = "segredo_super_seguro";

// banco
const db = new sqlite3.Database('./database.db');

// tabelas
db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  username TEXT,
  password TEXT
)
`);

db.run(`
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  items TEXT,
  payment TEXT,
  total REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`);


// REGISTER
app.post('/register', async (req, res) => {
  const { email, username, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (email, username, password) VALUES (?, ?, ?)`,
    [email, username, hashed],
    (err) => {
      if (err) return res.status(400).json({ message: "Erro ou email já existe" });

      res.json({ message: "Usuário criado com sucesso" });
    }
  );
});


// LOGIN
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (!user) return res.status(401).json({ message: "Usuário não encontrado" });

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) return res.status(401).json({ message: "Senha inválida" });

    const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "2h" });

    res.json({ token, user });
  });
});


// MIDDLEWARE
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "Sem token" });

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido" });
  }
}


// ORDER
app.post('/order', auth, (req, res) => {
  const { cart, payment } = req.body;

  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);

  db.run(
    `INSERT INTO orders (user_id, items, payment, total) VALUES (?, ?, ?, ?)`,
    [req.user.id, JSON.stringify(cart), payment, total],
    function (err) {
      if (err) return res.status(500).json({ message: "Erro ao salvar pedido" });

      res.json({ message: "Pedido criado!", orderId: this.lastID });
    }
  );
});

const path = require('path');
// SERVIR FRONTEND
app.use(express.static(path.join(__dirname, '../clickgas-front')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../clickgas/index.html'));
});

// START SERVER
app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});