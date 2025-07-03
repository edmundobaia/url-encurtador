const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { nanoid } = require('nanoid');

const app = express();
const db = new sqlite3.Database('./db.sqlite');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'segredo-super-seguro',
  resave: false,
  saveUninitialized: false
}));

// Criação das tabelas
db.run(`CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  clicks INTEGER DEFAULT 0
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
)`);

// Criar usuário admin padrão
const criarAdmin = async () => {
  db.get('SELECT * FROM users WHERE username = ?', ['admin'], async (err, row) => {
    if (!row) {
      const hash = await bcrypt.hash('admin123', 10);
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', ['admin', hash]);
      console.log('Usuário admin criado: admin / admin123');
    }
  });
};
criarAdmin();

// Middleware de autenticação
function autenticar(req, res, next) {
  if (req.session.usuario) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Rotas públicas
app.post('/encurtar', (req, res) => {
  const id = nanoid(6);
  const url = req.body.url;
  db.run('INSERT INTO links (id, url) VALUES (?, ?)', [id, url], err => {
    if (err) return res.status(500).json({ error: 'Erro ao salvar URL' });
    res.json({ shortUrl: `${req.protocol}://${req.get('host')}/${id}` });
  });
});

app.get('/:id', (req, res) => {
  const id = req.params.id;
  db.get('SELECT url, clicks FROM links WHERE id = ?', [id], (err, row) => {
    if (!row) return res.status(404).send('Link não encontrado');
    db.run('UPDATE links SET clicks = ? WHERE id = ?', [row.clicks + 1, id]);
    res.redirect(row.url);
  });
});

// Login
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.send('Usuário não encontrado');
    const valido = await bcrypt.compare(password, user.password);
    if (valido) {
      req.session.usuario = username;
      res.redirect('/painel');
    } else {
      res.send('Senha incorreta');
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Painel protegido
app.get('/painel', autenticar, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'painel.html'));
});

app.get('/api/links', autenticar, (req, res) => {
  db.all('SELECT * FROM links ORDER BY clicks DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro ao buscar links' });
    res.json(rows);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
