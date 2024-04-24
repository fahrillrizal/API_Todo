const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Koneksi ke database MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', 
  database: 'todo_apps'
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Terhubung ke database MySQL...');
});

const app = express();

// Middleware
app.use(bodyParser.json());


// Register
app.post('/register', (req, res) => {
    const { username, password } = req.body;
  
    // Verifikasi password
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,12}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ error: 'Password harus memiliki panjang 8-12 karakter dan setidaknya satu angka dan satu huruf' });
    }
  
    const sqlCheck = 'SELECT * FROM users WHERE username = ?';
    db.query(sqlCheck, [username], (err, result) => {
      if (err) throw err;
      if (result.length > 0) {
        res.status(400).json({ error: 'Username sudah digunakan' });
      } else {
        bcrypt.genSalt(10, (err, salt) => {
          if (err) throw err;
          bcrypt.hash(password, salt, (err, hash) => {
            if (err) throw err;
            const sqlInsert = 'INSERT INTO users (username, password) VALUES (?, ?)';
            db.query(sqlInsert, [username, hash], (err) => {
              if (err) throw err;
              res.status(201).json({ message: 'Registrasi berhasil' });
            });
          });
        });
      }
    });
  });
  
  // Login
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, result) => {
      if (err) throw err;
      if (result.length === 0) {
        res.status(400).json({ error: 'Username atau password salah' });
      } else {
        bcrypt.compare(password, result[0].password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            const user = {
              id: result[0].id,
              username: result[0].username
            };
            jwt.sign({ user }, 'secretkey', (err, token) => {
              if (err) throw err;
              res.json({
                message: 'Login berhasil',
                token
              });
            });
          } else {
            res.status(400).json({ error: 'Username atau password salah' });
          }
        });
      }
    });
  });
  
  // Middleware untuk verifikasi token
  function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
      const bearerToken = bearerHeader.split(' ')[1];
      req.token = bearerToken;
      next();
    } else {
      res.sendStatus(403);
    }
  }

// Menampilkan semua todo
app.get('/todos', (req, res) => {
  let sql = 'SELECT * FROM todo';
  db.query(sql, (err, result) => {
    if (err) throw err;
    res.json(result);
  });
});

// Menambahkan todo
app.post('/todos', (req, res) => {
  const task = req.body.task;
  let sql = 'INSERT INTO todo (task) VALUES (?)';
  db.query(sql, [task], (err, result) => {
    if (err) throw err;
    res.send('Todo berhasil ditambahkan');
  });
});

// Mengupdate todo
app.put('/todos/:id', verifyToken, (req, res) => {
  const id = req.params.id;
  const { task, complete } = req.body;

  let sql = 'UPDATE todo SET task = ?, complete = ? WHERE id = ?';
  db.query(sql, [task, complete, id], (err, result) => {
    if (err) throw err;
    res.send('Todo berhasil diperbarui');
  });
});

// Menghapus todo
app.delete('/todos/:id', (req, res) => {
  const id = req.params.id;
  let sql = 'DELETE FROM todo WHERE id = ?';
  db.query(sql, [id], (err, result) => {
    if (err) throw err;
    res.send('Todo berhasil dihapus');
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));