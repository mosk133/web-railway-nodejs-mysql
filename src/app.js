import express from 'express';
import { pool } from './db.js';
import { PORT } from './config.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // middleware datos de formulario y evitar el error

const SECRET_KEY = process.env.SECRET_KEY || "default_secret_key";

// ruta registro
app.get('/register', (req, res) => {
  res.send(`
    <form action="/register" method="post">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Register</button>
    </form>
  `);
});

// post registro
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.status(201).send('User registered');
  } catch (error) {
    res.status(500).send('Error registering user');
  }
});

// ruta login
app.get('/login', (req, res) => {
  res.send(`
    <form action="/login" method="post">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Login</button>
    </form>
  `);
});

// post login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

  if (result.rows.length === 0) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const user = result.rows[0];
  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });

  // HTTP-only cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Usar HTTPS en producción
    sameSite: 'Lax' // Para evitar problemas de CORS
  });

  res.json({ message: 'Logged in successfully' });
});

const authenticateToken = (req, res, next) => {
  const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: "Access forbidden: No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access forbidden: Invalid token" });
    }

    req.user = user;
    next();
  });
};

// ruta protegida que requiere auth
app.get('/protected', authenticateToken, (req, res) => {
  res.send('This is a protected route');
});

// ruta formulario de edicion de user
app.get('/edit/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

  if (result.rows.length === 0) {
    return res.status(404).send('User not found');
  }

  const user = result.rows[0];
  res.send(`
    <form action="/edit/${userId}" method="post">
      <label for="name">Name:</label>
      <input type="text" id="name" name="name" value="${user.name || ''}" required>
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" value="${user.username}" required>
      <button type="submit">Update</button>
    </form>
  `);
});

// post update de user
app.post('/edit/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const { name, username } = req.body;

  try {
    await pool.query('UPDATE users SET name = $1, username = $2 WHERE id = $3', [name, username, userId]);
    res.send('User updated');
  } catch (error) {
    res.status(500).send('Error updating user');
  }
});

// ruta paginacion
app.get('/', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const result = await pool.query('SELECT * FROM users LIMIT $1 OFFSET $2', [limit, offset]);
    const totalResult = await pool.query('SELECT COUNT(*) as count FROM users');
    const totalUsers = parseInt(totalResult.rows[0].count);
    const totalPages = Math.ceil(totalUsers / limit);

    let html = `
      <h1>User List</h1>
      <ul>
    `;

    result.rows.forEach(user => {
      html += `<li>${user.id}: ${user.username} - ${user.name || 'No Name'}</li>`;
    });

    html += `</ul>`;

    html += `
      <div>
        <span>Page ${page} of ${totalPages}</span>
    `;

    if (page > 1) {
      html += `
        <a href="/?page=${page - 1}&limit=${limit}">Previous</a>
      `;
    }

    if (page < totalPages) {
      html += `
        <a href="/?page=${page + 1}&limit=${limit}">Next</a>
      `;
    }

    html += `</div>`;

    res.send(html);
  } catch (error) {
    res.status(500).send('Error retrieving users');
  }
});

app.get('/ping', async (req, res) => {
  const result = await pool.query(`SELECT 'hello world' as RESULT`);
  res.json(result.rows[0]);
});

// ruta para crear un usuario aleatorio
app.get('/create', async (req, res) => {
  const randomName = Math.random().toString(36).substring(2, 7);
  const randomUsername = `user_${Math.random().toString(36).substring(2, 7)}`;
  const password = Math.random().toString(36).substring(2, 10);
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query('INSERT INTO users (name, username, password) VALUES ($1, $2, $3) RETURNING id', [randomName, randomUsername, hashedPassword]);
    res.json({ message: 'Random user created', userId: result.rows[0].id });
  } catch (error) {
    res.status(500).send('Error creating random user');
  }
});

app.listen(PORT, () => {
  console.log('Server on port', PORT);
});
