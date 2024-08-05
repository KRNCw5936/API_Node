const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const SECRET_KEY = 'your_secret_key'; // Ganti ini dengan kunci rahasia Anda

// Middleware untuk memverifikasi token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(403);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Endpoint untuk mendaftarkan pengguna baru
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });
    res.status(201).json(user);
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Endpoint untuk login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`Login attempt with email: ${email}`);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      console.log('User not found');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      console.log('Password does not match');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Endpoint untuk mendapatkan semua pengguna (hanya untuk pengguna yang diautentikasi)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Endpoint untuk mendapatkan pengguna berdasarkan ID (hanya untuk pengguna yang diautentikasi)
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const user = await prisma.user.findUnique({
      where: { id: parseInt(id) },
    });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Endpoint untuk memperbarui pengguna berdasarkan ID (hanya untuk pengguna yang diautentikasi)
app.put('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, password } = req.body;

    const data = { name, email };
    if (password) {
      data.password = bcrypt.hashSync(password, 10);
    }

    const user = await prisma.user.update({
      where: { id: parseInt(id) },
      data,
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Endpoint untuk menghapus pengguna berdasarkan ID (hanya untuk pengguna yang diautentikasi)
app.delete('/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const user = await prisma.user.delete({
      where: { id: parseInt(id) },
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});