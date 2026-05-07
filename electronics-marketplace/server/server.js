const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_key';
const DB_PATH = process.env.DB_PATH || './marketplace.db';

// Middleware
app.use(cors());
app.use(express.json());

// Initialize database
const db = new Database(DB_PATH);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    old_price REAL,
    category TEXT,
    brand TEXT,
    condition TEXT DEFAULT 'new',
    image_url TEXT,
    stock INTEGER DEFAULT 10,
    rating REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    total_price REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    UNIQUE(user_id, product_id)
  );
`);

// Seed products if table is empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (productCount.count === 0) {
  const insertProduct = db.prepare(`
    INSERT INTO products (name, description, price, old_price, category, brand, condition, rating, stock)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const products = [
    ['MacBook Air M2', '13.6" Liquid Retina display, 8GB RAM, 256GB SSD, Apple M2 chip', 1099.99, 1249.99, 'Laptops', 'Apple', 'new', 4.8, 15],
    ['Samsung Galaxy S24', '6.2" Dynamic AMOLED 2X, 128GB storage, 8GB RAM', 799.99, 859.99, 'Smartphones', 'Samsung', 'new', 4.7, 25],
    ['Sony WH-1000XM5', 'Wireless noise-cancelling headphones, 30h battery life', 348.00, 399.99, 'Audio', 'Sony', 'new', 4.9, 30],
    ['DJI Mini 4 Pro', '4K HDR video, 34min flight time, under 249g', 759.00, null, 'Drones', 'DJI', 'new', 4.6, 10],
    ['Logitech MX Master 3S', 'Wireless ergonomic mouse, 8K DPI, USB-C', 99.99, 109.99, 'Accessories', 'Logitech', 'new', 4.7, 40],
    ['Apple Watch Series 9', '45mm, GPS, Always-On Retina display', 429.00, 479.00, 'Wearables', 'Apple', 'new', 4.5, 20],
    ['Refurbished iPad Pro', '11" Liquid Retina, M1 chip, 128GB', 639.00, 799.00, 'Laptops', 'Apple', 'refurbished', 4.4, 5],
    ['Samsung Galaxy Buds2 Pro', 'Hi-Fi 24-bit audio, Intelligent ANC', 189.99, 229.99, 'Audio', 'Samsung', 'new', 4.6, 35],
    ['Dell XPS 15', '15.6" OLED, Intel i7-13700H, 16GB RAM, 512GB SSD', 1299.99, 1499.99, 'Laptops', 'Dell', 'new', 4.5, 8],
    ['iPhone 15 Pro', '6.1" Super Retina XDR, A17 Pro chip, 256GB', 1099.00, 1199.00, 'Smartphones', 'Apple', 'new', 4.8, 18],
    ['Bose QuietComfort Earbuds II', 'World-class noise cancelling, personalized sound', 279.00, 299.00, 'Audio', 'Bose', 'new', 4.4, 22],
    ['Nintendo Switch OLED', '7" OLED screen, 64GB storage, enhanced audio', 349.99, null, 'Gaming', 'Nintendo', 'new', 4.9, 12]
  ];

  const insertMany = db.transaction((products) => {
    for (const product of products) {
      insertProduct.run(...product);
    }
  });

  insertMany(products);
  console.log('Database seeded with products');
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, full_name } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = db.prepare(
      'INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)'
    ).run(username, email, hashedPassword, full_name || '');

    // Generate token
    const token = jwt.sign(
      { id: result.lastInsertRowid, username, email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: result.lastInsertRowid,
        username,
        email,
        full_name: full_name || ''
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  try {
    const user = db.prepare('SELECT id, username, email, full_name, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ PRODUCT ROUTES ============

// Get all products with optional filters
app.get('/api/products', (req, res) => {
  try {
    const { category, brand, condition, min_price, max_price, search } = req.query;
    
    let query = 'SELECT * FROM products WHERE 1=1';
    const params = [];

    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }
    if (brand) {
      query += ' AND brand = ?';
      params.push(brand);
    }
    if (condition) {
      query += ' AND condition = ?';
      params.push(condition);
    }
    if (min_price) {
      query += ' AND price >= ?';
      params.push(parseFloat(min_price));
    }
    if (max_price) {
      query += ' AND price <= ?';
      params.push(parseFloat(max_price));
    }
    if (search) {
      query += ' AND (name LIKE ? OR description LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY created_at DESC';

    const products = db.prepare(query).all(...params);
    res.json({ products });
  } catch (error) {
    console.error('Products fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single product
app.get('/api/products/:id', (req, res) => {
  try {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json({ product });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ CART ROUTES (Protected) ============

// Get user's cart
app.get('/api/cart', authenticateToken, (req, res) => {
  try {
    const cartItems = db.prepare(`
      SELECT c.id as cart_id, c.quantity, p.*
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `).all(req.user.id);
    res.json({ cart: cartItems });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add to cart
app.post('/api/cart', authenticateToken, (req, res) => {
  try {
    const { product_id, quantity = 1 } = req.body;

    // Check if product exists
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Check if already in cart
    const existing = db.prepare('SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?').get(req.user.id, product_id);
    
    if (existing) {
      db.prepare('UPDATE cart_items SET quantity = quantity + ? WHERE user_id = ? AND product_id = ?')
        .run(quantity, req.user.id, product_id);
    } else {
      db.prepare('INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)')
        .run(req.user.id, product_id, quantity);
    }

    res.json({ message: 'Product added to cart' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove from cart
app.delete('/api/cart/:productId', authenticateToken, (req, res) => {
  try {
    db.prepare('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?')
      .run(req.user.id, req.params.productId);
    res.json({ message: 'Product removed from cart' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ ORDER ROUTES (Protected) ============

// Place order (from cart)
app.post('/api/orders', authenticateToken, (req, res) => {
  try {
    const cartItems = db.prepare(`
      SELECT c.quantity, p.id, p.price, p.stock
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `).all(req.user.id);

    if (cartItems.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const insertOrder = db.prepare(
      'INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)'
    );

    const placeOrder = db.transaction(() => {
      for (const item of cartItems) {
        if (item.stock < item.quantity) {
          throw new Error(`Insufficient stock for product ID ${item.id}`);
        }
        insertOrder.run(req.user.id, item.id, item.quantity, item.price * item.quantity);
        db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?').run(item.quantity, item.id);
      }
      db.prepare('DELETE FROM cart_items WHERE user_id = ?').run(req.user.id);
    });

    placeOrder();
    res.json({ message: 'Order placed successfully' });
  } catch (error) {
    console.error('Order error:', error);
    res.status(400).json({ error: error.message || 'Failed to place order' });
  }
});

// Get user's orders
app.get('/api/orders', authenticateToken, (req, res) => {
  try {
    const orders = db.prepare(`
      SELECT o.*, p.name as product_name, p.image_url
      FROM orders o
      JOIN products p ON o.product_id = p.id
      WHERE o.user_id = ?
      ORDER BY o.created_at DESC
    `).all(req.user.id);
    res.json({ orders });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Electronics Marketplace API running on http://localhost:${PORT}`);
  console.log(`📦 Database: ${DB_PATH}`);
});