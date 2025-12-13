const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

// Register new user
const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid email format' 
      });
    }

    // Check password length
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert user into database
    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    
    db.query(query, [name, email, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ 
            success: false,
            error: 'Email already exists' 
          });
        }
        return res.status(500).json({ 
          success: false,
          error: 'Database error: ' + err.message 
        });
      }
      
      res.status(201).json({ 
        success: true,
        message: 'User registered successfully',
        userId: result.insertId
      });
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Server error: ' + error.message 
    });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required' 
      });
    }

    // Find user by email
    const query = 'SELECT * FROM users WHERE email = ?';
    
    db.query(query, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ 
          success: false,
          error: 'Database error: ' + err.message 
        });
      }
      
      if (results.length === 0) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid email or password' 
        });
      }

      const user = results[0];

      // Compare passwords
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid email or password' 
        });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email }, 
        process.env.JWT_SECRET, 
        { expiresIn: '7d' }
      );

      res.status(200).json({
        success: true,
        message: 'Login successful',
        token: token,
        user: { 
          id: user.id, 
          name: user.name, 
          email: user.email 
        }
      });
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Server error: ' + error.message 
    });
  }
};

// Get user profile
const getProfile = (req, res) => {
  try {
    const query = 'SELECT id, name, email, created_at FROM users WHERE id = ?';
    
    db.query(query, [req.userId], (err, results) => {
      if (err) {
        return res.status(500).json({ 
          success: false,
          error: 'Database error: ' + err.message 
        });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ 
          success: false,
          error: 'User not found' 
        });
      }

      res.status(200).json({ 
        success: true,
        user: results[0] 
      });
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Server error: ' + error.message 
    });
  }
};

module.exports = { register, login, getProfile };
