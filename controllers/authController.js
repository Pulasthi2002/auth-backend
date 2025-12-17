const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const cloudinary = require('../config/cloudinary');

// Register with profile picture
const register = async (req, res) => {
  try {
    const { name, email, password, profilePicture } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid email format' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Upload image to Cloudinary if provided
    let profilePictureUrl = null;
    if (profilePicture) {
      try {
        const uploadResult = await cloudinary.uploader.upload(profilePicture, {
          folder: 'auth_app_profiles',
          resource_type: 'image',
          transformation: [
            { width: 500, height: 500, crop: 'limit' },
            { quality: 'auto' },
            { fetch_format: 'auto' }
          ]
        });
        profilePictureUrl = uploadResult.secure_url;
      } catch (uploadError) {
        console.error('Cloudinary upload error:', uploadError);
        // Continue with registration even if image upload fails
      }
    }

    const query = 'INSERT INTO users (name, email, password, profile_picture) VALUES (?, ?, ?, ?)';
    
    db.query(query, [name, email, hashedPassword, profilePictureUrl], (err, result) => {
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
        userId: result.insertId,
        profilePicture: profilePictureUrl
      });
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: 'Server error: ' + error.message 
    });
  }
};

// Login (updated to return profile picture)
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required' 
      });
    }

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
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid email or password' 
        });
      }

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
          email: user.email,
          profilePicture: user.profile_picture
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

// Get profile (updated to return profile picture)
const getProfile = (req, res) => {
  try {
    const query = 'SELECT id, name, email, profile_picture, created_at FROM users WHERE id = ?';
    
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
