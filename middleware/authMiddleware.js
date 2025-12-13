const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    return res.status(403).json({ 
      success: false,
      error: 'No token provided' 
    });
  }

  // Extract token from "Bearer TOKEN"
  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(403).json({ 
      success: false,
      error: 'Invalid token format' 
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ 
        success: false,
        error: 'Unauthorized - Invalid or expired token' 
      });
    }
    
    // Add user ID to request object
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    next();
  });
};

module.exports = verifyToken;
