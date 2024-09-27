const authMiddleware = (req, res, next) => {
    const token = req.cookies.token; // Get token from cookies
  
    if (!token) {
      return res.status(401).json({ msg: 'No token, authorization denied' });
    }
  
    try {
      const decoded = jwt.verify(token, 'secret'); // Verify token with your secret
      req.user = decoded.user; // Add user from payload
      next(); // Move to the next middleware or route handler
    } catch (err) {
      res.status(401).json({ msg: 'Token is not valid' });
    }
  };