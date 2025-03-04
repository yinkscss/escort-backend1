import pool from './db.js'; // PostgreSQL connection pool

// Admin authentication middleware
export const adminAuth = async (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Not authorized, please log in." });
  }

  // Check if user is an admin
  try {
    const result = await pool.query("SELECT role FROM users WHERE id = $1", [req.session.userId]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      return res.status(403).json({ message: "Access denied, admin only." });
    }

    next(); // If admin, proceed to the next route
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
};


// authMiddleware.js

export const authMiddleware = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();  // Proceed to the next middleware or route handler
};
