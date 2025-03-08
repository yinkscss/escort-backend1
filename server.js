import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs"; // For hashing passwords
import pool from "./db.js"; // PostgreSQL connection pool
import dotenv from "dotenv";
import { authMiddleware } from './authMiddleware.js';  // Adjust the path if necessary
import { adminAuth } from './authMiddleware.js'; // Import admin authentication middleware
import multer from 'multer'; // For handling image uploads
import path from 'path';
import morgan from 'morgan';
import cors from 'cors';
import { fileURLToPath } from 'url'; // Add this import
import { dirname } from 'path'; // Add this import
import MongoStore from 'connect-mongo';

dotenv.config();

const app = express();

// Get the directory name of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


// CORS configuration
app.use(cors({
  origin: [
    'https://sophisticated-service-space.vercel.app',
    'https://escort-backend1.onrender.com',
    'https://www.seventhveilescortservice.pro' // ADD NEW DOMAIN
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Cookie',
    'Cache-Control' // ADD MISSING HEADER
  ]
}));



// Add after CORS config
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://sophisticated-service-space.vercel.app',
    'https://escort-backend1.onrender.com',
     'https://www.seventhveilescortservice.pro',
    'https://www.seventhveilescortservice.pro' // ADD NEW DOMAIN
  ];
  
  if (allowedOrigins.includes(req.headers.origin)) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Expose-Headers', 'Set-Cookie');
  next();
});

// Vary Header
app.use((req, res, next) => {
  res.header('Vary', 'Origin');
  next();
});

app.options('*', cors({
  origin: [
    'https://sophisticated-service-space.vercel.app',
    'https://escort-backend1.onrender.com', 'https://www.seventhveilescortservice.pro',
    'https://www.seventhveilescortservice.pro'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization', 
    'X-Requested-With',
    'Accept',
    'Cookie',
    'Cache-Control'
  ]
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));


app.set('trust proxy', 1);  // Essential for Render's reverse proxy


// Updated session configuration
app.use(session({
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    dbName: 'seventhveil',
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'interval',
    autoRemoveInterval: 60,
    crypto: {
      secret: process.env.SESSION_SECRET
    }
  }),
  name: 'escort_session',
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: false,
  proxy: true,
  rolling: true,
  genid: () => crypto.randomUUID(),
  unset: 'destroy',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'none',
    maxAge: 14 * 24 * 60 * 60 * 1000,
    domain: process.env.NODE_ENV === 'production' 
      ? '.onrender.com'
      : undefined
  }
}));

app.use((req, res, next) => {
  console.log('Session Verification:');
  console.log('Session ID:', req.sessionID);
  console.log('Session Exists:', !!req.session);
  console.log('User ID in Session:', req.session?.userId);
  console.log('Cookie Header:', req.headers.cookie);
  next();
});

// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Define the folder for storing images
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Use current timestamp as file name
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit for images
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files (jpeg, jpg, png, gif) are allowed.'));
    }
  }
});

//initialize Database

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS escrows (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        age INTEGER NOT NULL,
        bio TEXT,
        location VARCHAR(255),
        rates VARCHAR(100),
        availability VARCHAR(255),
        status VARCHAR(50) DEFAULT 'active',
        image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        escort_id INTEGER REFERENCES escrows(id),
        booking_date TIMESTAMP NOT NULL,
        duration VARCHAR(50) NOT NULL,
        location VARCHAR(255) NOT NULL,
        service VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        special_requests TEXT,
        contact_name VARCHAR(100),
        contact_email VARCHAR(255),
        contact_phone VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Database tables initialized');
  } catch (err) {
    console.error('❌ Database initialization error:', err);
    process.exit(1);
  }
}

// Call this before app.listen()
await initDB();


// Routes

//Base Routes

app.get("/", (req, res) => {
  res.status(200).json({
    status: "active",
    message: "Escrow Service API"
  });
});

// Signup Route



app.post("/auth/signup", async (req, res) => {
res.header('Access-Control-Allow-Origin', 'https://sophisticated-service-space.vercel.app');

  const { username, email, password } = req.body;

  // Validate input
  if (!username || !email || !password) {
    return res.status(400).json({ message: "Please fill all fields." });
  }

  try {
    // Check if user already exists
    const checkUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const newUser = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
      [username, email, hashedPassword]
    );

    res.status(201).json({
      message: "User created successfully",
      user: newUser.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login Route
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    // Find user with error handling
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    
    if (!user.rows.length) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Validate password
    const isValid = await bcrypt.compare(password, user.rows[0].password);
    if (!isValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Create new session
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ message: "Session error" });
      }

      // Set session data
      req.session.userId = user.rows[0].id;
      req.session.username = user.rows[0].username;
      req.session.role = user.rows[0].role;

      // Force session save
      req.session.save(err => {
        if (err) {
          console.error('Session save error:', err);
          return res.status(500).json({ message: "Session error" });
        }

        // Verify session in store
        req.sessionStore.get(req.sessionID, (storeErr, session) => {
          console.log('Stored session:', session);
          res.status(200).json({
            message: "Login successful",
            user: {
              id: user.rows[0].id,
              username: user.rows[0].username,
              role: user.rows[0].role
            }
          });
        });
      });
    });
  } catch (err) {
    console.error('Login route error:', err);
    res.status(500).json({ 
      message: "Server error",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Get the user details

app.get("/bookings/user", async (req, res) => {
  // Disable caching
   res.header("Cache-Control", "no-store, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  const userId = req.session.userId; // Get the user ID from the session

  if (!userId) {
    return res.status(401).json({ message: "You must be logged in to view bookings." });
  }

  try {
    // Fetch bookings based on userId
    const result = await pool.query(
      "SELECT * FROM bookings WHERE client_id = $1 ORDER BY booking_date DESC",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(200).json([]);  // No bookings found, return an empty array
    }

    res.status(200).json(result.rows);  // Return the bookings data to the frontend
    // console.log(result.rows)
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching bookings." });
  }
});

// view escort details 
app.get('/bookings/:id', authMiddleware, async (req, res) => {

const { id } = req.params;

const userId = req.session.userId;

try {

// For users, only let them see their own bookings for security reasons
const bookingQuery = await pool.query(
  "SELECT * FROM bookings WHERE id = $1 AND client_id = $2",
  [id, userId]
);
if (bookingQuery.rows.length === 0) {
  return res.status(404).json({ message: "Booking not found or not authorized to view." });
}
return res.status(200).json(bookingQuery.rows[0]);
} catch (err) {

console.error(err);
return res.status(500).json({ message: "Error fetching booking details." });
}

});

app.put('/bookings/:id/cancel', authMiddleware, async (req, res) => {

const { id } = req.params;

const userId = req.session.userId;

try {

// First check if the booking belongs to the user
const checkBooking = await pool.query(
  "SELECT * FROM bookings WHERE id = $1 AND client_id = $2",
  [id, userId]
);
if (checkBooking.rows.length === 0) {
  return res.status(403).json({ message: "You can only cancel your own bookings" });
}
// Now update the booking status
const result = await pool.query(
  "UPDATE bookings SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *",
  [id]
);
res.status(200).json({
  message: "Booking cancelled successfully",
  booking: result.rows[0]
});
} catch (err) {

    console.error("Error cancelling booking:", err.message, err.stack);
    res.status(500).json({ message: "Error cancelling booking" });

}

});

// Get all escort profiles (Admin Only)
app.get("/admin/escorts", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM escrows");
    res.status(200).json({ escorts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error retrieving escort profiles." });
  }
});

app.get("/escorts", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM escrows");
    res.status(200).json({ escorts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error retrieving escort profiles." });
  }
});

// Update escort profile (Admin Only)
app.put("/admin/escorts/:id", adminAuth, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, age, bio, location, rates, availability } = req.body;
  const imageUrl = req.file ? req.file.filename : null; // Get new image if uploaded

  try {
    const result = await pool.query(
      "UPDATE escrows SET name = $1, age = $2, bio = $3, location = $4, rates = $5, availability = $6, image = $7 WHERE id = $8 RETURNING *",
      [name, age, bio, location, rates, availability, imageUrl, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Escort not found." });
    }

    res.status(200).json({
      message: "Escort profile updated successfully",
      escort: result.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error updating escort profile." });
  }
});

// Delete escort profile (Admin Only)
app.delete("/admin/escorts/:id", adminAuth, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query("DELETE FROM escrows WHERE id = $1 RETURNING *", [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Escort not found." });
    }

    res.status(200).json({
      message: "Escort profile deleted successfully"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error deleting escort profile." });
  }
});

// Logout Route (destroy session)
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Failed to logout" });
    }
    res.status(200).json({ message: "Logged out successfully" });
  });
});

// Check session route (to verify if user is logged in)
app.get("/auth/session", (req, res) => {
  // Force no caching
  res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.header('Pragma', 'no-cache');
  res.header('Expires', '0');

  if (!req.session?.userId) {
    // Explicitly destroy invalid session
    req.session.destroy(() => {
      res.clearCookie('escort_session', {
        domain: process.env.NODE_ENV === 'production' 
          ? '.onrender.com' 
          : 'localhost',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
      });
      return res.status(401).json({ 
        isAuthenticated: false,
        message: "Not authenticated" 
      });
    });
    return;
  }

  // Return minimal session info
  res.status(200).json({
    isAuthenticated: true,
    user: {
      id: req.session.userId,
      username: req.session.username,
      role: req.session.role
    }
  });
});


// Client creates a booking request
app.post("/booking", async (req, res) => {
  const {
    escortId,
    bookingDate,
    duration,
    location,
    service,
    specialRequests,
    contactInfo,
  } = req.body;

  const clientId = req.session.userId; // Client is identified by their session

  // Validate required fields
  if (!escortId || !bookingDate || !duration || !location || !service || !contactInfo) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // Ensure the user is logged in
  if (!clientId) {
    return res.status(401).json({ message: "You must be logged in to book" });
  }

  try {
    // Insert the booking with all fields
    const result = await pool.query(
      `INSERT INTO bookings (
        client_id,
        escort_id,
        booking_date,
        duration,
        location,
        service,
        special_requests,
        contact_name,
        contact_email,
        contact_phone,
        status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [
        clientId, // client_id
        escortId, // escort_id
        bookingDate, // booking_date
        duration, // duration
        location, // location
        service, // service
        specialRequests, // special_requests
        contactInfo.name, // contact_name
        contactInfo.email, // contact_email
        contactInfo.phone, // contact_phone
        "pending", // status
      ]
    );

    res.status(201).json({
      message: "Booking request created successfully",
      booking: result.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error creating booking request" });
  }
});

app.get('/admin/bookings', adminAuth, async (req, res) => {

try {

const result = await pool.query(
  "SELECT * FROM bookings ORDER BY booking_date DESC"
);
res.status(200).json(result.rows);
} catch (err) {

console.error(err);
res.status(500).json({ message: 'Error fetching admin bookings' });
}

});

// Accept Booking 

app.put('/admin/booking/accept/:id', adminAuth, async (req, res) => {
  const { id } = req.params;

  console.log(`Received request to accept booking with ID: ${id}`);

  try {
    // Check if booking exists and is pending
    const checkBooking = await pool.query(
      "SELECT * FROM bookings WHERE id = $1 AND status = 'pending'",
      [id]
    );

    if (checkBooking.rows.length === 0) {
      console.log(`No pending booking found for ID: ${id}`);
      return res.status(400).json({ message: "Booking not found or already processed" });
    }

    // Proceed to update the booking status
    const result = await pool.query(
      "UPDATE bookings SET status = 'accepted', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      console.log(`Booking with ID ${id} was not updated. The booking might not exist.`);
      return res.status(404).json({ message: "Booking not found" });
    }

    console.log(`Booking with ID ${id} successfully accepted`);
    res.status(200).json({
      message: "Booking accepted successfully",
      booking: result.rows[0]
    });

  } catch (err) {
    console.error("Error accepting booking:", err);
    res.status(500).json({ message: "Error accepting booking" });
  }
});



// Get total number of escort profiles
app.get("/admin/dashboard/escort-stats", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*) AS total_escorts FROM escrows");
    res.status(200).json({ total_escorts: result.rows[0].total_escorts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching escort stats" });
  }
});

//Decline Booking

app.put('/admin/booking/decline/:id', adminAuth, async (req, res) => {

const { id } = req.params;

try {

const result = await pool.query(
  "UPDATE bookings SET status = 'declined', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *",
  [id]
);
if (result.rows.length === 0) {
  return res.status(404).json({ message: "Booking not found" });
}
res.status(200).json({
  message: "Booking declined successfully",
  booking: result.rows[0]
});
} catch (err) {

console.error(err);
res.status(500).json({ message: "Error declining booking" });
}

});
// Get total number of bookings
app.get("/admin/dashboard/booking-stats", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*) AS total_bookings FROM bookings");
    res.status(200).json({ total_bookings: result.rows[0].total_bookings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching booking stats" });
  }
});

// Get total number of accepted and declined bookings
app.get("/admin/dashboard/booking-status-stats", adminAuth, async (req, res) => {
  try {
    const acceptedResult = await pool.query("SELECT COUNT(*) AS accepted FROM bookings WHERE status = 'accepted'");
    const declinedResult = await pool.query("SELECT COUNT(*) AS declined FROM bookings WHERE status = 'declined'");

    res.status(200).json({
      accepted: acceptedResult.rows[0].accepted,
      declined: declinedResult.rows[0].declined
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching booking status stats" });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});


// Start the server
const PORT = process.env.PORT || 5000;


app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
