import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables

const { Pool } = pkg;

// Configure the database connection pool
const pool = new Pool({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  database: process.env.PG_DATABASE
});

// Function to test the connection
pool.connect()
  .then(client => {
    console.log('✅ Connected to PostgreSQL');
    client.release();
  })
  .catch(err => console.error('❌ PostgreSQL connection error:', err));

export default pool;
