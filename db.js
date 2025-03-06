import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pkg;

const productionConfig = {
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
};

const devConfig = {
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  database: process.env.PG_DATABASE
};

const pool = new Pool(process.env.NODE_ENV === 'production' ? productionConfig : devConfig);

// Enhanced connection test
pool.on('connect', () => console.log('✅ PostgreSQL connection established'));
pool.on('error', err => console.error('❌ PostgreSQL client error:', err));

export default pool;