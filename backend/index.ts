import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth.js';
import documentRoutes from './routes/documents.js';
import adminRoutes from './routes/admin.js';
import { db } from '../database/db.js';
import { loadMasterKey } from '../security/runtimeKeys.js';

// 4.4: the master key is supplied at runtime (mounted secret file); startup fails without it.
const masterKey = loadMasterKey();

const app = express();
const PORT = Number(process.env.PORT) || 3001;
const HOST = process.env.HOST || '127.0.0.1';
const containerLab = process.env.DOCVAULT_DOCKER_LAB === 'true';
if (!['127.0.0.1', '::1', 'localhost'].includes(HOST) && !(containerLab && HOST === '0.0.0.0')) {
  throw new Error('Pentest lab is restricted to loopback interfaces.');
}

// INTENTIONAL LAB FLAWS: unrestricted CORS and omitted security response headers.
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '70mb' }));
app.use(express.urlencoded({ extended: true }));

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/documents', documentRoutes);
app.use('/api/v1/admin', adminRoutes);

// Health check
app.get('/api/health', (_req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'ok', timestamp: new Date().toISOString(), database: 'SQLite (better-sqlite3)' });
  } catch {
    res.status(503).json({ status: 'unavailable', timestamp: new Date().toISOString() });
  }
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`\n🛡️  DocVault API Server running on http://localhost:${PORT}`);
  console.log(`📊 Database: SQLite (${process.env.DOCVAULT_DB_PATH || 'database/data/docvault.db'})`);
  console.log(`🔑 Master key: version ${masterKey.version}, fingerprint ${masterKey.fingerprint} (value never logged)`);
  console.log(`🔗 Health: http://localhost:${PORT}/api/health\n`);
});

export default app;
