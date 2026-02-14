// WARDKEY Server — v1.0.0
// SECURITY: Ensure JWT_SECRET and ADMIN_SECRET are strong random values in production
// Never use development defaults in production environments
require('dotenv').config();

// ═══════ STARTUP CHECKS ═══════
if (!process.env.JWT_SECRET) {
  console.error('\n  ❌ FATAL: JWT_SECRET environment variable is required.');
  console.error('  Set it in your .env file or environment before starting the server.\n');
  process.exit(1);
}

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const authRoutes = require('./routes/auth');
const vaultRoutes = require('./routes/vault');
const shareRoutes = require('./routes/share');
const aliasRoutes = require('./routes/aliases');
const adminRoutes = require('./routes/admin');
const { initDB } = require('./models/db');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (required for Railway/Render reverse proxy)
app.set('trust proxy', 1);

// ═══════ SECURITY ═══════
app.use(helmet({
  contentSecurityPolicy: false, // Disabled — this is a JSON API, CSP only applies to document responses
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));

// Admin CORS — restricted to configured admin origin (all admin endpoints require JWT auth)
app.use('/api/admin', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.ADMIN_ORIGIN || 'https://wardkey.io');
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
// Also allow www variants automatically
const allOrigins = [...new Set(allowedOrigins.flatMap(o => {
  const u = new URL(o);
  return u.hostname.startsWith('www.')
    ? [o, o.replace('://www.', '://')]
    : [o, o.replace('://', '://www.')];
}))];
app.use(cors({
  origin: allOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ═══════ RATE LIMITING ═══════
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many auth attempts. Please try again in 15 minutes.' }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/2fa/verify-login', authLimiter);

const shareLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many share requests. Please try again later.' }
});
app.use('/api/share/', shareLimiter);

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many admin login attempts. Please try again in 15 minutes.' }
});
app.use('/api/admin/login', adminLoginLimiter);

// ═══════ MIDDLEWARE ═══════
app.use(express.json({ limit: '10mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// CSRF protection for non-GET requests from browsers
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.headers.origin || req.headers.referer;
  const extOrigin = process.env.EXTENSION_ID ? `chrome-extension://${process.env.EXTENSION_ID}` : null;
  const allowed = [process.env.APP_ORIGIN || 'https://wardkey.io', extOrigin].filter(Boolean);
  if (!origin) {
    // Allow API clients with valid Bearer token (extension, scripts)
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ') && authHeader.length > 20) {
      // Token will be validated by authenticate middleware downstream
      // Only skip CSRF for requests that look like real API calls
      try {
        const jwt = require('jsonwebtoken');
        jwt.verify(authHeader.slice(7), process.env.JWT_SECRET, { algorithms: ['HS256'] });
        return next();
      } catch { /* invalid token — fall through to require Origin */ }
    }
    return res.status(403).json({ error: 'Origin header required' });
  }
  if (!allowed.some(a => origin === a)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

// ═══════ STATIC FILES ═══════
app.use(express.static(path.join(__dirname, 'public')));

// ═══════ API ROUTES ═══════
app.use('/api/auth', authRoutes);
app.use('/api/vault', vaultRoutes);
app.use('/api/share', shareRoutes);
app.use('/api/aliases', aliasRoutes);
app.use('/api/admin', adminRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Root — API info
app.get('/', (req, res) => {
  res.json({ name: 'WARDKEY API', version: '1.0.0', status: 'ok' });
});

// Catch-all for unknown routes
app.get('*', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ═══════ ERROR HANDLER ═══════
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// ═══════ START ═══════
// Ensure data directory exists
const dataDir = path.dirname(process.env.DB_PATH || './data/wardkey.db');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

initDB();

app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║     🔐 WARDKEY Server v1.0.0        ║
  ║     Port: ${String(PORT).padEnd(27)}║
  ║     Mode: ${(process.env.NODE_ENV || 'dev').padEnd(27)}║
  ╚══════════════════════════════════════╝
  `);
});

module.exports = app;
