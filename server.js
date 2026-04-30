const express    = require('express');
const cookieParser = require('cookie-parser');
const jwt        = require('jsonwebtoken');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Secret used to sign session tokens ──────────────────────────────────────
// Falls back to a random value per-process if JWT_SECRET is not set.
// Set JWT_SECRET in your environment for persistence across restarts.
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

const AUTH_USERNAME = process.env.AUTH_USERNAME;
const AUTH_PASSWORD = process.env.AUTH_PASSWORD;

const COOKIE_NAME = 'artefact_session';
const COOKIE_MAX_AGE = 8 * 60 * 60 * 1000; // 8 hours in ms

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Auth helpers ─────────────────────────────────────────────────────────────
function createToken() {
  return jwt.sign({ auth: true }, JWT_SECRET, { expiresIn: '8h' });
}

function isAuthenticated(req) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return false;
  try {
    jwt.verify(token, JWT_SECRET);
    return true;
  } catch {
    return false;
  }
}

function requireAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  res.redirect('/login');
}

// ── Public routes ─────────────────────────────────────────────────────────────

// Login page
app.get('/login', (req, res) => {
  if (isAuthenticated(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Login API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (username === AUTH_USERNAME && password === AUTH_PASSWORD) {
    const token = createToken();
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge:   COOKIE_MAX_AGE,
    });
    return res.json({ success: true });
  }

  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/login');
});

// ── Protected static files ────────────────────────────────────────────────────
app.use(requireAuth, express.static(path.join(__dirname)));

// Catch-all: redirect unauthenticated requests to /login
app.use((req, res) => {
  if (!isAuthenticated(req)) return res.redirect('/login');
  res.status(404).send('Not found');
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Artefact Slides running on port ${PORT}`);
});
