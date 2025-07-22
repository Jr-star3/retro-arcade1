require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const app = express();

// Configure your email transporter (credentials from .env only)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  xssFilter: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
  originAgentCluster: false,
}));

// CORS configuration
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL || 'https://yourdomain.com'
    : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { 
    error: 'Too many authentication attempts, please try again later',
    type: 'error'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { 
    error: 'Too many requests, please try again later',
    type: 'error'
  }
});

app.use(generalLimiter);
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));
// Serve free games as static files

const path = require('path');
// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return sendResponse(res, 401, 'Access token required', null, 'error');
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return sendResponse(res, 403, 'Invalid or expired token', null, 'error');
    }
    req.user = user;
    next();
  });
};

// Protect free games: require authentication
function redirectIfUnauthenticated(handler) {
  return function(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      return res.redirect('/index.html');
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.redirect('/index.html');
      }
      req.user = user;
      handler(req, res, next);
    });
  };
}


app.get('/games/retro-game.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'retro-game.html'));
});
// Dominoes removed
app.get('/games/chess.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'chess.html'));
});
// Block Merge route removed
app.get('/games/checkers.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'checkers.html'));
});
// Serve Concentration Game (free)
app.get('/games/concentrationgame.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'concentrationgame.html'));
});

// Protect arcade and subscription-related pages: require authentication
app.get(['/public/arcade.html', '/arcade.html'], redirectIfUnauthenticated((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'arcade.html'));
}));
app.get(['/public/subscribe.html', '/subscribe.html'], redirectIfUnauthenticated((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subscribe.html'));
}));
app.get(['/public/success.html', '/success.html'], redirectIfUnauthenticated((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'success.html'));
}));
app.get(['/public/cancel.html', '/cancel.html'], redirectIfUnauthenticated((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cancel.html'));
}));

// Serve premium games only to subscribed users
// Towers of Hanoi is now a free game
app.get('/games/towersofhanoi.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'towersofhanoi.html'));
});

// Premium games: require authentication and subscription
function requireSubscription(handler) {
  return function(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      return res.redirect('/subscribe.html');
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.redirect('/subscribe.html');
      }
      req.user = user;
      // Check subscription in DB
      db.get('SELECT subscribed FROM users WHERE email = ?', [user.email], (err, row) => {
        if (err || !row || !row.subscribed) {
          return res.redirect('/subscribe.html');
        }
        handler(req, res, next);
      });
    });
  };
}

app.get('/games/tictactoe.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'tictactoe.html'));
}));
app.use('/pages', express.static('pages'));

// ...existing code...

app.get('/games/checkers2.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'checkers2.html'));
}));

app.get('/games/pixelpulse.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'pixelpulse.html'));
}));

app.get('/games/prismrelay.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'prismrelay.html'));
}));

app.get('/games/signaldecoder.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'signaldecoder.html'));
}));

app.get('/games/terminallegend.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'terminallegend.html'));
}));

app.get('/games/towersofhanoi2.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'towersofhanoi2.html'));
}));

app.get('/games/wildlogiclab.html', requireSubscription((req, res) => {
  res.sendFile(path.join(__dirname, 'games', 'wildlogiclab.html'));
}));
// ...existing code...
// Removed app.use(express.static('.')) to prevent catch-all static serving

const db = new sqlite3.Database('./users.db');

// Initialize DB with enhanced schema - run synchronously to ensure tables exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    subscribed INTEGER DEFAULT 0,
    stripe_customer_id TEXT,
    email_verified INTEGER DEFAULT 0,
    verification_token TEXT,
    verification_expires INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_login INTEGER,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0
  )`, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('✅ Users table ready');
  });

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    email TEXT,
    token TEXT,
    expires_at INTEGER
  )`, (err) => {
    if (err) console.error('Error creating password_resets table:', err);
    else console.log('✅ Password resets table ready');
  });

  db.run(`CREATE TABLE IF NOT EXISTS game_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    game TEXT,
    score INTEGER,
    level INTEGER,
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    UNIQUE(email, game)
  )`, (err) => {
    if (err) console.error('Error creating game_progress table:', err);
    else console.log('✅ Game progress table ready');
  });

  db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`, (err) => {
    if (err) console.error('Error creating users index:', err);
  });
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token)`, (err) => {
    if (err) console.error('Error creating password_resets index:', err);
  });
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_game_progress_email ON game_progress(email)`, (err) => {
    if (err) console.error('Error creating game_progress index:', err);
  });
});

// Helper function for consistent API responses (matches frontend toast system)
const sendResponse = (res, status, message, data = null, type = 'info') => {
  res.status(status).json({
    message,
    type,
    data,
    timestamp: new Date().toISOString()
  });
};


// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err);
  const isDev = process.env.NODE_ENV === 'development';
  const message = isDev ? err.message : 'Internal server error';
  sendResponse(res, err.status || 500, message, null, 'error');
};

// =============================
// CONFIG ENDPOINT (STRIPE ENABLED)
// =============================
app.get('/config', (req, res) => {
  try {
    res.json({
      stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
      freeAccess: false,
      message: 'Premium features are now live!'
    });
  } catch (error) {
    console.error('Config error:', error);
    res.status(500).json({ error: 'Configuration unavailable' });
  }
});

// Registration with email verification
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`📝 Registration attempt: ${email}`);
    if (!email || !password) {
      return sendResponse(res, 400, 'Email and password are required', null, 'error');
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return sendResponse(res, 400, 'Please enter a valid email address', null, 'error');
    }
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during registration:', err);
        return sendResponse(res, 500, 'Registration failed. Please try again.', null, 'error');
      }
      if (user) {
        console.log(`❌ User already exists: ${email}`);
        return sendResponse(res, 400, 'An account with this email already exists', null, 'error');
      }
      const hash = await bcrypt.hash(password, 10);
      // Generate verification token and expiry (1 hour)
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpires = Date.now() + 3600 * 1000;
      db.run(
        'INSERT INTO users (email, password, email_verified, verification_token, verification_expires) VALUES (?, ?, 0, ?, ?)',
        [email, hash, verificationToken, verificationExpires], function(err) {
        if (err) {
          console.error('Database error during user creation:', err);
          return sendResponse(res, 500, 'Registration failed. Please try again.', null, 'error');
        }
        // Send verification email
        const verifyLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email.html?token=${verificationToken}`;
        const mailOptions = {
          from: process.env.EMAIL_USER || 'motorsportprogression@gmail.com',
          to: email,
          subject: 'Verify your email - Retro Arcade',
          html: `
            <h2>Welcome to Retro Arcade!</h2>
            <p>Click the link below to verify your email address:</p>
            <a href="${verifyLink}" style="background: #00ffff; color: #222; padding: 12px 24px; text-decoration: none; border-radius: 8px;">Verify Email</a>
            <p>This link will expire in 1 hour.</p>
          `
        };
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Email sending error:', error);
            return sendResponse(res, 500, 'Failed to send verification email. Please try again.', null, 'error');
          }
          sendResponse(res, 201, 'Account created! Please check your email to verify your account.', { userId: this.lastID }, 'success');
        });
      });
    });
  } catch (error) {
    console.error('Registration error:', error);
    sendResponse(res, 500, 'Registration failed. Please try again.', null, 'error');
  }
});

// Email verification endpoint (not required for Stripe)
app.get('/verify-email', (req, res) => {
  try {
    const { token: verificationToken } = req.query;
    if (!verificationToken) {
      return sendResponse(res, 400, 'Verification token is required', null, 'error');
    }
    db.get('SELECT * FROM users WHERE verification_token = ? AND verification_expires > ?', 
      [verificationToken, Date.now()], (err, user) => {
      if (err) {
        console.error('Database error during email verification:', err);
        return sendResponse(res, 500, 'Verification failed. Please try again.', null, 'error');
      }
      if (!user) {
        return sendResponse(res, 400, 'Invalid or expired verification token', null, 'error');
      }
      db.run('UPDATE users SET email_verified = 1, verification_token = NULL, verification_expires = NULL WHERE id = ?', 
        [user.id], (err) => {
        if (err) {
          console.error('Error updating user verification:', err);
          return sendResponse(res, 500, 'Verification failed. Please try again.', null, 'error');
        }
        console.log(`✅ Email verified for user: ${user.email}`);
        sendResponse(res, 200, 'Email verified successfully! You can now log in.', null, 'success');
      });
    });
  } catch (error) {
    console.error('Email verification error:', error);
    sendResponse(res, 500, 'Verification failed. Please try again.', null, 'error');
  }
});

// =============================
// LOGIN ENDPOINT (REAL SUBSCRIPTION)
// =============================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`🔐 Login attempt: ${email}`);
    if (!email || !password) {
      return sendResponse(res, 400, 'Email and password are required', null, 'error');
    }
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during login:', err);
        return sendResponse(res, 500, 'Login failed. Please try again.', null, 'error');
      }
      console.log(`🔍 User found in database:`, user ? 'YES' : 'NO');
      if (!user) {
        console.log(`❌ User not found: ${email}`);
        return sendResponse(res, 401, 'Invalid email or password', null, 'error');
      }
      // Require email verification
      if (!user.email_verified) {
        return sendResponse(res, 401, 'Please verify your email before logging in.', null, 'error');
      }
      console.log(`🔍 User found: ${email}, checking password...`);
      const validPassword = await bcrypt.compare(password, user.password);
      console.log(`🔍 Password valid: ${validPassword}`);
      if (!validPassword) {
        return sendResponse(res, 401, 'Invalid email or password', null, 'error');
      }
      db.run('UPDATE users SET last_login = ? WHERE email = ?', 
        [Math.floor(Date.now() / 1000), email]);
      const token = jwt.sign({ email }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '7d' });
      console.log(`✅ Login successful: ${email}`);
      sendResponse(res, 200, 'Welcome back to Retro Arcade!', {
        token,
        subscribed: !!user.subscribed // <-- REAL subscription status
      }, 'success');
    });
  } catch (error) {
    console.error('Login error:', error);
    sendResponse(res, 500, 'Login failed. Please try again.', null, 'error');
  }
});

// Game progress endpoints (unchanged)
app.post('/api/game-progress', authenticateToken, [
  body('game').isLength({ min: 1 }).withMessage('Game name is required'),
  body('score').isInt({ min: 0 }).withMessage('Score must be a positive number'),
  body('level').optional().isInt({ min: 1 }).withMessage('Level must be a positive number')
], (req, res) => {

  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendResponse(res, 400, 'Invalid game progress data', errors.array(), 'error');
    }
    const { game, score, level = 1 } = req.body;
    const email = req.user.email;
    db.run(`
      INSERT OR REPLACE INTO game_progress (email, game, score, level, updated_at) 
      VALUES (?, ?, ?, ?, ?)
    `, [email, game, score, level, Math.floor(Date.now() / 1000)], function(err) {
      if (err) {
        console.error('Error saving game progress:', err);
        return sendResponse(res, 500, 'Failed to save game progress', null, 'error');
      }
      sendResponse(res, 200, 'Game progress saved successfully!', { 
        game, score, level 
      }, 'success');
    });
  } catch (error) {
    console.error('Game progress error:', error);
    sendResponse(res, 500, 'Failed to save game progress', null, 'error');
  }
});

app.get('/api/game-progress', authenticateToken, (req, res) => {
  try {
    const email = req.user.email;
    db.all(
      'SELECT game, score, level, updated_at FROM game_progress WHERE email = ? ORDER BY updated_at DESC',
      [email],
      (err, rows) => {
        if (err) {
          console.error('Error loading game progress:', err);
          return sendResponse(res, 500, 'Failed to load game progress', null, 'error');
        }
        const progress = rows.map(row => ({
          ...row,
          updated_at: new Date(row.updated_at * 1000).toISOString()
        }));
        sendResponse(res, 200, 'Game progress loaded successfully', { progress }, 'success');
      }
    );
  } catch (error) {
    console.error('Game progress error:', error);
    sendResponse(res, 500, 'Failed to load game progress', null, 'error');
  }
});

// Enhanced user profile endpoint (unchanged)
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const email = req.user.email;
    db.get(`
      SELECT 
        email, 
        subscribed, 
        created_at, 
        last_login,
        (SELECT COUNT(DISTINCT game) FROM game_progress WHERE email = ?) as games_played,
        (SELECT MAX(score) FROM game_progress WHERE email = ?) as high_score
      FROM users 
      WHERE email = ?
    `, [email, email, email], (err, user) => {
      if (err) {
        console.error('Error loading user profile:', err);
        return sendResponse(res, 500, 'Failed to load profile', null, 'error');
      }
      if (!user) {
        return sendResponse(res, 404, 'User not found', null, 'error');
      }
      const profile = {
        email: user.email,
        subscribed: !!user.subscribed,
        memberSince: new Date(user.created_at * 1000).toLocaleDateString(),
        lastLogin: user.last_login ? new Date(user.last_login * 1000).toISOString() : null,
        gamesPlayed: user.games_played || 0,
        highScore: user.high_score || 0
      };
      sendResponse(res, 200, 'Profile loaded successfully', profile, 'success');
    });
  } catch (error) {
    console.error('Profile error:', error);
    sendResponse(res, 500, 'Failed to load profile', null, 'error');
  }
});

// =============================
// STRIPE ROUTES (ENABLED)
// =============================
app.post('/create-checkout-session', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return sendResponse(res, 400, 'Email is required', null, 'error');
    }
    let customer;
    const customers = await stripe.customers.list({ email, limit: 1 });
    if (customers.data.length > 0) {
      customer = customers.data[0];
    } else {
      customer = await stripe.customers.create({ email });
      db.run('UPDATE users SET stripe_customer_id = ? WHERE email = ?', [customer.id, email]);
    }
    const subscriptions = await stripe.subscriptions.list({
      customer: customer.id,
      status: 'all',
      limit: 10
    });
    const hasActive = subscriptions.data.some(sub =>
      ['active', 'trialing', 'past_due', 'unpaid'].includes(sub.status)
    );
    if (hasActive) {
      // Keep error response format for already subscribed
      return sendResponse(res, 409, 'You already have an active subscription', { alreadySubscribed: true }, 'info');
    }
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1,
      }],
      mode: 'subscription',
      customer: customer.id,
      success_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/success.html?email=${encodeURIComponent(email)}`,
      cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/subscribe.html`
    });
    // Return session id at top level for Stripe.js compatibility
    res.json({ id: session.id });
  } catch (err) {
    // Log full error for debugging
    console.error('Stripe checkout error:', err);
    // Send more helpful error message in development
    const isDev = process.env.NODE_ENV !== 'production';
    const errorMsg = isDev && err && err.message ? `Stripe error: ${err.message}` : 'Failed to create checkout session. Please try again.';
    sendResponse(res, 500, errorMsg, null, 'error');
  }
});

app.post('/create-customer-portal-session', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return sendResponse(res, 400, 'Email is required', null, 'error');
    }
    const customers = await stripe.customers.list({ email, limit: 1 });
    if (!customers.data.length) {
      return sendResponse(res, 404, 'No subscription found for this account', null, 'error');
    }
    const session = await stripe.billingPortal.sessions.create({
      customer: customers.data[0].id,
      return_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/arcade.html`,
    });
    sendResponse(res, 200, 'Redirecting to subscription management...', { url: session.url }, 'success');
  } catch (err) {
    console.error('Customer portal error:', err);
    sendResponse(res, 500, 'Could not open subscription management. Please contact support.', null, 'error');
  }
});

// Stripe webhook with signature verification and rate limiting
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  message: 'Too many webhook requests, please try again later.'
});

app.post('/webhook', webhookLimiter, bodyParser.raw({type: 'application/json'}), async (req, res) => {
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const email = event.data.object.customer_email;
        db.run('UPDATE users SET subscribed = 1 WHERE email = ?', [email], err => {
          if (err) console.error('DB error updating subscribed (checkout.session.completed):', err);
          else console.log(`✅ Subscription activated for ${email}`);
        });
        break;
      }
      case 'customer.subscription.deleted':
      case 'customer.subscription.canceled': {
        const customerId = event.data.object.customer;
        try {
          const customer = await stripe.customers.retrieve(customerId);
          if (customer.email) {
            db.run('UPDATE users SET subscribed = 0 WHERE email = ?', [customer.email], err => {
              if (err) console.error('DB error updating unsubscribed (subscription deleted):', err);
              else console.log(`❌ Subscription canceled for ${customer.email}`);
            });
          }
        } catch (e) {
          console.error('Error retrieving customer for subscription cancel:', e);
        }
        break;
      }
      case 'invoice.payment_failed': {
        const customerId = event.data.object.customer;
        try {
          const customer = await stripe.customers.retrieve(customerId);
          if (customer.email) {
            // Optionally, set a grace period or notify user
            console.warn(`⚠️ Payment failed for ${customer.email}`);
          }
        } catch (e) {
          console.error('Error retrieving customer for payment failed:', e);
        }
        break;
      }
      case 'customer.subscription.updated': {
        // You can handle plan changes, renewals, etc. here
        const customerId = event.data.object.customer;
        try {
          const customer = await stripe.customers.retrieve(customerId);
          if (customer.email) {
            // Log or update status if needed
            console.log(`ℹ️ Subscription updated for ${customer.email}`);
          }
        } catch (e) {
          console.error('Error retrieving customer for subscription update:', e);
        }
        break;
      }
      default:
        // Log unhandled event types for future reference
        console.log(`Unhandled Stripe event type: ${event.type}`);
    }
    res.json({received: true});
  } catch (err) {
    console.error('Error handling Stripe webhook event:', err);
    res.status(500).send('Webhook handler error');
  }
});

// =============================
// SUBSCRIPTION STATUS ENDPOINT (REAL SUBSCRIPTION)
// =============================
app.get('/api/subscription-status', authenticateToken, (req, res) => {
  const email = req.user.email;
  db.get('SELECT subscribed FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return sendResponse(res, 500, 'Failed to load subscription status', null, 'error');
    }
    sendResponse(res, 200, 'Subscription status loaded', {
      subscribed: !!user.subscribed,
      freeAccess: false
    }, 'success');
  });
});

// =============================
// /me ENDPOINT (REAL SUBSCRIPTION)
// =============================
app.get('/me', authenticateToken, (req, res) => {
  try {
    const email = req.user.email;
    db.get('SELECT email, subscribed, last_login FROM users WHERE email = ?', [email], (err, user) => {
      if (err) {
        console.error('Error in /me endpoint:', err);
        return sendResponse(res, 500, 'Failed to load user information', null, 'error');
      }
      if (!user) {
        return sendResponse(res, 404, 'User not found', null, 'error');
      }
      sendResponse(res, 200, 'User information loaded successfully', { 
        email: user.email, 
        subscribed: !!user.subscribed,
        lastLogin: user.last_login ? new Date(user.last_login * 1000).toISOString() : null
      }, 'success');
    });
  } catch (error) {
    console.error('Error in /me endpoint:', error);
    sendResponse(res, 500, 'Failed to load user information', null, 'error');
  }
});

// Enhanced forgot password endpoint (unchanged)
app.post('/forgot-password', authLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Please enter a valid email address')
], (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendResponse(res, 400, 'Please enter a valid email address', null, 'error');
    }
    const { email } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      if (err) {
        console.error('Database error in forgot password:', err);
        return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
      }
      const responseMessage = 'If your email is registered, you will receive a reset link.';
      if (!user) {
        return sendResponse(res, 200, responseMessage, null, 'info');
      }
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 3600 * 1000;
      db.run('DELETE FROM password_resets WHERE email = ?', [email], (err) => {
        if (err) {
          console.error('Error cleaning up old tokens:', err);
        }
        db.run('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)', 
          [email, token, expiresAt], (err) => {
          if (err) {
            console.error('Error storing reset token:', err);
            return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
          }
          const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/forgot-password.html?token=${token}`;
          const mailOptions = {
            from: process.env.EMAIL_USER || 'motorsportprogression@gmail.com',
            to: email,
            subject: 'Password Reset - Retro Arcade',
            html: `
              <h2>Password Reset Request</h2>
              <p>You requested a password reset for your Retro Arcade account.</p>
              <p>Click the link below to reset your password:</p>
              <a href="${resetLink}" style="background: #00ffff; color: #222; padding: 12px 24px; text-decoration: none; border-radius: 8px;">Reset Password</a>
              <p>This link will expire in 1 hour.</p>
              <p>If you didn't request this reset, you can safely ignore this email.</p>
            `
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Email sending error:', error);
              return sendResponse(res, 500, 'Failed to send reset email. Please try again.', null, 'error');
            }
            sendResponse(res, 200, responseMessage, null, 'success');
          });
        });
      });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
  }
});

// Enhanced reset password endpoint (unchanged)
app.post('/reset-password', [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendResponse(res, 400, 'Please check your password requirements', errors.array(), 'error');
    }
    const { token, password } = req.body;
    db.get('SELECT * FROM password_resets WHERE token = ?', [token], async (err, row) => {
      if (err) {
        console.error('Database error in reset password:', err);
        return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
      }
      if (!row || row.expires_at < Date.now()) {
        return sendResponse(res, 400, 'Invalid or expired reset token. Please request a new password reset.', null, 'error');
      }
      const hash = await bcrypt.hash(password, 12);
      db.run('UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = 0 WHERE email = ?', 
        [hash, row.email], (err) => {
        if (err) {
          console.error('Error updating password:', err);
          return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
        }
        db.run('DELETE FROM password_resets WHERE token = ?', [token], (err) => {
          if (err) {
            console.error('Error cleaning up reset token:', err);
          }
        });
        sendResponse(res, 200, 'Password reset successful! You can now log in with your new password.', null, 'success');
      });
    });
  } catch (error) {
    console.error('Reset password error:', error);
    sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
  }
});

// Apply error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🎮 Retro Arcade Server running on http://localhost:${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default (not secure)'}`);
  console.log(`💳 Stripe: ${process.env.STRIPE_SECRET_KEY ? 'Configured' : 'Not configured'}`);
});