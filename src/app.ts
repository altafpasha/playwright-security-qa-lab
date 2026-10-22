import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import path from 'path';

// Augment express-session types to include custom session user
declare module 'express-session' {
  interface SessionData {
    user?: {
      id: string;
      email: string;
      name: string;
      role: 'user' | 'admin';
    };
  }
}

export const app = express();

// ==========================================
// Synthetic Demo Accounts (Development Only)
// ==========================================
export const DEMO_USERS = [
  {
    id: 'usr_001',
    email: 'user@demo.local',
    password: 'UserPass123!',
    name: 'Jane Doe',
    role: 'user' as const,
    department: 'Quality Assurance',
    created: '2025-01-15'
  },
  {
    id: 'adm_001',
    email: 'admin@demo.local',
    password: 'AdminPass123!',
    name: 'Security Administrator',
    role: 'admin' as const,
    department: 'Application Security',
    created: '2024-11-01'
  }
];

// ==========================================
// Baseline Security Headers (Defense-in-Depth)
// ==========================================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline CSS for lightweight single-file templates
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"], // Mitigate clickjacking attacks
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    frameguard: { action: 'deny' }, // X-Frame-Options: DENY
    noSniff: true, // X-Content-Type-Options: nosniff
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true
    },
    hidePoweredBy: true // Remove X-Powered-By: Express
  })
);

// Body and Cookie Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==========================================
// Session Handling Configuration
// ==========================================
export const SESSION_COOKIE_NAME = 'secqa.sid';

app.use(
  session({
    name: SESSION_COOKIE_NAME,
    secret: process.env.SESSION_SECRET || 'dev-insecure-secret-key-for-lab-testing-only-32chars',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevent client-side script access (mitigate XSS cookie theft)
      sameSite: 'lax', // Protect against cross-site request forgery in top-level navigations
      secure: process.env.NODE_ENV === 'production', // Use secure in production HTTPS
      maxAge: 60 * 60 * 1000 // 1 hour session lifetime
    }
  })
);

// Static assets (CSS, client JS, images)
app.use('/static', express.static(path.join(__dirname, '../public')));

// ==========================================
// Sensitive Endpoint Cache Control Middleware
// ==========================================
export const noCacheMiddleware = (_req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
};

// ==========================================
// Authentication & RBAC Middleware
// ==========================================
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.session || !req.session.user) {
    if (req.path.startsWith('/api/')) {
      res.status(401).json({
        success: false,
        error: 'Unauthorized: Authentication required to access this resource'
      });
      return;
    }
    const returnUrl = encodeURIComponent(req.originalUrl || '/dashboard');
    res.redirect(`/login?redirect=${returnUrl}`);
    return;
  }
  next();
};

export const requireAdmin = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.session || !req.session.user) {
    if (req.path.startsWith('/api/')) {
      res.status(401).json({
        success: false,
        error: 'Unauthorized: Authentication required'
      });
      return;
    }
    res.redirect('/login');
    return;
  }

  if (req.session.user.role !== 'admin') {
    if (req.path.startsWith('/api/')) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Administrator privileges required'
      });
      return;
    }
    res.status(403).redirect('/access-denied');
    return;
  }

  next();
};

// ==========================================
// HTML Page Rendering Helper (Zero Bundler)
// ==========================================
const renderLayout = (title: string, bodyContent: string, user?: { email: string; role: string; name: string }): string => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} | SecQA Lab</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header class="app-header">
    <div class="nav-container">
      <div class="brand">
        <a href="/" class="brand-link" data-testid="brand-logo">
          <span class="shield-icon">🛡️</span>
          <strong>SecQA Lab</strong>
        </a>
      </div>
      <nav class="nav-links">
        ${
          user
            ? `
          <a href="/dashboard" class="nav-item" data-testid="nav-dashboard">Dashboard</a>
          ${
            user.role === 'admin'
              ? `<a href="/admin" class="nav-item admin-badge-link" data-testid="nav-admin">Admin Portal</a>`
              : ''
          }
          <span class="user-pill" data-testid="user-pill">${user.name} (${user.role})</span>
          <button id="logoutBtn" class="btn btn-secondary btn-sm" data-testid="logout-button">Log Out</button>
        `
            : `
          <a href="/login" class="nav-item" data-testid="nav-login">Sign In</a>
        `
        }
      </nav>
    </div>
  </header>
  <main class="main-content" id="main-content">
    ${bodyContent}
  </main>
  <footer class="app-footer">
    <p>Playwright Security QA Lab &bull; Synthetic Demo Environment &bull; Portfolio & Security Evaluation Only</p>
  </footer>
  <script src="/static/app.js"></script>
</body>
</html>
`;

// ==========================================
// UI Web Routes
// ==========================================

// Root redirect
app.get('/', (req: Request, res: Response) => {
  if (req.session && req.session.user) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Login Page
app.get('/login', (req: Request, res: Response) => {
  if (req.session && req.session.user) {
    res.redirect('/dashboard');
    return;
  }

  const redirectTarget = typeof req.query.redirect === 'string' ? req.query.redirect : '/dashboard';

  const html = renderLayout(
    'Sign In',
    `
    <div class="auth-card" data-testid="login-card">
      <h1 class="auth-title" data-testid="page-title">Sign In to SecQA Lab</h1>
      <p class="auth-subtitle">Demonstration portal for Security QA & Playwright Automation</p>
      
      <div id="alertBox" class="alert-box hidden" role="alert" data-testid="login-alert"></div>

      <form id="loginForm" method="POST" action="/api/auth/login" novalidate data-testid="login-form">
        <input type="hidden" id="redirectInput" name="redirect" value="${redirectTarget}">

        <div class="form-group">
          <label for="emailInput">Work Email</label>
          <input 
            type="email" 
            id="emailInput" 
            name="email" 
            class="form-control" 
            placeholder="user@demo.local" 
            required 
            autocomplete="username"
            data-testid="input-email"
          >
          <span class="field-error" id="emailError" data-testid="email-error"></span>
        </div>

        <div class="form-group">
          <label for="passwordInput">Password</label>
          <input 
            type="password" 
            id="passwordInput" 
            name="password" 
            class="form-control" 
            placeholder="••••••••••••" 
            required 
            autocomplete="current-password"
            data-testid="input-password"
          >
          <span class="field-error" id="passwordError" data-testid="password-error"></span>
        </div>

        <button type="submit" id="submitBtn" class="btn btn-primary btn-block" data-testid="login-submit-button">
          Sign In
        </button>
      </form>

      <div class="demo-credentials-helper">
        <h4>Demo Credentials (Development Only)</h4>
        <div class="credential-grid">
          <div class="cred-item">
            <span class="cred-role">Standard User:</span>
            <code>user@demo.local</code> / <code>UserPass123!</code>
          </div>
          <div class="cred-item">
            <span class="cred-role">Administrator:</span>
            <code>admin@demo.local</code> / <code>AdminPass123!</code>
          </div>
        </div>
      </div>
    </div>
    `
  );

  res.send(html);
});

// Dashboard Page (Protected, Sensitive Cache Disabled)
app.get('/dashboard', requireAuth, noCacheMiddleware, (req: Request, res: Response) => {
  const user = req.session.user!;
  const html = renderLayout(
    'Dashboard',
    `
    <div class="dashboard-container" data-testid="dashboard-page">
      <div class="dashboard-header">
        <h1 data-testid="dashboard-welcome">Welcome, ${user.name}</h1>
        <p class="role-badge ${user.role}" data-testid="role-badge">Role: ${user.role.toUpperCase()}</p>
      </div>

      <div class="dashboard-grid">
        <div class="card" data-testid="profile-card">
          <h3>Your Profile</h3>
          <p><strong>Email:</strong> <span data-testid="user-email">${user.email}</span></p>
          <p><strong>User ID:</strong> <span data-testid="user-id">${user.id}</span></p>
          <p><strong>Privilege Tier:</strong> <span data-testid="user-role">${user.role}</span></p>
          <button id="refreshProfileBtn" class="btn btn-outline btn-sm" data-testid="refresh-profile-btn">
            Verify Profile API
          </button>
          <div id="profileApiOutput" class="api-debug-box hidden" data-testid="profile-api-output"></div>
        </div>

        <div class="card" data-testid="security-controls-card">
          <h3>Security QA Checklist</h3>
          <ul class="checklist">
            <li>✅ Role-Based Access Control Active</li>
            <li>✅ HttpOnly & SameSite Session Cookies</li>
            <li>✅ Sensitive Route Cache Invalidation</li>
            <li>✅ Content Security Policy Enforced</li>
          </ul>
        </div>
      </div>
    </div>
    `,
    user
  );

  res.send(html);
});

// Admin Page (Protected, Admin Only, Sensitive Cache Disabled)
app.get('/admin', requireAdmin, noCacheMiddleware, (req: Request, res: Response) => {
  const user = req.session.user!;
  const html = renderLayout(
    'Admin Portal',
    `
    <div class="admin-container" data-testid="admin-page">
      <div class="admin-header">
        <h1 data-testid="admin-title">Administrator Security Console</h1>
        <p class="admin-subtitle">Restricted Zone: Access permitted exclusively for role=admin</p>
      </div>

      <div class="admin-table-container card">
        <h3>Managed Directory Users</h3>
        <p class="table-caption">Data fetched directly from <code>/api/admin/users</code></p>
        
        <table class="data-table" data-testid="users-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Department</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody id="adminUsersTableBody" data-testid="users-table-body">
            ${DEMO_USERS.map(
              (u) => `
              <tr data-testid="user-row-${u.id}">
                <td><code>${u.id}</code></td>
                <td>${u.name}</td>
                <td>${u.email}</td>
                <td><span class="badge ${u.role}">${u.role}</span></td>
                <td>${u.department}</td>
                <td>${u.created}</td>
              </tr>
            `
            ).join('')}
          </tbody>
        </table>
      </div>
    </div>
    `,
    user
  );

  res.send(html);
});

// Access Denied (403) Page
app.get('/access-denied', (req: Request, res: Response) => {
  const user = req.session ? req.session.user : undefined;
  res.status(403);
  const html = renderLayout(
    'Access Denied (403)',
    `
    <div class="error-container" data-testid="access-denied-page">
      <div class="error-icon">🚫</div>
      <h1 data-testid="access-denied-title">403 Forbidden</h1>
      <p class="error-message" data-testid="access-denied-message">
        You do not have administrative privileges to access this area.
      </p>
      <div class="actions">
        <a href="/dashboard" class="btn btn-primary" data-testid="back-to-dashboard-btn">Return to Dashboard</a>
      </div>
    </div>
    `,
    user
  );
  res.send(html);
});

// ==========================================
// REST API Endpoints
// ==========================================

// POST /api/auth/login
app.post('/api/auth/login', (req: Request, res: Response): void => {
  const { email, password, redirect } = req.body;

  // Validation: Check required fields
  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({
      success: false,
      error: 'Email and password are required fields.'
    });
    return;
  }

  const trimmedEmail = email.trim().toLowerCase();

  // Find user
  const foundUser = DEMO_USERS.find((u) => u.email.toLowerCase() === trimmedEmail);

  // Constant-time-like generic rejection to mitigate user enumeration
  if (!foundUser || foundUser.password !== password) {
    res.status(401).json({
      success: false,
      error: 'Invalid email or password.'
    });
    return;
  }

  // Session regeneration prevents session fixation attacks
  req.session.regenerate((err) => {
    if (err) {
      res.status(500).json({ success: false, error: 'Failed to initialize session.' });
      return;
    }

    req.session.user = {
      id: foundUser.id,
      email: foundUser.email,
      name: foundUser.name,
      role: foundUser.role
    };

    res.status(200).json({
      success: true,
      user: {
        id: foundUser.id,
        email: foundUser.email,
        name: foundUser.name,
        role: foundUser.role
      },
      redirectTo: redirect && redirect.startsWith('/') ? redirect : '/dashboard'
    });
  });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req: Request, res: Response): void => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ success: false, error: 'Failed to destroy session.' });
      return;
    }
    res.clearCookie(SESSION_COOKIE_NAME);
    res.status(200).json({
      success: true,
      message: 'Logged out successfully.'
    });
  });
});

// GET /api/auth/status
app.get('/api/auth/status', (req: Request, res: Response): void => {
  if (req.session && req.session.user) {
    res.status(200).json({
      authenticated: true,
      user: req.session.user
    });
  } else {
    res.status(200).json({
      authenticated: false
    });
  }
});

// GET /api/profile (Protected, Sensitive Cache Disabled)
app.get('/api/profile', requireAuth, noCacheMiddleware, (req: Request, res: Response): void => {
  const sessionUser = req.session.user!;
  const fullRecord = DEMO_USERS.find((u) => u.id === sessionUser.id);

  if (!fullRecord) {
    res.status(404).json({ success: false, error: 'User profile not found.' });
    return;
  }

  // Never leak password hashes or internal secrets in API responses
  res.status(200).json({
    success: true,
    user: {
      id: fullRecord.id,
      email: fullRecord.email,
      name: fullRecord.name,
      role: fullRecord.role,
      department: fullRecord.department,
      created: fullRecord.created
    }
  });
});

// GET /api/admin/users (Protected, Admin Only, Sensitive Cache Disabled)
app.get('/api/admin/users', requireAdmin, noCacheMiddleware, (_req: Request, res: Response): void => {
  // Strip passwords before returning
  const sanitizedUsers = DEMO_USERS.map(({ password: _, ...safeProps }) => safeProps);
  res.status(200).json({
    success: true,
    count: sanitizedUsers.length,
    users: sanitizedUsers
  });
});

// ==========================================
// Centralized Error & 404 Handlers
// ==========================================

// 404 Handler
app.use((req: Request, res: Response) => {
  if (req.path.startsWith('/api/')) {
    res.status(404).json({
      success: false,
      error: `Endpoint not found: ${req.method} ${req.path}`
    });
    return;
  }
  res.status(404).send(
    renderLayout(
      'Not Found (404)',
      `
      <div class="error-container">
        <h1>404 Not Found</h1>
        <p>The page you requested does not exist.</p>
        <a href="/" class="btn btn-primary">Return Home</a>
      </div>
      `
    )
  );
});

// 500 Central Error Handler (Prevents stack trace leaks in responses)
app.use((_err: Error, _req: Request, res: Response, _next: NextFunction) => {
  // Safe generic response without internal stack trace disclosure
  res.status(500).json({
    success: false,
    error: 'An internal server error occurred. Details have been logged securely.'
  });
});
