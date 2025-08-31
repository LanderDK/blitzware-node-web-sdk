# BlitzWare Node.js SDK

A comprehensive OAuth 2.0 SDK for Node.js applications supporting both Express.js and Koa.js frameworks with middleware patterns.

## 🚀 Quick Start

Build a secure server‑rendered web app using BlitzWare OAuth 2.0 Authorization Code flow with automatic route management and session handling.

### Prerequisites

- A BlitzWare OAuth application (Client ID, Client Secret, Redirect URI)
- Node.js 18+
- HTTPS in production

### 1) Configure BlitzWare

Get your application keys from the BlitzWare dashboard. You will need:

- Client ID
- Client Secret
- A Redirect URI added to your application's Redirect URIs list (under Security)

If the redirect URI is not configured, authentication will fail.

### 2) Install the BlitzWare Node SDK

Run this in your project directory:

```bash
npm install blitzware-node-sdk express express-session dotenv
# or
# yarn add blitzware-node-sdk express express-session dotenv
```

### 3) Configure environment

Create a `.env` file with your credentials:

```
BLITZWARE_CLIENT_ID=your-client-id
BLITZWARE_CLIENT_SECRET=your-client-secret
BLITZWARE_REDIRECT_URI=http://localhost:3000/callback
SESSION_SECRET=replace-with-a-strong-secret
# Optional: override auth base (self-hosted/staging)
# BLITZWARE_BASE_URL=https://auth.blitzware.xyz/api/auth
```

## 4) Express setup

Create `server.js` (or `app.js`):

```js
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });
const express = require("express");
const session = require("express-session");
const { expressAuth, expressRequiresAuth } = require("../dist");

const app = express();
const port = process.env.PORT || 3000;

// BlitzWare configuration
const config = {
  authRequired: false, // Don't require auth for all routes
  clientId: process.env.BLITZWARE_CLIENT_ID || "your-client-id",
  clientSecret: process.env.BLITZWARE_CLIENT_SECRET || "your-client-secret",
  redirectUri:
    process.env.BLITZWARE_REDIRECT_URI || `http://localhost:${port}/callback`,
  secret: process.env.SESSION_SECRET || "LONG_RANDOM_STRING",
  // baseUrl: process.env.BLITZWARE_BASE_URL, // Optional: custom auth server
};

// Session middleware (required for auth middleware)
app.use(
  session({
    secret: config.secret,
    resave: false,
    saveUninitialized: false,
  })
);

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// BlitzWare auth router attaches /login, /logout, and /callback routes
app.use(expressAuth(config));

// Home route - req.session.user is provided from the auth router
app.get("/", (req, res) => {
  res.send(`
    <html>
      <head><title>BlitzWare Express Example</title></head>
      <body>
        <h1>BlitzWare Express Example</h1>
        ${
          req.session.user
            ? `
            <p>✅ <strong>Logged in as ${req.session.user.username}</strong></p>
            <p><a href="/profile">View Profile</a></p>
            <p><a href="/logout">Logout</a></p>
          `
            : `
            <p>❌ Not logged in</p>
            <p><a href="/login">Login</a></p>
          `
        }
      </body>
    </html>
  `);
});

// Protected profile route - expressRequiresAuth() middleware
app.get("/profile", expressRequiresAuth(), (req, res) => {
  res.send(`
    <html>
      <head><title>Profile</title></head>
      <body>
        <h1>Profile</h1>
        <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
        <p><a href="/">← Back to Home</a></p>
      </body>
    </html>
  `);
});

app.listen(port, () => {
  console.log(`
🚀 BlitzWare Express Example running at http://localhost:${port}

🔗 Routes:
   • GET /         - Home page
   • GET /profile  - Protected profile page  
   • GET /login    - Login (automatic)
   • GET /logout   - Logout (automatic)

📝 Setup:
   1. Set BLITZWARE_CLIENT_ID and BLITZWARE_CLIENT_SECRET in .env
   2. Visit http://localhost:${port}/login to authenticate
  `);
});

module.exports = app;
```

Run:

```bash
node server.js
```

Then visit `http://localhost:3000`.

## 5) Koa setup

Create a Koa app (example):

```js
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });
const Koa = require("koa");
const Router = require("@koa/router");
const KoaSession = require("koa-session");
const session = KoaSession && KoaSession.default ? KoaSession.default : KoaSession;
const bodyParser = require("koa-bodyparser");
const { koaAuth, koaRequiresAuth } = require("../dist");

const app = new Koa();
const router = new Router();
const port = process.env.PORT || 3001;

// BlitzWare configuration
const config = {
  authRequired: false, // Don't require auth for all routes
  clientId: process.env.BLITZWARE_CLIENT_ID || "your-client-id",
  clientSecret: process.env.BLITZWARE_CLIENT_SECRET || "your-client-secret",
  redirectUri:
    process.env.BLITZWARE_REDIRECT_URI || `http://localhost:${port}/callback`,
  secret: process.env.SESSION_SECRET || "LONG_RANDOM_STRING",
  // baseUrl: process.env.BLITZWARE_BASE_URL, // Optional: custom auth server
};

// Koa requires signing keys for sessions
app.keys = [config.secret];

// Session middleware
app.use(session(app));

app.use(bodyParser());

// BlitzWare auth router attaches /login, /logout, and /callback routes
app.use(koaAuth(config));

// Home route - ctx.session.user is provided from the auth router
router.get("/", async (ctx) => {
  ctx.type = "html";
  ctx.body = `
    <html>
      <head><title>BlitzWare Koa Example</title></head>
      <body>
        <h1>BlitzWare Koa Example</h1>
        ${
          ctx.session.user
            ? `
            <p>✅ <strong>Logged in as ${ctx.session.user.username}</strong></p>
            <p><a href="/profile">View Profile</a></p>
            <p><a href="/logout">Logout</a></p>
          `
            : `
            <p>❌ Not logged in</p>
            <p><a href="/login">Login</a></p>
          `
        }
      </body>
    </html>
  `;
});

// Protected profile route - koaRequiresAuth() middleware
router.get("/profile", koaRequiresAuth(), async (ctx) => {
  ctx.type = "html";
  ctx.body = `
    <html>
      <head><title>Profile</title></head>
      <body>
        <h1>Profile</h1>
        <pre>${JSON.stringify(ctx.session.user, null, 2)}</pre>
        <p><a href="/">← Back to Home</a></p>
      </body>
    </html>
  `;
});

app.use(router.routes());
app.use(router.allowedMethods());

app.listen(port, () => {
  console.log(`
🚀 BlitzWare Koa Example running at http://localhost:${port}

🔗 Routes:
   • GET /         - Home page
   • GET /profile  - Protected profile page
   • GET /login    - Login (automatic)
   • GET /logout   - Logout (automatic)

📝 Setup:
   1. Set BLITZWARE_CLIENT_ID and BLITZWARE_CLIENT_SECRET in .env
   2. Visit http://localhost:${port}/login to authenticate
  `);
});
```

## 6) How it works

- PKCE + state: The SDK generates a `state` and PKCE verifier/challenge.
  - `state` defends against CSRF
  - PKCE protects the code exchange

### Automatic Routes

When you use `expressAuth()` or `koaAuth()`, the following routes are created automatically:

- `GET /login` - Initiates OAuth login flow
- `GET /logout` - Logs out user and clears session
- `GET /callback` - OAuth callback handler

### Protection

- `expressRequiresAuth()` and `koaRequiresAuth()` check for a user stored in the session. They do not perform token introspection by default.

### Logout (front-channel)

The SDK performs a front-channel logout: it serves a small HTML page that POSTs to the auth service (so auth-service cookies are sent) and then redirects back to your app.

---

If you need additional features — token introspection on each request, automatic refresh using `session.refreshToken`, or other behavior — open an issue or PR and I can add an opt-in option such as `requiresAuth({ validateToken: true })`.

---

License: MIT