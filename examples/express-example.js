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
