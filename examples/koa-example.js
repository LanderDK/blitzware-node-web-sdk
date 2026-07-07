const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });
const Koa = require("koa");
const Router = require("@koa/router");
const KoaSession = require("koa-session");
const session =
  KoaSession && KoaSession.default ? KoaSession.default : KoaSession;
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
  // authBaseUrl: process.env.BLITZWARE_AUTH_BASE_URL, // Optional managed auth domain
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
