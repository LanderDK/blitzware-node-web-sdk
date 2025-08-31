import { Request, Response, NextFunction, Router } from "express";
import { BlitzWareAuth } from "./BlitzWareAuth";
import { BlitzWareAuthError, BlitzWareAuthConfig, BlitzWareUser } from "./types";

type Logger = {
  error?: (...args: any[]) => void;
  warn?: (...args: any[]) => void;
  info?: (...args: any[]) => void;
  debug?: (...args: any[]) => void;
};

const noop = () => {};

function normalizeLogger(l?: Logger): Required<Logger> {
  return {
    error: l?.error ?? noop,
    warn: l?.warn ?? noop,
    info: l?.info ?? noop,
    debug: l?.debug ?? noop,
  };
}

// Global BlitzWare instance for API
let globalBlitzware: BlitzWareAuth | null = null;

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      blitzware?: {
        user?: BlitzWareUser;
        accessToken?: string;
        isAuthenticated(): boolean;
      };
    }
  }
}

/**
 * Configuration for BlitzWare authentication
 */
export interface AuthConfig extends BlitzWareAuthConfig {
  /** Whether authentication is required for all routes (default: true) */
  authRequired?: boolean;
  /** Enable BlitzWare logout functionality (default: true) */
  blitzwareLogout?: boolean;
  /** Base URL for the application (auto-detected if not provided) */
  baseURL?: string;
  /** Secret for signing sessions */
  secret?: string;
  /** Routes that don't require authentication when authRequired=true */
  publicPaths?: Array<string | RegExp>;
  /** Optional logger (console-like). Defaults to no-op to avoid leaking logs. */
  logger?: Logger;
  /** Success redirect after login */
  successRedirect?: string;
  /** Error redirect after failed login */
  errorRedirect?: string;
  /** Additional parameters to pass to authorization URL */
  additionalParams?: Record<string, string>;
}

/**
 * Main auth function - similar to auth(config)
 * Usage: app.use(auth(config))
 */
export function expressAuth(config: AuthConfig) {
  const {
    authRequired = true,
    blitzwareLogout = true,
    baseURL,
    secret,
    publicPaths = [],
    successRedirect = "/",
    errorRedirect = "/login?error=auth_failed",
    additionalParams = {},
    logger: configLogger,
    ...blitzwareConfig
  } = config;

  const logger = normalizeLogger(configLogger);

  // Auto-detect baseURL if not provided
  if (!blitzwareConfig.redirectUri && baseURL) {
    blitzwareConfig.redirectUri = `${baseURL}/callback`;
  }

  // Initialize global BlitzWare instance
  globalBlitzware = new BlitzWareAuth(blitzwareConfig);

  const router = Router();

  // Helper: check if a request path is public
  function isPublicPath(pathname: string): boolean {
    if (pathname === "/login" || pathname === "/callback" || pathname === "/logout") return true;
    return publicPaths.some((p) => {
      if (typeof p === "string") return p === pathname;
      try { return p.test(pathname); } catch { return false; }
    });
  }

  // Middleware to attach user and enforce auth if required
  router.use((req: Request, res: Response, next: NextFunction) => {
    const session = req.session as any;
    
    // Initialize req.blitzware
    req.blitzware = {
      user: session?.user || undefined,
      accessToken: session?.accessToken || undefined,
      isAuthenticated: () => !!session?.user,
    };

    // If auth is required and user is not authenticated and not on public path
    if (authRequired && !req.blitzware.isAuthenticated() && !isPublicPath(req.path)) {
      return res.redirect("/login");
    }

    next();
  });

  // Login route
  router.get("/login", async (req: Request, res: Response) => {
    try {
      const session = req.session as any;

      if (!session) {
        logger.error("Session not found. Make sure express-session middleware is configured.");
        return res.status(500).send("Session configuration error");
      }

      const state = globalBlitzware!.generateState();
      const { url: authUrl, codeVerifier } = globalBlitzware!.getAuthorizationUrl({
        state,
        additionalParams,
      });

      session.oauthState = state;
      session.codeVerifier = codeVerifier;

      res.redirect(authUrl);
    } catch (error) {
      logger.error("Login error");
      res.status(500).send("Login failed");
    }
  });

  // Callback route
  router.get("/callback", async (req: Request, res: Response) => {
    try {
      const session = req.session as any;

      if (!session) {
        logger.error("Session not found. Make sure express-session middleware is configured.");
        return res.status(500).send("Session configuration error");
      }

      const expectedState = session.oauthState;
      const codeVerifier = session.codeVerifier;

      const tokenResponse = await globalBlitzware!.handleCallback(
        req.query,
        expectedState,
        codeVerifier
      );

      session.accessToken = tokenResponse.access_token;
      if (tokenResponse.refresh_token) {
        session.refreshToken = tokenResponse.refresh_token;
      }

      const user = await globalBlitzware!.getUserInfo(tokenResponse.access_token);
      session.user = user;

      session.oauthState = null;
      session.codeVerifier = null;

      res.redirect(successRedirect);
    } catch (error) {
      logger.warn("OAuth callback failed");

      const url = new URL(
        errorRedirect,
        `${req.protocol}://${req.get("host")}`
      );
      if (error instanceof BlitzWareAuthError) {
        url.searchParams.set("error_code", error.code);
      } else {
        url.searchParams.set("error", "auth_failed");
      }

      res.redirect(url.toString());
    }
  });

  // Logout route (if enabled)
  if (blitzwareLogout) {
    router.get("/logout", async (req: Request, res: Response) => {
      try {
        const session = req.session as any;

        if (session) {
          session.accessToken = null;
          session.refreshToken = null;
          session.user = null;
        }

        // Use front-channel logout
        const authBase = globalBlitzware!.getBaseUrl().replace(/\/$/, "");
        const logoutUrl = `${authBase}/logout`;
        const clientId = globalBlitzware!.getConfig().clientId;

        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.status(200).send(`<!doctype html>
<html>
  <head>
    <meta http-equiv="referrer" content="no-referrer">
    <meta charset="utf-8">
    <title>Logging out…</title>
  </head>
  <body>
    <form id="logoutForm" method="POST" action="${logoutUrl}">
      <input type="hidden" name="client_id" value="${clientId}">
    </form>
    <script>
      (function() {
        try {
          fetch('${logoutUrl}', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: '${clientId}' })
          }).catch(function(){ /* ignore */ }).finally(function(){
            window.location.replace('${successRedirect}');
          });
        } catch (e) {
          document.getElementById('logoutForm').submit();
          setTimeout(function(){ window.location.replace('${successRedirect}'); }, 500);
        }
      })();
    </script>
  </body>
</html>`);
      } catch (error) {
        logger.error("Logout error");
        res.redirect(successRedirect);
      }
    });
  }

  return router;
}

/**
 * requiresAuth middleware
 * Usage: router.get('/profile', requiresAuth(), (req, res) => { ... })
 */
export function expressRequiresAuth() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.blitzware?.isAuthenticated()) {
      return res.redirect("/login");
    }
    next();
  };
}

// ============================================================================
// KOA MIDDLEWARE IMPLEMENTATION
// ============================================================================

// Koa types (inline to avoid dependency)
interface KoaContext {
  path: string;
  method: string;
  query: any;
  session?: any;
  status: number;
  body: any;
  type: string;
  redirect(url: string): void;
  blitzware?: {
    user?: BlitzWareUser;
    accessToken?: string;
    isAuthenticated(): boolean;
  };
}

type KoaNext = () => Promise<void>;

// Global BlitzWare instance for Koa API
let globalKoaBlitzware: BlitzWareAuth | null = null;

/**
 * Main koaAuth function - Koa equivalent of auth(config)
 * Usage: app.use(koaAuth(config))
 */
export function koaAuth(config: AuthConfig) {
  const {
    authRequired = false, // Default to false for Koa (more flexible)
    blitzwareLogout = true,
    baseURL,
    secret,
    publicPaths = [],
    successRedirect = "/",
    errorRedirect = "/login?error=auth_failed",
    additionalParams = {},
    logger: configLogger,
    ...blitzwareConfig
  } = config;

  const logger = normalizeLogger(configLogger);

  // Auto-detect baseURL if not provided
  if (!blitzwareConfig.redirectUri && baseURL) {
    blitzwareConfig.redirectUri = `${baseURL}/callback`;
  }

  // Initialize global BlitzWare instance for Koa
  globalKoaBlitzware = new BlitzWareAuth(blitzwareConfig);

  // Helper: check if a request path is public
  function isPublicPath(pathname: string): boolean {
    if (pathname === "/login" || pathname === "/callback" || pathname === "/logout") return true;
    return publicPaths.some((p) => {
      if (typeof p === "string") return p === pathname;
      try { return p.test(pathname); } catch { return false; }
    });
  }

  // Return Koa middleware function
  return async (ctx: KoaContext, next: KoaNext) => {
    const session = ctx.session as any;

    // Initialize ctx.blitzware
    ctx.blitzware = {
      user: session?.user || undefined,
      accessToken: session?.accessToken || undefined,
      isAuthenticated: () => !!session?.user,
    };

    // Handle auth routes
    if (ctx.path === "/login" && ctx.method === "GET") {
      try {
        if (!session) {
          logger.error("Session not found. Make sure koa-session middleware is configured.");
          ctx.status = 500;
          ctx.body = "Session configuration error";
          return;
        }

        const state = globalKoaBlitzware!.generateState();
        const { url: authUrl, codeVerifier } = globalKoaBlitzware!.getAuthorizationUrl({
          state,
          additionalParams,
        });

        session.oauthState = state;
        session.codeVerifier = codeVerifier;

        ctx.redirect(authUrl);
        return;
      } catch (error) {
        logger.error("Login error");
        ctx.status = 500;
        ctx.body = "Login failed";
        return;
      }
    }

    if (ctx.path === "/callback" && ctx.method === "GET") {
      try {
        if (!session) {
          logger.error("Session not found. Make sure koa-session middleware is configured.");
          ctx.status = 500;
          ctx.body = "Session configuration error";
          return;
        }

        const expectedState = session.oauthState;
        const codeVerifier = session.codeVerifier;

        const tokenResponse = await globalKoaBlitzware!.handleCallback(
          ctx.query,
          expectedState,
          codeVerifier
        );

        session.accessToken = tokenResponse.access_token;
        if (tokenResponse.refresh_token) {
          session.refreshToken = tokenResponse.refresh_token;
        }

        const user = await globalKoaBlitzware!.getUserInfo(tokenResponse.access_token);
        session.user = user;

        session.oauthState = null;
        session.codeVerifier = null;

        ctx.redirect(successRedirect);
        return;
      } catch (error) {
        logger.warn("OAuth callback failed");
        ctx.redirect(errorRedirect);
        return;
      }
    }

    if (ctx.path === "/logout" && ctx.method === "GET") {
      try {
        // Clear session first
        if (session) {
          session.accessToken = null;
          session.refreshToken = null;
          session.user = null;
        }

        if (blitzwareLogout) {
          // Use front-channel logout like Express version
          const authBase = globalKoaBlitzware!.getBaseUrl().replace(/\/$/, "");
          const logoutUrl = `${authBase}/logout`;
          const clientId = globalKoaBlitzware!.getConfig().clientId;

          ctx.type = "text/html; charset=utf-8";
          ctx.status = 200;
          ctx.body = `<!doctype html>
<html>
  <head>
    <meta http-equiv="referrer" content="no-referrer">
    <meta charset="utf-8">
    <title>Logging out…</title>
  </head>
  <body>
    <form id="logoutForm" method="POST" action="${logoutUrl}">
      <input type="hidden" name="client_id" value="${clientId}">
    </form>
    <script>
      (function() {
        try {
          fetch('${logoutUrl}', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: '${clientId}' })
          }).catch(function(){ /* ignore */ }).finally(function(){
            window.location.replace('${successRedirect}');
          });
        } catch (e) {
          document.getElementById('logoutForm').submit();
          setTimeout(function(){ window.location.replace('${successRedirect}'); }, 500);
        }
      })();
    </script>
  </body>
</html>`;
          return;
        } else {
          ctx.redirect("/");
          return;
        }
      } catch (error) {
        logger.error("Logout error");
        ctx.redirect("/");
        return;
      }
    }

    // If auth is required and user is not authenticated and not on public path
    if (authRequired && !ctx.blitzware.isAuthenticated() && !isPublicPath(ctx.path)) {
      ctx.redirect("/login");
      return;
    }

    // Continue to next middleware
    await next();
  };
}

/**
 * requiresAuth middleware for Koa
 * Usage: router.get('/profile', koaRequiresAuth(), async (ctx) => { ... })
 */
export function koaRequiresAuth() {
  return async (ctx: KoaContext, next: KoaNext) => {
    if (!ctx.blitzware?.isAuthenticated()) {
      ctx.redirect("/login");
      return;
    }
    await next();
  };
}
