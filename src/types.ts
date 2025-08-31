/**
 * BlitzWare Authentication Error
 * Custom error class for handling authentication-related errors
 */
export class BlitzWareAuthError extends Error {
  public readonly code: string;
  public readonly details?: Record<string, any>;

  constructor(message: string, code: string, details?: Record<string, any>) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "BlitzWareAuthError";
  }
}

/**
 * Configuration parameters for BlitzWare authentication
 */
export interface BlitzWareAuthConfig {
  /** OAuth 2.0 Client ID */
  clientId: string;
  /** OAuth 2.0 Client Secret (for confidential clients) */
  clientSecret: string;
  /** Redirect URI for OAuth 2.0 callback */
  redirectUri: string;
  /** Optional override for the BlitzWare Auth API base URL */
  baseUrl?: string;
}

/**
 * User information returned from the userinfo endpoint
 */
export interface BlitzWareUser {
  /** Unique user identifier */
  id: string;
  /** Username */
  username: string;
  /** User email address */
  email?: string;
  /** User roles */
  roles?: string[];
  /** Additional user properties */
  [key: string]: any;
}

/**
 * OAuth 2.0 token response
 */
export interface TokenResponse {
  /** Access token for API requests */
  access_token: string;
  /** Token type (usually "Bearer") */
  token_type: string;
  /** Token expiration time in seconds */
  expires_in?: number;
  /** Refresh token for obtaining new access tokens */
  refresh_token?: string;
  /** Scope of the access token */
  scope?: string;
}

/**
 * Token introspection response (RFC 7662)
 */
export interface TokenIntrospectionResponse {
  /** Whether the token is currently active */
  active: boolean;
  /** Client identifier for the OAuth 2.0 client that requested this token */
  client_id?: string;
  /** Human-readable identifier for the resource owner who authorized this token */
  username?: string;
  /** Type of the token */
  token_type?: string;
  /** Expiration timestamp (Unix timestamp) */
  exp?: number;
  /** Issued at timestamp (Unix timestamp) */
  iat?: number;
  /** Subject of the token */
  sub?: string;
  /** Intended audience for this token */
  aud?: string;
  /** Issuer of this token */
  iss?: string;
  /** String identifier for the token */
  jti?: string;
  /** Space-separated list of scopes associated with this token */
  scope?: string;
}

/**
 * Authorization URL generation parameters
 */
export interface AuthorizationUrlParams {
  /** OAuth 2.0 response type (default: "code") */
  responseType?: "code";
  /** State parameter for CSRF protection */
  state?: string;
  /** (Deprecated) Use additionalParams.scope instead */
  // keep for backward compatibility in examples; not used directly by SDK
  scope?: string;
  /** Additional query parameters */
  additionalParams?: Record<string, string>;
}

/**
 * Authorization callback parameters
 */
export interface AuthorizationCallbackParams {
  /** Authorization code from OAuth provider */
  code?: string;
  /** State parameter for verification */
  state?: string;
  /** Error code if authorization failed */
  error?: string;
  /** Human-readable error description */
  error_description?: string;
  /** Additional error information URI */
  error_uri?: string;
}
