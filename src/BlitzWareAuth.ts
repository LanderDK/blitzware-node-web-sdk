import axios, { AxiosInstance, AxiosResponse } from "axios";
import { randomBytes, createHash } from "crypto";
// Note: crypto and URL are Node.js built-in modules
import {
  BlitzWareAuthConfig,
  BlitzWareAuthError,
  TokenResponse,
  TokenIntrospectionResponse,
  BlitzWareUser,
  AuthorizationUrlParams,
  AuthorizationCallbackParams,
} from "./types";

const DEFAULT_BASE_URL = "https://auth.blitzware.xyz/api/auth";
const DEFAULT_TIMEOUT = 30000;

/**
 * BlitzWare Node.js SDK for Traditional Web Applications
 *
 * This SDK implements OAuth 2.0 Authorization Code flow for confidential clients.
 * Unlike Single Page Applications, traditional web apps can securely store client secrets
 * and don't require PKCE (Proof Key for Code Exchange).
 */
export class BlitzWareAuth {
  private readonly config: BlitzWareAuthConfig;
  private readonly httpClient: AxiosInstance;
  private readonly baseUrl: string = DEFAULT_BASE_URL;
  private readonly timeout: number = DEFAULT_TIMEOUT;

  constructor(config: BlitzWareAuthConfig) {
    // Validate required configuration
    if (!config.clientId) {
      throw new BlitzWareAuthError(
        "Client ID is required",
        "missing_client_id"
      );
    }
    if (!config.clientSecret) {
      throw new BlitzWareAuthError(
        "Client Secret is required",
        "missing_client_secret"
      );
    }
    if (!config.redirectUri) {
      throw new BlitzWareAuthError(
        "Redirect URI is required",
        "missing_redirect_uri"
      );
    }

    this.config = config;

    // Allow overriding the base API URL if provided
    if ((config as any).baseUrl) {
      this.baseUrl = (config as any).baseUrl as string;
    }

    // Configure HTTP client
    this.httpClient = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      withCredentials: true, // Include session cookies in all requests
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "BlitzWare-Node-SDK/1.0.0",
      },
    });

    // Add response interceptor for error handling
    this.httpClient.interceptors.response.use(
      (response: AxiosResponse) => response,
      (error: any) => {
        throw this.parseApiError(error);
      }
    );
  }

  /**
   * Get the BlitzWare Auth API base URL used by this instance
   */
  public getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Generate a PKCE code verifier (random string)
   * @returns Base64URL-encoded random string
   */
  public generateCodeVerifier(): string {
    return randomBytes(32).toString("base64url");
  }

  /**
   * Generate a PKCE code challenge from a code verifier
   * @param codeVerifier The code verifier to generate a challenge for
   * @returns Base64URL-encoded SHA256 hash of the code verifier
   */
  public generateCodeChallenge(codeVerifier: string): string {
    return createHash("sha256").update(codeVerifier).digest("base64url");
  }

  /**
   * Generate a secure random state parameter for CSRF protection
   */
  public generateState(): string {
  return randomBytes(32).toString("base64url");
  }

  /**
   * Generate the authorization URL to redirect users for authentication
   *
   * @param params - Authorization parameters
   * @returns Object containing the authorization URL and code verifier (for PKCE)
   */
  public getAuthorizationUrl(params: AuthorizationUrlParams = {}): {
    url: string;
    codeVerifier: string;
  } {
    const { responseType = "code", state, additionalParams = {} } = params;

  const url = new URL(`${this.baseUrl}/authorize`);

    // Required parameters
    url.searchParams.set("response_type", responseType);
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", this.config.redirectUri);

    // Optional parameters
    if (state) {
      url.searchParams.set("state", state);
    }

    // PKCE parameters - recommended for all OAuth clients
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);

    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");

    // Additional custom parameters
    Object.entries(additionalParams).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });

    return {
      url: url.toString(),
      codeVerifier,
    };
  }

  /**
   * Handle the authorization callback and exchange code for tokens
   *
   * @param callbackParams - Parameters from the authorization callback
   * @param expectedState - Expected state value for verification (optional)
   * @param codeVerifier - PKCE code verifier (optional)
   * @returns Token response containing access_token and refresh_token
   */
  public async handleCallback(
    callbackParams: AuthorizationCallbackParams,
    expectedState?: string,
    codeVerifier?: string
  ): Promise<TokenResponse> {
    // Check for authorization errors
    if (callbackParams.error) {
      throw new BlitzWareAuthError(
        callbackParams.error_description ||
          `Authorization failed: ${callbackParams.error}`,
        callbackParams.error
      );
    }

    // Verify authorization code is present
    if (!callbackParams.code) {
      throw new BlitzWareAuthError(
        "Authorization code not found in callback",
        "missing_authorization_code"
      );
    }

    // Verify state parameter if provided
    if (expectedState && callbackParams.state !== expectedState) {
      throw new BlitzWareAuthError(
        "State parameter mismatch - possible CSRF attack",
        "invalid_state"
      );
    }

    // Exchange authorization code for tokens
    return this.exchangeCodeForTokens(callbackParams.code, codeVerifier);
  }

  /**
   * Exchange authorization code for access and refresh tokens
   *
   * @param code - Authorization code from OAuth provider
   * @param codeVerifier - PKCE code verifier (optional)
   * @returns Token response
   */
  public async exchangeCodeForTokens(
    code: string,
    codeVerifier?: string
  ): Promise<TokenResponse> {
    try {
      const requestBody: any = {
        grant_type: "authorization_code",
        code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: this.config.redirectUri,
      };

      // Include PKCE code verifier if provided
      if (codeVerifier) {
        requestBody.code_verifier = codeVerifier;
      }

      const response: AxiosResponse<TokenResponse> = await this.httpClient.post(
        "/token",
        requestBody
      );

      return response.data;
    } catch (error) {
      throw this.parseApiError(
        error,
        "Failed to exchange authorization code for tokens",
        "token_exchange_failed"
      );
    }
  }

  /**
   * Refresh an access token using a refresh token
   *
   * @param refreshToken - The refresh token
   * @returns New token response
   */
  public async refreshToken(refreshToken: string): Promise<TokenResponse> {
    if (!refreshToken) {
      throw new BlitzWareAuthError(
        "Refresh token is required",
        "missing_refresh_token"
      );
    }

    try {
      const response: AxiosResponse<TokenResponse> = await this.httpClient.post(
        "/token",
        {
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
        }
      );

      return response.data;
    } catch (error) {
      throw this.parseApiError(
        error,
        "Failed to refresh access token",
        "token_refresh_failed"
      );
    }
  }

  /**
   * Get user information using an access token
   *
   * @param accessToken - Valid access token
   * @returns User information
   */
  public async getUserInfo(accessToken: string): Promise<BlitzWareUser> {
    if (!accessToken) {
      throw new BlitzWareAuthError(
        "Access token is required",
        "missing_access_token"
      );
    }

    try {
      const response: AxiosResponse<BlitzWareUser> = await this.httpClient.get(
        "/userinfo",
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      return response.data;
    } catch (error) {
      throw this.parseApiError(
        error,
        "Failed to get user information",
        "userinfo_failed"
      );
    }
  }

  /**
   * Introspect a token to get its metadata (RFC 7662)
   *
   * @param token - Token to introspect
   * @param tokenTypeHint - Hint about the token type ('access_token' or 'refresh_token')
   * @returns Token introspection response
   */
  public async introspectToken(
    token: string,
    tokenTypeHint?: "access_token" | "refresh_token"
  ): Promise<TokenIntrospectionResponse> {
    if (!token) {
      throw new BlitzWareAuthError(
        "Token is required for introspection",
        "missing_token"
      );
    }

    try {
      const payload: any = {
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      };

      if (tokenTypeHint) {
        payload.token_type_hint = tokenTypeHint;
      }

      const response: AxiosResponse<TokenIntrospectionResponse> =
        await this.httpClient.post("/introspect", payload);

      return response.data;
    } catch (error) {
      throw this.parseApiError(
        error,
        "Failed to introspect token",
        "token_introspection_failed"
      );
    }
  }

  /**
   * Revoke a token (access token or refresh token)
   *
   * @param token - Token to revoke
   * @param tokenTypeHint - Hint about the token type
   */
  public async revokeToken(
    token: string,
    tokenTypeHint?: "access_token" | "refresh_token"
  ): Promise<void> {
    if (!token) {
      throw new BlitzWareAuthError(
        "Token is required for revocation",
        "missing_token"
      );
    }

    try {
      const payload: any = {
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      };

      if (tokenTypeHint) {
        payload.token_type_hint = tokenTypeHint;
      }

      await this.httpClient.post("/revoke", payload);
    } catch (error) {
      throw this.parseApiError(
        error,
        "Failed to revoke token",
        "token_revocation_failed"
      );
    }
  }

  /**
   * Logout the user from the BlitzWare authentication service
   * This invalidates all tokens for the client and clears the user session
   */
  public async logout(): Promise<void> {
    try {
      await this.httpClient.post("/logout", {
        client_id: this.config.clientId,
      });
    } catch (error) {
      throw this.parseApiError(error, "Failed to log out", "logout_failed");
    }
  }

  /**
   * Validate that a token is active and get user information
   * This is a convenience method that combines introspection and user info
   *
   * @param accessToken - Access token to validate
   * @returns User information if token is valid
   */
  public async validateTokenAndGetUser(
    accessToken: string
  ): Promise<BlitzWareUser> {
    // First introspect the token to check if it's active
    const introspection = await this.introspectToken(
      accessToken,
      "access_token"
    );

    if (!introspection.active) {
      throw new BlitzWareAuthError("Token is not active", "token_inactive");
    }

    // If token is active, get user information
    return this.getUserInfo(accessToken);
  }

  /**
   * Parse API errors into BlitzWareAuthError instances
   */
  private parseApiError(
    error: any,
    fallbackMessage: string = "An authentication error occurred",
    fallbackCode: string = "auth_error"
  ): BlitzWareAuthError {
    // Check if it's an axios error with response data
    if (error?.response?.data) {
      const responseData = error.response.data;

      // Check if response matches our API error format
      if (responseData.code && responseData.message) {
        return new BlitzWareAuthError(
          responseData.message,
          responseData.code,
          responseData.details
        );
      }

      // Handle OAuth 2.0 standard error format
      if (responseData.error) {
        return new BlitzWareAuthError(
          responseData.error_description ||
            `OAuth error: ${responseData.error}`,
          responseData.error
        );
      }
    }

    // Check if it's already a BlitzWareAuthError
    if (error instanceof BlitzWareAuthError) {
      return error;
    }

    // Handle network errors
    if (error?.code === "ECONNREFUSED" || error?.code === "ETIMEDOUT") {
      return new BlitzWareAuthError(
        "Unable to connect to BlitzWare authentication service",
        "network_error"
      );
    }

    // Fallback to generic error
    return new BlitzWareAuthError(fallbackMessage, fallbackCode);
  }

  /**
   * Get the client configuration (without sensitive data)
   */
  public getConfig(): Omit<BlitzWareAuthConfig, "clientSecret"> {
    const { clientSecret, ...config } = this.config;
    return config;
  }
}
