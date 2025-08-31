import { BlitzWareAuth } from "../BlitzWareAuth";
import { BlitzWareAuthError } from "../types";

describe("BlitzWareAuth", () => {
  const validConfig = {
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    redirectUri: "http://localhost:3000/callback",
  };

  describe("constructor", () => {
    it("should create instance with valid config", () => {
      const auth = new BlitzWareAuth(validConfig);
      expect(auth).toBeInstanceOf(BlitzWareAuth);
    });

    it("should throw error when clientId is missing", () => {
      expect(() => {
        new BlitzWareAuth({
          ...validConfig,
          clientId: "",
        });
      }).toThrow(BlitzWareAuthError);
    });

    it("should throw error when clientSecret is missing", () => {
      expect(() => {
        new BlitzWareAuth({
          ...validConfig,
          clientSecret: "",
        });
      }).toThrow(BlitzWareAuthError);
    });

    it("should throw error when redirectUri is missing", () => {
      expect(() => {
        new BlitzWareAuth({
          ...validConfig,
          redirectUri: "",
        });
      }).toThrow(BlitzWareAuthError);
    });

    it("should create instance with valid config", () => {
      const auth = new BlitzWareAuth(validConfig);
      const config = auth.getConfig();

      expect(config.clientId).toBe(validConfig.clientId);
      expect(config.redirectUri).toBe(validConfig.redirectUri);
      // clientSecret should not be included in getConfig()
      expect("clientSecret" in config).toBe(false);
    });
  });

  describe("generateState", () => {
    it("should generate a random state string", () => {
      const auth = new BlitzWareAuth(validConfig);
      const state1 = auth.generateState();
      const state2 = auth.generateState();

      expect(typeof state1).toBe("string");
      expect(typeof state2).toBe("string");
      expect(state1).not.toBe(state2);
      expect(state1.length).toBeGreaterThan(0);
    });
  });

  describe("PKCE", () => {
    let auth: BlitzWareAuth;

    beforeEach(() => {
      auth = new BlitzWareAuth(validConfig);
    });

    it("should generate a code verifier", () => {
      const verifier = auth.generateCodeVerifier();
      expect(typeof verifier).toBe("string");
      expect(verifier.length).toBeGreaterThan(0);
    });

    it("should generate unique code verifiers", () => {
      const verifier1 = auth.generateCodeVerifier();
      const verifier2 = auth.generateCodeVerifier();
      expect(verifier1).not.toBe(verifier2);
    });

    it("should generate a code challenge from verifier", () => {
      const verifier = auth.generateCodeVerifier();
      const challenge = auth.generateCodeChallenge(verifier);

      expect(typeof challenge).toBe("string");
      expect(challenge.length).toBeGreaterThan(0);
      expect(challenge).not.toBe(verifier);
    });

    it("should generate same challenge for same verifier", () => {
      const verifier = "test-verifier";
      const challenge1 = auth.generateCodeChallenge(verifier);
      const challenge2 = auth.generateCodeChallenge(verifier);
      expect(challenge1).toBe(challenge2);
    });
  });

  describe("getAuthorizationUrl", () => {
    let auth: BlitzWareAuth;

    beforeEach(() => {
      auth = new BlitzWareAuth(validConfig);
    });

    it("should generate authorization URL with required parameters", () => {
      const result = auth.getAuthorizationUrl();
      const urlObj = new URL(result.url);

      expect(urlObj.searchParams.get("response_type")).toBe("code");
      expect(urlObj.searchParams.get("client_id")).toBe(validConfig.clientId);
      expect(urlObj.searchParams.get("redirect_uri")).toBe(
        validConfig.redirectUri
      );
      expect(urlObj.searchParams.get("code_challenge")).toBeTruthy();
      expect(urlObj.searchParams.get("code_challenge_method")).toBe("S256");
      expect(result.codeVerifier).toBeTruthy();
    });

    it("should include optional parameters when provided", () => {
      const params = {
        state: "test-state",
        scope: "read write",
        additionalParams: {
          prompt: "consent",
          max_age: "3600",
        },
      };

      const result = auth.getAuthorizationUrl(params);
      const urlObj = new URL(result.url);

      expect(urlObj.searchParams.get("state")).toBe(params.state);
      expect(urlObj.searchParams.get("prompt")).toBe(
        params.additionalParams.prompt
      );
      expect(urlObj.searchParams.get("max_age")).toBe(
        params.additionalParams.max_age
      );
      expect(urlObj.searchParams.get("code_challenge")).toBeTruthy();
      expect(urlObj.searchParams.get("code_challenge_method")).toBe("S256");
      expect(result.codeVerifier).toBeTruthy();
    });

    it("should use default response_type if not specified", () => {
      const result = auth.getAuthorizationUrl();
      const urlObj = new URL(result.url);

      expect(urlObj.searchParams.get("response_type")).toBe("code");
    });
  });

  describe("handleCallback", () => {
    let auth: BlitzWareAuth;

    beforeEach(() => {
      auth = new BlitzWareAuth(validConfig);
    });

    it("should throw error when authorization error is present", async () => {
      const callbackParams = {
        error: "access_denied",
        error_description: "User denied access",
      };

      await expect(auth.handleCallback(callbackParams)).rejects.toThrow(
        BlitzWareAuthError
      );
    });

    it("should throw error when code is missing", async () => {
      const callbackParams = {};

      await expect(auth.handleCallback(callbackParams)).rejects.toThrow(
        BlitzWareAuthError
      );
    });

    it("should throw error when state parameter does not match", async () => {
      const callbackParams = {
        code: "test-code",
        state: "received-state",
      };
      const expectedState = "expected-state";

      await expect(
        auth.handleCallback(callbackParams, expectedState)
      ).rejects.toThrow(BlitzWareAuthError);
    });

    // Note: Full integration tests would require mocking the HTTP client
    // or running against a test server
  });

  describe("getConfig", () => {
    it("should return config without client secret", () => {
      const auth = new BlitzWareAuth(validConfig);
      const config = auth.getConfig();

      expect(config.clientId).toBe(validConfig.clientId);
      expect(config.redirectUri).toBe(validConfig.redirectUri);
      expect(config).not.toHaveProperty("clientSecret");
    });
  });

  describe("logout", () => {
    let auth: BlitzWareAuth;

    beforeEach(() => {
      auth = new BlitzWareAuth(validConfig);
    });

    it("should call logout endpoint with client_id", async () => {
      // Mock the HTTP client post method
      const mockPost = jest.fn().mockResolvedValue({ data: {} });
      (auth as any).httpClient.post = mockPost;

      await auth.logout();

      expect(mockPost).toHaveBeenCalledWith("/logout", {
        client_id: validConfig.clientId,
      });
    });

    it("should throw BlitzWareAuthError on failure", async () => {
      // Mock the HTTP client to throw an error
      const mockPost = jest.fn().mockRejectedValue(new Error("Network error"));
      (auth as any).httpClient.post = mockPost;

      await expect(auth.logout()).rejects.toThrow(BlitzWareAuthError);
    });
  });

  describe("revokeToken", () => {
    let auth: BlitzWareAuth;

    beforeEach(() => {
      auth = new BlitzWareAuth(validConfig);
    });

    it("should call revoke endpoint with token and client credentials", async () => {
      const mockPost = jest.fn().mockResolvedValue({ data: {} });
      (auth as any).httpClient.post = mockPost;

      const token = "test-access-token";
      await auth.revokeToken(token, "access_token");

      expect(mockPost).toHaveBeenCalledWith("/revoke", {
        token,
        client_id: validConfig.clientId,
        client_secret: validConfig.clientSecret,
        token_type_hint: "access_token",
      });
    });

    it("should throw error for missing token", async () => {
      await expect(auth.revokeToken("")).rejects.toThrow(BlitzWareAuthError);
    });
  });
});
