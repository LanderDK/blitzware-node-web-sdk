// Main exports for the BlitzWare Node.js SDK
export { BlitzWareAuth } from "./BlitzWareAuth";
export {
  BlitzWareAuthError,
  BlitzWareAuthConfig,
  BlitzWareUser,
  TokenResponse,
  TokenIntrospectionResponse,
  AuthorizationUrlParams,
  AuthorizationCallbackParams,
} from "./types";

export {
  expressAuth,
  expressRequiresAuth,
  expressRequiresRole,
  koaAuth,
  koaRequiresAuth,
  koaRequiresRole,
  AuthConfig,
} from "./middleware";

// Default export for convenience
export { BlitzWareAuth as default } from "./BlitzWareAuth";
