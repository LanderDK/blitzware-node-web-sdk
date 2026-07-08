import { BlitzWareUser } from './types';

declare global {
  namespace Express {
    interface Request {
      blitzware?: {
        user?: BlitzWareUser;
        accessToken?: string;
        idToken?: string;
        isAuthenticated(): boolean;
      };
    }
  }
}

export {};
