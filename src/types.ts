import type * as express from "express";
import * as passport from "passport";
import { Profile, SamlConfig } from ".";

export interface AuthenticateOptions extends passport.AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  additionalParams?: Record<string, any>;
}

export interface StrategyOptions {
  name?: string;
  passReqToCallback?: boolean;
}

export type User = Record<string, unknown>;

export interface RequestWithUser extends express.Request {
  samlLogoutRequest: Profile;
  user: User;
}

export type VerifiedCallback = (
  err: Error | null,
  user?: Record<string, unknown>,
  info?: Record<string, unknown>
) => void;

export type VerifyWithRequest = (
  req: express.Request,
  profile: Profile | null,
  done: VerifiedCallback
) => void;

export type VerifyWithoutRequest = (profile: Profile | null, done: VerifiedCallback) => void;

export type PassportSamlConfig = SamlConfig & StrategyOptions;

export type StrategyOptionsCallback = (
  err: Error | null,
  samlOptions?: Partial<PassportSamlConfig>
) => void;

interface BaseMultiStrategyConfig {
  getSamlOptions(req: express.Request, callback: StrategyOptionsCallback): void;
}

export type MultiStrategyConfig = Partial<PassportSamlConfig> &
  StrategyOptions &
  BaseMultiStrategyConfig;

export class ErrorWithXmlStatus extends Error {
  constructor(message: string, public readonly xmlStatus: string) {
    super(message);
  }
}
