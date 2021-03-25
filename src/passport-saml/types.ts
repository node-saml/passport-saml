import type * as express from "express";
import * as passport from "passport";
import type { SamlOptions, MandatorySamlOptions, SamlIDPListConfig } from "../node-saml/types";

export interface AuthenticateOptions extends passport.AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
  additionalParams?: Record<string, any>;
}

export interface AuthorizeOptions extends AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
}

export interface StrategyOptions {
  name?: string;
  passReqToCallback?: boolean;
}

/**
 * These options are availble for configuring a SAML strategy
 */
export type SamlConfig = Partial<SamlOptions> & StrategyOptions & MandatorySamlOptions;

export interface Profile {
  issuer?: string;
  sessionIndex?: string;
  nameID?: string;
  nameIDFormat?: string;
  nameQualifier?: string;
  spNameQualifier?: string;
  ID?: string;
  mail?: string; // InCommon Attribute urn:oid:0.9.2342.19200300.100.1.3
  email?: string; // `mail` if not present in the assertion
  ["urn:oid:0.9.2342.19200300.100.1.3"]?: string;
  getAssertionXml?(): string; // get the raw assertion XML
  getAssertion?(): Record<string, unknown>; // get the assertion XML parsed as a JavaScript object
  getSamlResponseXml?(): string; // get the raw SAML response XML
  [attributeName: string]: unknown; // arbitrary `AttributeValue`s
}

export interface RequestWithUser extends express.Request {
  samlLogoutRequest: any;
  user?: Profile;
}

export type VerifiedCallback = (
  err: Error | null,
  user?: Record<string, unknown>,
  info?: Record<string, unknown>
) => void;

export type VerifyWithRequest = (
  req: express.Request,
  profile: Profile | null | undefined,
  done: VerifiedCallback
) => void;

export type VerifyWithoutRequest = (
  profile: Profile | null | undefined,
  done: VerifiedCallback
) => void;

export type SamlOptionsCallback = (err: Error | null, samlOptions?: SamlConfig) => void;

interface BaseMultiSamlConfig {
  getSamlOptions(req: express.Request, callback: SamlOptionsCallback): void;
}

export type MultiSamlConfig = Partial<SamlConfig> & StrategyOptions & BaseMultiSamlConfig;
