import type * as express from "express";
import * as passport from "passport";
import type { CacheProvider } from "./inmemory-cache-provider";

export type CertCallback = (
  callback: (err: Error | null, cert?: string | string[]) => void
) => void;
export type RacComparision = "exact" | "minimum" | "maximum" | "better";
export type SignatureAlgorithm = "sha1" | "sha256" | "sha512";

export interface AuthenticateOptions extends passport.AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
  additionalParams?: Record<string, any>;
}

export interface AuthorizeOptions extends AuthenticateOptions {
  samlFallback?: "login-request" | "logout-request";
}

export interface SamlSigningOptions {
  /** @deprecated use privateKey field instead */
  privateCert?: string | Buffer;
  privateKey?: string | Buffer;
  signatureAlgorithm?: SignatureAlgorithm;
  xmlSignatureTransforms?: string[];
  digestAlgorithm?: string;
}

/**
 * These are SAML options that must be provided to construct a new SAML Strategy
 */
export interface MandatorySamlOptions {
  cert: string | string[] | CertCallback;
}

/**
 * The options required to use a SAML strategy
 * These may be provided by means of defaults specified in the constructor
 */
export interface SamlOptions extends SamlSigningOptions, MandatorySamlOptions {
  // Core
  callbackUrl?: string;
  path: string;
  protocol?: string;
  host: string;
  entryPoint?: string;
  issuer: string;
  decryptionPvk?: string | Buffer;

  // Additional SAML behaviors
  additionalParams: Record<string, string>;
  additionalAuthorizeParams: Record<string, string>;
  identifierFormat?: string | null;
  acceptedClockSkewMs: number;
  attributeConsumingServiceIndex?: string;
  disableRequestedAuthnContext: boolean;
  authnContext: string[];
  forceAuthn: boolean;
  skipRequestCompression: boolean;
  authnRequestBinding?: string;
  racComparison: RacComparision;
  providerName?: string;
  passive: boolean;
  idpIssuer?: string;
  audience?: string;
  scoping?: SamlScopingConfig;
  wantAssertionsSigned?: boolean;

  // InResponseTo Validation
  validateInResponseTo: boolean;
  requestIdExpirationPeriodMs: number;
  cacheProvider: CacheProvider;

  // Logout
  logoutUrl: string;
  additionalLogoutParams: Record<string, string>;
  logoutCallbackUrl?: string;

  // extras
  disableRequestAcsUrl: boolean;
}
export interface StrategyOptions {
  name?: string;
  passReqToCallback?: boolean;
}

/**
 * These options are availble for configuring a SAML strategy
 */
export type SamlConfig = Partial<SamlOptions> & StrategyOptions & MandatorySamlOptions;

export interface SamlScopingConfig {
  idpList?: SamlIDPListConfig[];
  proxyCount?: number;
  requesterId?: string[] | string;
}

export type XMLValue = string | number | boolean | null | XMLObject | XMLValue[];

export type XMLObject = {
  [key: string]: XMLValue;
};

export type XMLInput = XMLObject;

export interface AuthorizeRequestXML {
  "samlp:AuthnRequest": XMLInput;
}

export interface LogoutRequestXML {
  "samlp:LogoutRequest": {
    "saml:NameID": XMLInput;
    [key: string]: XMLValue;
  };
}

export interface ServiceMetadataXML {
  EntityDescriptor: {
    [key: string]: XMLValue;
    SPSSODescriptor: XMLObject;
  };
}

export interface AudienceRestrictionXML {
  Audience?: XMLObject[];
}

export type XMLOutput = Record<string, any>;

export interface SamlIDPListConfig {
  entries: SamlIDPEntryConfig[];
  getComplete?: string;
}

export interface SamlIDPEntryConfig {
  providerId: string;
  name?: string;
  loc?: string;
}

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
