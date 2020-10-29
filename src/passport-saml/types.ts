import type express from 'express';
import type { CacheProvider } from './inmemory-cache-provider';

export type CertCallback = (callback: (err: Error | null, cert?: string | string[]) => void) => void;

export interface SamlConfig {
    // Core
    callbackUrl?: string;
    path?: string;
    protocol?: string;
    host?: string;
    entryPoint?: string;
    issuer?: string;
    privateCert?: string;
    cert?: string | string[] | CertCallback;
    decryptionPvk?: string;
    signatureAlgorithm?: 'sha1' | 'sha256' | 'sha512';

    // Additional SAML behaviors
    additionalParams?: any;
    additionalAuthorizeParams?: any;
    identifierFormat?: string;
    acceptedClockSkewMs?: number;
    attributeConsumingServiceIndex?: string;
    disableRequestedAuthnContext?: boolean;
    authnContext?: string;
    forceAuthn?: boolean;
    skipRequestCompression?: boolean;
    authnRequestBinding?: string;
    RACComparison?: 'exact' | 'minimum' | 'maximum' | 'better';
    providerName?: string;
    passive?: boolean;
    idpIssuer?: string;
    audience?: string;

    // InResponseTo Validation
    validateInResponseTo?: boolean;
    requestIdExpirationPeriodMs?: number;
    cacheProvider?: CacheProvider;

    // Passport
    name?: string;
    passReqToCallback?: boolean;

    // Logout
    logoutUrl?: string;
    additionalLogoutParams?: any;
    logoutCallbackUrl?: string;
}

export type Profile = {
    issuer?: string;
    sessionIndex?: string;
    nameID?: string;
    nameIDFormat?: string;
    nameQualifier?: string;
    spNameQualifier?: string;
    ID?: string;
    mail?: string; // InCommon Attribute urn:oid:0.9.2342.19200300.100.1.3
    email?: string; // `mail` if not present in the assertion
    getAssertionXml(): string; // get the raw assertion XML
    getAssertion(): Record<string, unknown>; // get the assertion XML parsed as a JavaScript object
    getSamlResponseXml(): string; // get the raw SAML response XML
  } & {
    [attributeName: string]: unknown; // arbitrary `AttributeValue`s
  };
  
export type VerifiedCallback = (err: Error | null, user?: Record<string, unknown>, info?: Record<string, unknown>) => void;

export type VerifyWithRequest = (req: express.Request, profile: Profile, done: VerifiedCallback) => void;

export type VerifyWithoutRequest = (profile: Profile, done: VerifiedCallback) => void;
  