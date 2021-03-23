export type SignatureAlgorithm = "sha1" | "sha256" | "sha512";

export interface SamlSigningOptions {
  privateKey?: string | Buffer;
  signatureAlgorithm?: SignatureAlgorithm;
  xmlSignatureTransforms?: string[];
  digestAlgorithm?: string;
}

export interface AudienceRestrictionXML {
  Audience?: XMLObject[];
}

export type XMLValue = string | number | boolean | null | XMLObject | XMLValue[];

export type XMLObject = {
  [key: string]: XMLValue;
};

export type XMLInput = XMLObject;

export type XMLOutput = Record<string, any>;

export interface AuthorizeRequestXML {
  "samlp:AuthnRequest": XMLInput;
}

export type CertCallback = (
  callback: (err: Error | null, cert?: string | string[]) => void
) => void;

/**
 * These are SAML options that must be provided to construct a new SAML Strategy
 */
export interface MandatorySamlOptions {
  cert: string | string[] | CertCallback;
}

export interface SamlIDPListConfig {
  entries: SamlIDPEntryConfig[];
  getComplete?: string;
}

export interface SamlIDPEntryConfig {
  providerId: string;
  name?: string;
  loc?: string;
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
