export type SignatureAlgorithm = "sha1" | "sha256" | "sha512";

export interface SamlSigningOptions {
  privateKey?: string | Buffer;
  signatureAlgorithm?: SignatureAlgorithm;
  xmlSignatureTransforms?: string[];
  digestAlgorithm?: string;
}
