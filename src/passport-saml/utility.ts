import { SignedXml } from "xml-crypto";
import { SamlSigningOptions } from "./types";
import * as algorithms from "./algorithms";

export function assertRequired<T>(value: T | null | undefined, error?: string): T {
  if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
    throw new TypeError(error ?? "value does not exist");
  } else {
    return value;
  }
}

export function signXml(samlMessage: string, xpath: string, options: SamlSigningOptions): string {
  const defaultTransforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ];

  if (!samlMessage) throw new Error("samlMessage is required");
  if (!xpath) throw new Error("xpath is required");
  if (!options) {
    options = {} as SamlSigningOptions;
  }

  if (options.privateCert) {
    console.warn("options.privateCert has been deprecated; use options.privateKey instead.");

    if (!options.privateKey) {
      options.privateKey = options.privateCert;
    }
  }

  if (!options.privateKey) throw new Error("options.privateKey is required");

  const transforms = options.xmlSignatureTransforms || defaultTransforms;
  const sig = new SignedXml();
  if (options.signatureAlgorithm) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference(xpath, transforms, algorithms.getDigestAlgorithm(options.digestAlgorithm));
  sig.signingKey = options.privateKey;
  sig.computeSignature(samlMessage, {
    location: { reference: xpath, action: "append" },
  });

  return sig.getSignedXml();
}

export function signXmlResponse(samlMessage: string, options: SamlSigningOptions): string {
  const responseXpath =
    '//*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

  return signXml(samlMessage, responseXpath, options);
}
