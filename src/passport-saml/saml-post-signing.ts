import { SignedXml } from 'xml-crypto';
import * as algorithms from './algorithms';
import { SAMLOptions } from './saml';

const authnRequestXPath = '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';
const issuerXPath = '/*[local-name(.)="Issuer" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:assertion"]';
const defaultTransforms = [ 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#' ];

export function signSamlPost(samlMessage: string, xpath: string, options: SAMLOptions) {
  if (!samlMessage) throw new Error('samlMessage is required');
  if (!xpath) throw new Error('xpath is required');
  if (!options || (!options.privateCert && !options.privateKey)) throw new Error('options.privateCert or options.privateKey is required');

  const transforms = options.xmlSignatureTransforms || defaultTransforms;
  const sig = new SignedXml();
  if (options.signatureAlgorithm) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference(xpath, transforms, algorithms.getDigestAlgorithm(options.digestAlgorithm));
  sig.signingKey = options.privateCert || options.privateKey;
  sig.computeSignature(samlMessage, { location: { reference: xpath + issuerXPath, action: 'after' }});
  return sig.getSignedXml();
}

export function signAuthnRequestPost(authnRequest: string, options: SAMLOptions) {
  return signSamlPost(authnRequest, authnRequestXPath, options);
}
