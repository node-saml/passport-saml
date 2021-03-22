import { SamlSigningOptions } from "./types";
import { signXml } from "./xml";

const authnRequestXPath =
  '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';
const issuerXPath =
  '/*[local-name(.)="Issuer" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:assertion"]';

export function signSamlPost(
  samlMessage: string,
  xpath: string,
  options: SamlSigningOptions
): string {
  return signXml(samlMessage, xpath, { reference: xpath + issuerXPath, action: "after" }, options);
}

export function signAuthnRequestPost(authnRequest: string, options: SamlSigningOptions): string {
  return signSamlPost(authnRequest, authnRequestXPath, options);
}
