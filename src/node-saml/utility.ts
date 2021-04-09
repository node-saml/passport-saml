import { SamlSigningOptions } from "./types";
import { signXml } from "./xml";

export function assertRequired<T>(value: T | null | undefined, error?: string): T {
  if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
    throw new TypeError(error ?? "value does not exist");
  } else {
    return value;
  }
}

export function signXmlResponse(samlMessage: string, options: SamlSigningOptions): string {
  const responseXpath =
    '//*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

  return signXml(
    samlMessage,
    responseXpath,
    { reference: responseXpath, action: "append" },
    options
  );
}
