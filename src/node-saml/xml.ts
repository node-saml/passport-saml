import * as util from "util";
import * as xmlCrypto from "xml-crypto";
import * as xmlenc from "xml-encryption";
import * as xmldom from "@xmldom/xmldom";
import * as xml2js from "xml2js";
import * as xmlbuilder from "xmlbuilder";
import { isValidSamlSigningOptions, SamlSigningOptions } from "./types";
import * as algorithms from "./algorithms";

type SelectedValue = string | number | boolean | Node;

const selectXPath = <T extends SelectedValue>(
  guard: (values: SelectedValue[]) => values is T[],
  node: Node,
  xpath: string
): T[] => {
  const result = xmlCrypto.xpath(node, xpath);
  if (!guard(result)) {
    throw new Error("invalid xpath return type");
  }
  return result;
};

const attributesXPathTypeGuard = (values: SelectedValue[]): values is Attr[] => {
  return values.every((value) => {
    if (typeof value != "object") {
      return false;
    }
    return typeof value.nodeType === "number" && value.nodeType === value.ATTRIBUTE_NODE;
  });
};

const elementsXPathTypeGuard = (values: SelectedValue[]): values is Element[] => {
  return values.every((value) => {
    if (typeof value != "object") {
      return false;
    }
    return typeof value.nodeType === "number" && value.nodeType === value.ELEMENT_NODE;
  });
};

export const xpath = {
  selectAttributes: (node: Node, xpath: string): Attr[] =>
    selectXPath(attributesXPathTypeGuard, node, xpath),
  selectElements: (node: Node, xpath: string): Element[] =>
    selectXPath(elementsXPathTypeGuard, node, xpath),
};

export const decryptXml = async (xml: string, decryptionKey: string | Buffer) =>
  util.promisify(xmlenc.decrypt).bind(xmlenc)(xml, { key: decryptionKey });

const normalizeNewlines = (xml: string): string => {
  // we can use this utility before passing XML to `xml-crypto`
  // we are considered the XML processor and are responsible for newline normalization
  // https://github.com/node-saml/passport-saml/issues/431#issuecomment-718132752
  return xml.replace(/\r\n?/g, "\n");
};

const normalizeXml = (xml: string): string => {
  // we can use this utility to parse and re-stringify XML
  // `DOMParser` will take care of normalization tasks, like replacing XML-encoded carriage returns with actual carriage returns
  return parseDomFromString(xml).toString();
};

/**
 * This function checks that the |signature| is signed with a given |cert|.
 */
export const validateXmlSignatureForCert = (
  signature: Node,
  certPem: string,
  fullXml: string,
  currentNode: Element
): boolean => {
  const sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    file: "",
    getKeyInfo: () => "<X509Data></X509Data>",
    getKey: () => Buffer.from(certPem),
  };
  const signatureStr = normalizeNewlines(signature.toString());
  sig.loadSignature(signatureStr);
  // We expect each signature to contain exactly one reference to the top level of the xml we
  //   are validating, so if we see anything else, reject.
  if (sig.references.length != 1) return false;
  const refUri = sig.references[0].uri!;
  const refId = refUri[0] === "#" ? refUri.substring(1) : refUri;
  // If we can't find the reference at the top level, reject
  const idAttribute = currentNode.getAttribute("ID") ? "ID" : "Id";
  if (currentNode.getAttribute(idAttribute) != refId) return false;
  // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  //   multiple candidate references is bad news)
  const totalReferencedNodes = xpath.selectElements(
    currentNode.ownerDocument,
    "//*[@" + idAttribute + "='" + refId + "']"
  );

  if (totalReferencedNodes.length > 1) {
    return false;
  }
  // normalize XML to replace XML-encoded carriage returns with actual carriage returns
  fullXml = normalizeXml(fullXml);
  fullXml = normalizeNewlines(fullXml);
  return sig.checkSignature(fullXml);
};

interface XmlSignatureLocation {
  reference: string;
  action: "append" | "prepend" | "before" | "after";
}

export const signXml = (
  xml: string,
  xpath: string,
  location: XmlSignatureLocation,
  options: SamlSigningOptions
): string => {
  const defaultTransforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ];

  if (!xml) throw new Error("samlMessage is required");
  if (!location) throw new Error("location is required");
  if (!options) throw new Error("options is required");
  if (!isValidSamlSigningOptions(options)) throw new Error("options.privateKey is required");

  const transforms = options.xmlSignatureTransforms ?? defaultTransforms;
  const sig = new xmlCrypto.SignedXml();
  if (options.signatureAlgorithm != null) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference(xpath, transforms, algorithms.getDigestAlgorithm(options.digestAlgorithm));
  sig.signingKey = options.privateKey;
  sig.computeSignature(xml, {
    location,
  });

  return sig.getSignedXml();
};

export const parseDomFromString = (xml: string): Document => {
  return new xmldom.DOMParser().parseFromString(xml);
};

export const parseXml2JsFromString = async (xml: string | Buffer): Promise<any> => {
  const parserConfig = {
    explicitRoot: true,
    explicitCharkey: true,
    tagNameProcessors: [xml2js.processors.stripPrefix],
  };
  const parser = new xml2js.Parser(parserConfig);
  return parser.parseStringPromise(xml);
};

export const buildXml2JsObject = (rootName: string, xml: any): string => {
  const builderOpts = {
    rootName,
    headless: true,
  };
  return new xml2js.Builder(builderOpts).buildObject(xml);
};

export const buildXmlBuilderObject = (xml: Record<string, any>, pretty: boolean): string => {
  const options = pretty ? { pretty: true, indent: "  ", newline: "\n" } : {};
  return xmlbuilder.create(xml).end(options);
};
