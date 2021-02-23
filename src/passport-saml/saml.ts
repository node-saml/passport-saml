import Debug from "debug";
const debug = Debug("passport-saml");
import * as zlib from "zlib";
import * as xml2js from "xml2js";
import * as xmlCrypto from "xml-crypto";
import * as crypto from "crypto";
import * as xmldom from "xmldom";
import * as url from "url";
import * as querystring from "querystring";
import * as xmlbuilder from "xmlbuilder";
import * as xmlenc from "xml-encryption";
import * as util from "util";
import { CacheProvider as InMemoryCacheProvider } from "./inmemory-cache-provider";
import * as algorithms from "./algorithms";
import { signAuthnRequestPost } from "./saml-post-signing";
import type { Request } from "express";
import { ParsedQs } from "qs";
import {
  AudienceRestrictionXML,
  AuthenticateOptions,
  AuthorizeOptions,
  AuthorizeRequestXML,
  CertCallback,
  LogoutRequestXML,
  Profile,
  RequestWithUser,
  SamlOptions,
  SamlIDPListConfig,
  SamlIDPEntryConfig,
  SamlScopingConfig,
  ServiceMetadataXML,
  XMLInput,
  XMLObject,
  XMLOutput,
  XMLValue,
} from "./types";

const inflateRawAsync = util.promisify(zlib.inflateRaw);
const deflateRawAsync = util.promisify(zlib.deflateRaw);

interface NameID {
  value: string | null;
  format: string | null;
}

async function processValidlySignedPostRequestAsync(
  self: SAML,
  doc: XMLOutput,
  dom: Document
): Promise<{ profile?: Profile; loggedOut?: boolean }> {
  const request = doc.LogoutRequest;
  if (request) {
    const profile = {} as Profile;
    if (request.$.ID) {
      profile.ID = request.$.ID;
    } else {
      throw new Error("Missing SAML LogoutRequest ID");
    }
    const issuer = request.Issuer;
    if (issuer && issuer[0]._) {
      profile.issuer = issuer[0]._;
    } else {
      throw new Error("Missing SAML issuer");
    }
    const nameID = await self.getNameIDAsync(self, dom);
    if (nameID) {
      profile.nameID = nameID.value!;
      if (nameID.format) {
        profile.nameIDFormat = nameID.format;
      }
    } else {
      throw new Error("Missing SAML NameID");
    }
    const sessionIndex = request.SessionIndex;
    if (sessionIndex) {
      profile.sessionIndex = sessionIndex[0]._;
    }
    return { profile, loggedOut: true };
  } else {
    throw new Error("Unknown SAML request message");
  }
}

async function processValidlySignedSamlLogoutAsync(
  self: SAML,
  doc: XMLOutput,
  dom: Document
): Promise<{ profile?: Profile | null; loggedOut?: boolean }> {
  const response = doc.LogoutResponse;
  const request = doc.LogoutRequest;

  if (response) {
    return { profile: null, loggedOut: true };
  } else if (request) {
    return await processValidlySignedPostRequestAsync(self, doc, dom);
  } else {
    throw new Error("Unknown SAML response message");
  }
}

async function promiseWithNameID(nameid: Node): Promise<NameID> {
  const format = xmlCrypto.xpath(nameid, "@Format") as Node[];
  return {
    value: nameid.textContent,
    format: format && format[0] && format[0].nodeValue,
  };
}

class SAML {
  options: SamlOptions;
  cacheProvider: InMemoryCacheProvider;

  constructor(options: Partial<SamlOptions>) {
    this.options = this.initialize(options);
    this.cacheProvider = this.options.cacheProvider;
  }
  initialize(options: Partial<SamlOptions>): SamlOptions {
    if (!options) {
      options = {};
    }

    if (options.privateCert) {
      console.warn("options.privateCert has been deprecated; use options.privateKey instead.");

      if (!options.privateKey) {
        options.privateKey = options.privateCert;
      }
    }

    if (Object.prototype.hasOwnProperty.call(options, "cert") && !options.cert) {
      throw new Error("Invalid property: cert must not be empty");
    }

    if (!options.path) {
      options.path = "/saml/consume";
    }

    if (!options.host) {
      options.host = "localhost";
    }

    if (!options.issuer) {
      options.issuer = "onelogin_saml";
    }

    if (options.identifierFormat === undefined) {
      options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    }

    if (options.authnContext === undefined) {
      options.authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    }

    if (!Array.isArray(options.authnContext)) {
      options.authnContext = [options.authnContext];
    }

    if (!options.acceptedClockSkewMs) {
      // default to no skew
      options.acceptedClockSkewMs = 0;
    }

    if (!options.validateInResponseTo) {
      options.validateInResponseTo = false;
    }

    if (!options.requestIdExpirationPeriodMs) {
      options.requestIdExpirationPeriodMs = 28800000; // 8 hours
    }

    if (!options.cacheProvider) {
      options.cacheProvider = new InMemoryCacheProvider({
        keyExpirationPeriodMs: options.requestIdExpirationPeriodMs,
      });
    }

    if (!options.logoutUrl) {
      // Default to Entry Point
      options.logoutUrl = options.entryPoint || "";
    }

    // sha1, sha256, or sha512
    if (!options.signatureAlgorithm) {
      options.signatureAlgorithm = "sha1";
    }

    /**
     * List of possible values:
     * - exact : Assertion context must exactly match a context in the list
     * - minimum:  Assertion context must be at least as strong as a context in the list
     * - maximum:  Assertion context must be no stronger than a context in the list
     * - better:  Assertion context must be stronger than all contexts in the list
     */
    if (
      !options.RACComparison ||
      ["exact", "minimum", "maximum", "better"].indexOf(options.RACComparison) === -1
    ) {
      options.RACComparison = "exact";
    }

    options.authnRequestBinding = options.authnRequestBinding || "HTTP-Redirect";

    return options as SamlOptions;
  }

  getProtocol(req: Request | { headers?: undefined; protocol?: undefined }) {
    return this.options.protocol || (req.protocol || "http").concat("://");
  }

  getCallbackUrl(req: Request | { headers?: undefined; protocol?: undefined }) {
    // Post-auth destination
    if (this.options.callbackUrl) {
      return this.options.callbackUrl;
    } else {
      let host;
      if (req.headers) {
        host = req.headers.host;
      } else {
        host = this.options.host;
      }
      return this.getProtocol(req) + host + this.options.path;
    }
  }

  generateUniqueID() {
    return crypto.randomBytes(10).toString("hex");
  }

  generateInstant() {
    return new Date().toISOString();
  }

  signRequest(samlMessage: querystring.ParsedUrlQueryInput) {
    const samlMessageToSign: querystring.ParsedUrlQueryInput = {};
    samlMessage.SigAlg = algorithms.getSigningAlgorithm(this.options.signatureAlgorithm);
    const signer = algorithms.getSigner(this.options.signatureAlgorithm);
    if (samlMessage.SAMLRequest) {
      samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
    }
    if (samlMessage.SAMLResponse) {
      samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse;
    }
    if (samlMessage.RelayState) {
      samlMessageToSign.RelayState = samlMessage.RelayState;
    }
    if (samlMessage.SigAlg) {
      samlMessageToSign.SigAlg = samlMessage.SigAlg;
    }
    signer.update(querystring.stringify(samlMessageToSign));
    samlMessage.Signature = signer.sign(this.keyToPEM(this.options.privateKey), "base64");
  }

  async generateAuthorizeRequestAsync(
    req: Request,
    isPassive: boolean,
    isHttpPostBinding: boolean
  ): Promise<string | undefined> {
    const id = "_" + this.generateUniqueID();
    const instant = this.generateInstant();
    const forceAuthn = this.options.forceAuthn || false;

    if (this.options.validateInResponseTo) {
      await this.cacheProvider.saveAsync(id, instant);
    }
    const request: AuthorizeRequestXML = {
      "samlp:AuthnRequest": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instant,
        "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Destination": this.options.entryPoint,
        "saml:Issuer": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": this.options.issuer,
        },
      },
    };

    if (isPassive) request["samlp:AuthnRequest"]["@IsPassive"] = true;

    if (forceAuthn) {
      request["samlp:AuthnRequest"]["@ForceAuthn"] = true;
    }

    if (!this.options.disableRequestACSUrl) {
      request["samlp:AuthnRequest"]["@AssertionConsumerServiceURL"] = this.getCallbackUrl(req);
    }

    if (this.options.identifierFormat) {
      request["samlp:AuthnRequest"]["samlp:NameIDPolicy"] = {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@Format": this.options.identifierFormat,
        "@AllowCreate": "true",
      };
    }

    if (!this.options.disableRequestedAuthnContext) {
      const authnContextClassRefs: XMLInput[] = [];
      (this.options.authnContext as string[]).forEach(function (value) {
        authnContextClassRefs.push({
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": value,
        });
      });

      request["samlp:AuthnRequest"]["samlp:RequestedAuthnContext"] = {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@Comparison": this.options.RACComparison,
        "saml:AuthnContextClassRef": authnContextClassRefs,
      };
    }

    if (this.options.attributeConsumingServiceIndex != null) {
      request["samlp:AuthnRequest"][
        "@AttributeConsumingServiceIndex"
      ] = this.options.attributeConsumingServiceIndex;
    }

    if (this.options.providerName) {
      request["samlp:AuthnRequest"]["@ProviderName"] = this.options.providerName;
    }

    if (this.options.scoping) {
      const scoping: XMLInput = {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      };

      if (typeof this.options.scoping.proxyCount === "number") {
        scoping["@ProxyCount"] = this.options.scoping.proxyCount;
      }

      if (this.options.scoping.idpList) {
        scoping["samlp:IDPList"] = this.options.scoping.idpList.map(
          (idpListItem: SamlIDPListConfig) => {
            const formattedIdpListItem: XMLInput = {
              "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            };

            if (idpListItem.entries) {
              formattedIdpListItem["samlp:IDPEntry"] = idpListItem.entries.map(
                (entry: SamlIDPEntryConfig) => {
                  const formattedEntry: XMLInput = {
                    "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                  };

                  formattedEntry["@ProviderID"] = entry.providerId;

                  if (entry.name) {
                    formattedEntry["@Name"] = entry.name;
                  }

                  if (entry.loc) {
                    formattedEntry["@Loc"] = entry.loc;
                  }

                  return formattedEntry;
                }
              );
            }

            if (idpListItem.getComplete) {
              formattedIdpListItem["samlp:GetComplete"] = idpListItem.getComplete;
            }

            return formattedIdpListItem;
          }
        );
      }

      if (this.options.scoping.requesterId) {
        scoping["samlp:RequesterID"] = this.options.scoping.requesterId;
      }

      request["samlp:AuthnRequest"]["samlp:Scoping"] = scoping;
    }

    let stringRequest = xmlbuilder.create((request as unknown) as Record<string, any>).end();
    if (isHttpPostBinding && this.options.privateKey) {
      stringRequest = signAuthnRequestPost(stringRequest, this.options);
    }
    return stringRequest;
  }

  async generateLogoutRequest(req: RequestWithUser) {
    const id = "_" + this.generateUniqueID();
    const instant = this.generateInstant();

    const request = {
      "samlp:LogoutRequest": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instant,
        "@Destination": this.options.logoutUrl,
        "saml:Issuer": {
          "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "#text": this.options.issuer,
        },
        "saml:NameID": {
          "@Format": req.user!.nameIDFormat,
          "#text": req.user!.nameID,
        },
      },
    } as LogoutRequestXML;

    if (req.user!.nameQualifier != null) {
      request["samlp:LogoutRequest"]["saml:NameID"]["@NameQualifier"] = req.user!.nameQualifier;
    }

    if (req.user!.spNameQualifier != null) {
      request["samlp:LogoutRequest"]["saml:NameID"]["@SPNameQualifier"] = req.user!.spNameQualifier;
    }

    if (req.user!.sessionIndex) {
      request["samlp:LogoutRequest"]["saml2p:SessionIndex"] = {
        "@xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        "#text": req.user!.sessionIndex,
      };
    }

    await this.cacheProvider.saveAsync(id, instant);
    return xmlbuilder.create((request as unknown) as Record<string, any>).end();
  }

  generateLogoutResponse(req: Request, logoutRequest: Profile) {
    const id = "_" + this.generateUniqueID();
    const instant = this.generateInstant();

    const request = {
      "samlp:LogoutResponse": {
        "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "@ID": id,
        "@Version": "2.0",
        "@IssueInstant": instant,
        "@Destination": this.options.logoutUrl,
        "@InResponseTo": logoutRequest.ID,
        "saml:Issuer": {
          "#text": this.options.issuer,
        },
        "samlp:Status": {
          "samlp:StatusCode": {
            "@Value": "urn:oasis:names:tc:SAML:2.0:status:Success",
          },
        },
      },
    };

    return xmlbuilder.create(request).end();
  }

  async requestToUrlAsync(
    request: string | null | undefined,
    response: string | null,
    operation: string,
    additionalParameters: querystring.ParsedUrlQuery
  ): Promise<string> {
    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from((request || response)!, "utf8");
    } else {
      buffer = await deflateRawAsync((request || response)!);
    }

    const base64 = buffer.toString("base64");
    let target = url.parse(this.options.entryPoint, true);

    if (operation === "logout") {
      if (this.options.logoutUrl) {
        target = url.parse(this.options.logoutUrl, true);
      }
    } else if (operation !== "authorize") {
      throw new Error("Unknown operation: " + operation);
    }

    const samlMessage: querystring.ParsedUrlQuery = request
      ? {
          SAMLRequest: base64,
        }
      : {
          SAMLResponse: base64,
        };
    Object.keys(additionalParameters).forEach((k) => {
      samlMessage[k] = additionalParameters[k];
    });
    if (this.options.privateKey) {
      if (!this.options.entryPoint) {
        throw new Error('"entryPoint" config parameter is required for signed messages');
      }

      // sets .SigAlg and .Signature
      this.signRequest(samlMessage);
    }
    Object.keys(samlMessage).forEach((k) => {
      target.query[k] = samlMessage[k];
    });

    // Delete 'search' to for pulling query string from 'query'
    // https://nodejs.org/api/url.html#url_url_format_urlobj
    target.search = null;

    return url.format(target);
  }

  getAdditionalParams(
    req: Request,
    operation: string,
    overrideParams?: querystring.ParsedUrlQuery
  ) {
    const additionalParams: querystring.ParsedUrlQuery = {};

    const RelayState = (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
    if (RelayState) {
      additionalParams.RelayState = RelayState;
    }

    const optionsAdditionalParams = this.options.additionalParams || {};
    Object.keys(optionsAdditionalParams).forEach(function (k) {
      additionalParams[k] = optionsAdditionalParams[k];
    });

    let optionsAdditionalParamsForThisOperation: Record<string, string> = {};
    if (operation == "authorize") {
      optionsAdditionalParamsForThisOperation = this.options.additionalAuthorizeParams || {};
    }
    if (operation == "logout") {
      optionsAdditionalParamsForThisOperation = this.options.additionalLogoutParams || {};
    }

    Object.keys(optionsAdditionalParamsForThisOperation).forEach(function (k) {
      additionalParams[k] = optionsAdditionalParamsForThisOperation[k];
    });

    overrideParams = overrideParams || {};
    Object.keys(overrideParams).forEach(function (k) {
      additionalParams[k] = overrideParams![k];
    });

    return additionalParams;
  }

  async getAuthorizeUrlAsync(req: Request, options: AuthorizeOptions): Promise<string> {
    const request = await this.generateAuthorizeRequestAsync(req, this.options.passive, false);
    const operation = "authorize";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this.requestToUrlAsync(
      request,
      null,
      operation,
      this.getAdditionalParams(req, operation, overrideParams)
    );
  }

  async getAuthorizeFormAsync(req: Request) {
    // The quoteattr() function is used in a context, where the result will not be evaluated by javascript
    // but must be interpreted by an XML or HTML parser, and it must absolutely avoid breaking the syntax
    // of an element attribute.
    const quoteattr = function (
      s:
        | string
        | number
        | boolean
        | undefined
        | null
        | readonly string[]
        | readonly number[]
        | readonly boolean[],
      preserveCR?: boolean
    ) {
      const preserveCRChar = preserveCR ? "&#13;" : "\n";
      return (
        ("" + s) // Forces the conversion to string.
          .replace(/&/g, "&amp;") // This MUST be the 1st replacement.
          .replace(/'/g, "&apos;") // The 4 other predefined entities, required.
          .replace(/"/g, "&quot;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          // Add other replacements here for HTML only
          // Or for XML, only if the named entities are defined in its DTD.
          .replace(/\r\n/g, preserveCRChar) // Must be before the next replacement.
          .replace(/[\r\n]/g, preserveCRChar)
      );
    };

    const request = await this.generateAuthorizeRequestAsync(req, this.options.passive, true);
    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from(request!, "utf8");
    } else {
      buffer = await deflateRawAsync(request!);
    }

    const operation = "authorize";
    const additionalParameters = this.getAdditionalParams(req, operation);
    const samlMessage: querystring.ParsedUrlQueryInput = {
      SAMLRequest: buffer!.toString("base64"),
    };

    Object.keys(additionalParameters).forEach((k) => {
      samlMessage[k] = additionalParameters[k] || "";
    });

    const formInputs = Object.keys(samlMessage)
      .map((k) => {
        return '<input type="hidden" name="' + k + '" value="' + quoteattr(samlMessage[k]) + '" />';
      })
      .join("\r\n");

    return [
      "<!DOCTYPE html>",
      "<html>",
      "<head>",
      '<meta charset="utf-8">',
      '<meta http-equiv="x-ua-compatible" content="ie=edge">',
      "</head>",
      '<body onload="document.forms[0].submit()">',
      "<noscript>",
      "<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>",
      "</noscript>",
      '<form method="post" action="' + encodeURI(this.options.entryPoint) + '">',
      formInputs,
      '<input type="submit" value="Submit" />',
      "</form>",
      '<script>document.forms[0].style.display="none";</script>', // Hide the form if JavaScript is enabled
      "</body>",
      "</html>",
    ].join("\r\n");
  }

  async getLogoutUrlAsync(req: RequestWithUser, options: AuthenticateOptions & AuthorizeOptions) {
    const request = await this.generateLogoutRequest(req);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this.requestToUrlAsync(
      request,
      null,
      operation,
      this.getAdditionalParams(req, operation, overrideParams)
    );
  }

  getLogoutResponseUrl(
    req: RequestWithUser,
    options: AuthenticateOptions & AuthorizeOptions,
    callback: (err: Error | null, url?: string | null) => void
  ) {
    util.callbackify(() => this.getLogoutResponseUrlAsync(req, options))(callback);
  }
  async getLogoutResponseUrlAsync(
    req: RequestWithUser,
    options: AuthenticateOptions & AuthorizeOptions
  ) {
    const response = this.generateLogoutResponse(req, req.samlLogoutRequest);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this.requestToUrlAsync(
      null,
      response,
      operation,
      this.getAdditionalParams(req, operation, overrideParams)
    );
  }

  certToPEM(cert: string): string {
    cert = cert.match(/.{1,64}/g)!.join("\n");

    if (cert.indexOf("-BEGIN CERTIFICATE-") === -1) cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    if (cert.indexOf("-END CERTIFICATE-") === -1) cert = cert + "\n-----END CERTIFICATE-----\n";

    return cert;
  }

  async certsToCheck(): Promise<undefined | string[]> {
    if (!this.options.cert) {
      return undefined;
    }
    if (typeof this.options.cert === "function") {
      return util
        .promisify(this.options.cert as CertCallback)()
        .then((certs) => {
          if (!Array.isArray(certs)) {
            certs = [certs as string];
          }
          return certs as string[];
        });
    }
    let certs = this.options.cert;
    if (!Array.isArray(certs)) {
      certs = [certs];
    }
    return certs;
  }

  // This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
  //   signature of the |currentNode|.
  //
  // See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
  //   vectors against SAML signature verification.
  validateSignature(fullXml: string, currentNode: HTMLElement, certs: string[]) {
    const xpathSigQuery =
      ".//*[" +
      "local-name(.)='Signature' and " +
      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
      "descendant::*[local-name(.)='Reference' and @URI='#" +
      currentNode.getAttribute("ID") +
      "']" +
      "]";
    const signatures = xmlCrypto.xpath(currentNode, xpathSigQuery);
    // This function is expecting to validate exactly one signature, so if we find more or fewer
    //   than that, reject.
    if (signatures.length != 1) {
      return false;
    }

    const signature = signatures[0];
    return certs.some((certToCheck) => {
      return this.validateSignatureForCert(signature as string, certToCheck, fullXml, currentNode);
    });
  }

  // This function checks that the |signature| is signed with a given |cert|.
  validateSignatureForCert(
    signature: string | Node,
    cert: string,
    fullXml: string,
    currentNode: HTMLElement
  ) {
    const sig = new xmlCrypto.SignedXml();
    sig.keyInfoProvider = {
      file: "",
      getKeyInfo: (key) => "<X509Data></X509Data>",
      getKey: (keyInfo) => Buffer.from(this.certToPEM(cert)),
    };
    signature = this.normalizeNewlines(signature.toString());
    sig.loadSignature(signature);
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
    const totalReferencedNodes = xmlCrypto.xpath(
      currentNode.ownerDocument,
      "//*[@" + idAttribute + "='" + refId + "']"
    );

    if (totalReferencedNodes.length > 1) {
      return false;
    }
    fullXml = this.normalizeNewlines(fullXml);
    return sig.checkSignature(fullXml);
  }

  async validatePostResponseAsync(
    container: Record<string, string>
  ): Promise<{ profile?: Profile | null; loggedOut?: boolean }> {
    let xml: string, doc: Document, inResponseTo: string | null;
    try {
      xml = Buffer.from(container.SAMLResponse, "base64").toString("utf8");
      doc = new xmldom.DOMParser({}).parseFromString(xml);

      if (!Object.prototype.hasOwnProperty.call(doc, "documentElement"))
        throw new Error("SAMLResponse is not valid base64-encoded XML");

      const inResponseToNodes = xmlCrypto.xpath(
        doc,
        "/*[local-name()='Response']/@InResponseTo"
      ) as Attr[];

      if (inResponseToNodes) {
        inResponseTo = inResponseToNodes.length ? inResponseToNodes[0].nodeValue : null;

        await this.validateInResponseTo(inResponseTo);
      }
      const certs = await this.certsToCheck();
      // Check if this document has a valid top-level signature
      let validSignature = false;
      if (this.options.cert && this.validateSignature(xml, doc.documentElement, certs!)) {
        validSignature = true;
      }

      const assertions = xmlCrypto.xpath(
        doc,
        "/*[local-name()='Response']/*[local-name()='Assertion']"
      ) as HTMLElement[];
      const encryptedAssertions = xmlCrypto.xpath(
        doc,
        "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']"
      );

      if (assertions.length + encryptedAssertions.length > 1) {
        // There's no reason I know of that we want to handle multiple assertions, and it seems like a
        //   potential risk vector for signature scope issues, so treat this as an invalid signature
        throw new Error("Invalid signature: multiple assertions");
      }

      if (assertions.length == 1) {
        if (
          this.options.cert &&
          !validSignature &&
          !this.validateSignature(xml, assertions[0], certs!)
        ) {
          throw new Error("Invalid signature");
        }
        return this.processValidlySignedAssertionAsync(
          assertions[0].toString(),
          xml,
          inResponseTo!
        );
      }

      if (encryptedAssertions.length == 1) {
        if (!this.options.decryptionPvk)
          throw new Error("No decryption key for encrypted SAML response");

        const encryptedAssertionXml = encryptedAssertions[0].toString();

        const xmlencOptions = { key: this.options.decryptionPvk };
        const decryptedXml: string = await util.promisify(xmlenc.decrypt).bind(xmlenc)(
          encryptedAssertionXml,
          xmlencOptions
        );
        const decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
        const decryptedAssertions = xmlCrypto.xpath(
          decryptedDoc,
          "/*[local-name()='Assertion']"
        ) as HTMLElement[];
        if (decryptedAssertions.length != 1) throw new Error("Invalid EncryptedAssertion content");

        if (
          this.options.cert &&
          !validSignature &&
          !this.validateSignature(decryptedXml, decryptedAssertions[0], certs!)
        )
          throw new Error("Invalid signature from encrypted assertion");

        return await this.processValidlySignedAssertionAsync(
          decryptedAssertions[0].toString(),
          xml,
          inResponseTo!
        );
      }

      // If there's no assertion, fall back on xml2js response parsing for the status &
      //   LogoutResponse code.

      const parserConfig = {
        explicitRoot: true,
        explicitCharkey: true,
        tagNameProcessors: [xml2js.processors.stripPrefix],
      };
      const parser = new xml2js.Parser(parserConfig);
      const xmljsDoc = await parser.parseStringPromise(xml);
      const response = xmljsDoc.Response;
      if (response) {
        const assertion = response.Assertion;
        if (!assertion) {
          const status = response.Status;
          if (status) {
            const statusCode = status[0].StatusCode;
            if (
              statusCode &&
              statusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder"
            ) {
              const nestedStatusCode = statusCode[0].StatusCode;
              if (
                nestedStatusCode &&
                nestedStatusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
              ) {
                if (this.options.cert && !validSignature) {
                  throw new Error("Invalid signature: NoPassive");
                }
                return { profile: null, loggedOut: false };
              }
            }

            // Note that we're not requiring a valid signature before this logic -- since we are
            //   throwing an error in any case, and some providers don't sign error results,
            //   let's go ahead and give the potentially more helpful error.
            if (statusCode && statusCode[0].$.Value) {
              const msgType = statusCode[0].$.Value.match(/[^:]*$/)[0];
              if (msgType != "Success") {
                let msg = "unspecified";
                if (status[0].StatusMessage) {
                  msg = status[0].StatusMessage[0]._;
                } else if (statusCode[0].StatusCode) {
                  msg = statusCode[0].StatusCode[0].$.Value.match(/[^:]*$/)[0];
                }
                const error = new Error("SAML provider returned " + msgType + " error: " + msg);
                const builderOpts = {
                  rootName: "Status",
                  headless: true,
                };
                // @ts-expect-error adding extra attr to default Error object
                error.statusXml = new xml2js.Builder(builderOpts).buildObject(status[0]);
                throw error;
              }
            }
          }
        }
        throw new Error("Missing SAML assertion");
      } else {
        if (this.options.cert && !validSignature) {
          throw new Error("Invalid signature: No response found");
        }
        const logoutResponse = xmljsDoc.LogoutResponse;
        if (logoutResponse) {
          return { profile: null, loggedOut: true };
        } else {
          throw new Error("Unknown SAML response message");
        }
      }
    } catch (err) {
      debug("validatePostResponse resulted in an error: %s", err);
      if (this.options.validateInResponseTo) {
        await this.cacheProvider.removeAsync(inResponseTo!);
      }
      throw err;
    }
  }

  async validateInResponseTo(inResponseTo: string | null) {
    if (this.options.validateInResponseTo) {
      if (inResponseTo) {
        const result = await this.cacheProvider.getAsync(inResponseTo);
        if (!result) throw new Error("InResponseTo is not valid");
        return;
      } else {
        throw new Error("InResponseTo is missing from response");
      }
    } else {
      return;
    }
  }

  async validateRedirectAsync(
    container: ParsedQs,
    originalQuery: string | null
  ): Promise<{ profile?: Profile | null; loggedOut?: boolean }> {
    const samlMessageType = container.SAMLRequest ? "SAMLRequest" : "SAMLResponse";

    const data = Buffer.from(container[samlMessageType] as string, "base64");
    const inflated = await inflateRawAsync(data);

    const dom = new xmldom.DOMParser().parseFromString(inflated.toString());
    const parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix],
    };
    const parser = new xml2js.Parser(parserConfig);
    const doc: XMLOutput = await parser.parseStringPromise(inflated);
    samlMessageType === "SAMLResponse"
      ? await this.verifyLogoutResponse(doc)
      : this.verifyLogoutRequest(doc);
    await this.hasValidSignatureForRedirect(container, originalQuery);
    return await processValidlySignedSamlLogoutAsync(this, doc, dom);
  }

  async hasValidSignatureForRedirect(
    container: ParsedQs,
    originalQuery: string | null
  ): Promise<boolean | void> {
    const tokens = originalQuery!.split("&");
    const getParam = (key: string) => {
      const exists = tokens.filter((t) => {
        return new RegExp(key).test(t);
      });
      return exists[0];
    };

    if (container.Signature && this.options.cert) {
      let urlString = getParam("SAMLRequest") || getParam("SAMLResponse");

      if (getParam("RelayState")) {
        urlString += "&" + getParam("RelayState");
      }

      urlString += "&" + getParam("SigAlg");

      const certs = await this.certsToCheck();
      const hasValidQuerySignature = certs!.some((cert) => {
        return this.validateSignatureForRedirect(
          urlString,
          container.Signature as string,
          container.SigAlg as string,
          cert
        );
      });
      if (!hasValidQuerySignature) {
        throw new Error("Invalid signature");
      }
    } else {
      return true;
    }
  }

  validateSignatureForRedirect(
    urlString: crypto.BinaryLike,
    signature: string,
    alg: string,
    cert: string
  ) {
    // See if we support a matching algorithm, case-insensitive. Otherwise, throw error.
    function hasMatch(ourAlgo: string) {
      // The incoming algorithm is forwarded as a URL.
      // We trim everything before the last # get something we can compare to the Node.js list
      const algFromURI = alg.toLowerCase().replace(/.*#(.*)$/, "$1");
      return ourAlgo.toLowerCase() === algFromURI;
    }
    const i = crypto.getHashes().findIndex(hasMatch);
    let matchingAlgo;
    if (i > -1) {
      matchingAlgo = crypto.getHashes()[i];
    } else {
      throw new Error(alg + " is not supported");
    }

    const verifier = crypto.createVerify(matchingAlgo);
    verifier.update(urlString);

    return verifier.verify(this.certToPEM(cert), signature, "base64");
  }

  verifyLogoutRequest(doc: XMLOutput) {
    this.verifyIssuer(doc.LogoutRequest);
    const nowMs = new Date().getTime();
    const conditions = doc.LogoutRequest.$;
    const conErr = this.checkTimestampsValidityError(
      nowMs,
      conditions.NotBefore,
      conditions.NotOnOrAfter
    );
    if (conErr) {
      throw conErr;
    }
  }

  async verifyLogoutResponse(doc: XMLOutput) {
    const statusCode = doc.LogoutResponse.Status[0].StatusCode[0].$.Value;
    if (statusCode !== "urn:oasis:names:tc:SAML:2.0:status:Success")
      throw new Error("Bad status code: " + statusCode);

    this.verifyIssuer(doc.LogoutResponse);
    const inResponseTo = doc.LogoutResponse.$.InResponseTo;
    if (inResponseTo) {
      return this.validateInResponseTo(inResponseTo);
    }

    return true;
  }

  verifyIssuer(samlMessage: XMLOutput) {
    if (this.options.idpIssuer) {
      const issuer = samlMessage.Issuer;
      if (issuer) {
        if (issuer[0]._ !== this.options.idpIssuer)
          throw new Error(
            "Unknown SAML issuer. Expected: " + this.options.idpIssuer + " Received: " + issuer[0]._
          );
      } else {
        throw new Error("Missing SAML issuer");
      }
    }
  }

  async processValidlySignedAssertionAsync(
    xml: xml2js.convertableToString,
    samlResponseXml: string,
    inResponseTo: string
  ) {
    let msg;
    const parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix],
    };
    const nowMs = new Date().getTime();
    const profile = {} as Profile;
    const parser = new xml2js.Parser(parserConfig);
    const doc: XMLOutput = await parser.parseStringPromise(xml);
    const parsedAssertion: XMLOutput = doc;
    const assertion: XMLOutput = doc.Assertion;
    getInResponseTo: {
      const issuer = assertion.Issuer;
      if (issuer && issuer[0]._) {
        profile.issuer = issuer[0]._;
      }

      if (inResponseTo) {
        profile.inResponseTo = inResponseTo;
      }

      const authnStatement = assertion.AuthnStatement;
      if (authnStatement) {
        if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
          profile.sessionIndex = authnStatement[0].$.SessionIndex;
        }
      }

      const subject = assertion.Subject;
      let subjectConfirmation, confirmData;
      if (subject) {
        const nameID = subject[0].NameID;
        if (nameID && nameID[0]._) {
          profile.nameID = nameID[0]._;

          if (nameID[0].$ && nameID[0].$.Format) {
            profile.nameIDFormat = nameID[0].$.Format;
            profile.nameQualifier = nameID[0].$.NameQualifier;
            profile.spNameQualifier = nameID[0].$.SPNameQualifier;
          }
        }

        subjectConfirmation = subject[0].SubjectConfirmation
          ? subject[0].SubjectConfirmation[0]
          : null;
        confirmData =
          subjectConfirmation && subjectConfirmation.SubjectConfirmationData
            ? subjectConfirmation.SubjectConfirmationData[0]
            : null;
        if (subject[0].SubjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
          msg = "Unable to process multiple SubjectConfirmations in SAML assertion";
          throw new Error(msg);
        }

        if (subjectConfirmation) {
          if (confirmData && confirmData.$) {
            const subjectNotBefore = confirmData.$.NotBefore;
            const subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;

            const subjErr = this.checkTimestampsValidityError(
              nowMs,
              subjectNotBefore,
              subjectNotOnOrAfter
            );
            if (subjErr) {
              throw subjErr;
            }
          }
        }
      }

      // Test to see that if we have a SubjectConfirmation InResponseTo that it matches
      // the 'InResponseTo' attribute set in the Response
      if (this.options.validateInResponseTo) {
        if (subjectConfirmation) {
          if (confirmData && confirmData.$) {
            const subjectInResponseTo = confirmData.$.InResponseTo;
            if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
              await this.cacheProvider.removeAsync(inResponseTo);
              throw new Error("InResponseTo is not valid");
            } else if (subjectInResponseTo) {
              let foundValidInResponseTo = false;
              const result = await this.cacheProvider.getAsync(subjectInResponseTo);
              if (result) {
                const createdAt = new Date(result);
                if (nowMs < createdAt.getTime() + this.options.requestIdExpirationPeriodMs)
                  foundValidInResponseTo = true;
              }
              await this.cacheProvider.removeAsync(inResponseTo);
              if (!foundValidInResponseTo) {
                throw new Error("InResponseTo is not valid");
              }
              break getInResponseTo;
            }
          }
        } else {
          await this.cacheProvider.removeAsync(inResponseTo);
          break getInResponseTo;
        }
      } else {
        break getInResponseTo;
      }
    }
    const conditions = assertion.Conditions ? assertion.Conditions[0] : null;
    if (assertion.Conditions && assertion.Conditions.length > 1) {
      msg = "Unable to process multiple conditions in SAML assertion";
      throw new Error(msg);
    }
    if (conditions && conditions.$) {
      const conErr = this.checkTimestampsValidityError(
        nowMs,
        conditions.$.NotBefore,
        conditions.$.NotOnOrAfter
      );
      if (conErr) throw conErr;
    }

    if (this.options.audience) {
      const audienceErr = this.checkAudienceValidityError(
        this.options.audience,
        conditions.AudienceRestriction
      );
      if (audienceErr) throw audienceErr;
    }

    const attributeStatement = assertion.AttributeStatement;
    if (attributeStatement) {
      const attributes: XMLOutput[] = [].concat(
        ...attributeStatement
          .filter((attr: XMLObject) => Array.isArray(attr.Attribute))
          .map((attr: XMLObject) => attr.Attribute)
      );

      const attrValueMapper = (value: XMLObject) => {
        const hasChildren = Object.keys(value).some((cur) => {
          return cur !== "_" && cur !== "$";
        });
        return hasChildren ? value : value._;
      };

      if (attributes) {
        attributes.forEach((attribute) => {
          if (!Object.prototype.hasOwnProperty.call(attribute, "AttributeValue")) {
            // if attributes has no AttributeValue child, continue
            return;
          }
          const value = attribute.AttributeValue;
          if (value.length === 1) {
            profile[attribute.$.Name] = attrValueMapper(value[0]);
          } else {
            profile[attribute.$.Name] = value.map(attrValueMapper);
          }
        });
      }
    }

    if (!profile.mail && profile["urn:oid:0.9.2342.19200300.100.1.3"]) {
      // See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary
      // for definition of attribute OIDs
      profile.mail = profile["urn:oid:0.9.2342.19200300.100.1.3"];
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    profile.getAssertionXml = () => xml.toString();
    profile.getAssertion = () => parsedAssertion;
    profile.getSamlResponseXml = () => samlResponseXml;

    return { profile, loggedOut: false };
  }

  checkTimestampsValidityError(nowMs: number, notBefore: string, notOnOrAfter: string) {
    if (this.options.acceptedClockSkewMs == -1) return null;

    if (notBefore) {
      const notBeforeMs = Date.parse(notBefore);
      if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs)
        return new Error("SAML assertion not yet valid");
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = Date.parse(notOnOrAfter);
      if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs)
        return new Error("SAML assertion expired");
    }

    return null;
  }

  checkAudienceValidityError(
    expectedAudience: string,
    audienceRestrictions: AudienceRestrictionXML[]
  ) {
    if (!audienceRestrictions || audienceRestrictions.length < 1) {
      return new Error("SAML assertion has no AudienceRestriction");
    }
    const errors = audienceRestrictions
      .map((restriction) => {
        if (!restriction.Audience || !restriction.Audience[0] || !restriction.Audience[0]._) {
          return new Error("SAML assertion AudienceRestriction has no Audience value");
        }
        if (restriction.Audience[0]._ !== expectedAudience) {
          return new Error("SAML assertion audience mismatch");
        }
        return null;
      })
      .filter((result) => {
        return result !== null;
      });
    if (errors.length > 0) {
      return errors[0];
    }
    return null;
  }

  async validatePostRequestAsync(
    container: Record<string, string>
  ): Promise<{ profile?: Profile; loggedOut?: boolean }> {
    const xml = Buffer.from(container.SAMLRequest, "base64").toString("utf8");
    const dom = new xmldom.DOMParser().parseFromString(xml);
    const parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix],
    };
    const parser = new xml2js.Parser(parserConfig);
    const doc = await parser.parseStringPromise(xml);
    const certs = await this.certsToCheck();
    if (this.options.cert && !this.validateSignature(xml, dom.documentElement, certs!)) {
      throw new Error("Invalid signature on documentElement");
    }
    return await processValidlySignedPostRequestAsync(this, doc, dom);
  }

  async getNameIDAsync(self: SAML, doc: Node): Promise<NameID> {
    const nameIds = xmlCrypto.xpath(
      doc,
      "/*[local-name()='LogoutRequest']/*[local-name()='NameID']"
    ) as Node[];
    const encryptedIds = xmlCrypto.xpath(
      doc,
      "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']"
    ) as Node[];

    if (nameIds.length + encryptedIds.length > 1) {
      throw new Error("Invalid LogoutRequest");
    }
    if (nameIds.length === 1) {
      return promiseWithNameID(nameIds[0]);
    }
    if (encryptedIds.length === 1) {
      if (!self.options.decryptionPvk) {
        throw new Error("No decryption key for encrypted SAML response");
      }

      const encryptedDatas = xmlCrypto.xpath(encryptedIds[0], "./*[local-name()='EncryptedData']");

      if (encryptedDatas.length !== 1) {
        throw new Error("Invalid LogoutRequest");
      }
      const encryptedDataXml = encryptedDatas[0].toString();

      const xmlencOptions = { key: self.options.decryptionPvk };
      const decryptedXml: string = await util.promisify(xmlenc.decrypt).bind(xmlenc)(
        encryptedDataXml,
        xmlencOptions
      );
      const decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
      const decryptedIds = xmlCrypto.xpath(decryptedDoc, "/*[local-name()='NameID']") as Node[];
      if (decryptedIds.length !== 1) {
        throw new Error("Invalid EncryptedAssertion content");
      }
      return await promiseWithNameID(decryptedIds[0]);
    }
    throw new Error("Missing SAML NameID");
  }

  generateServiceProviderMetadata(decryptionCert: string | null, signingCert?: string | null) {
    const metadata: ServiceMetadataXML = {
      EntityDescriptor: {
        "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
        "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
        "@entityID": this.options.issuer,
        "@ID": this.options.issuer.replace(/\W/g, "_"),
        SPSSODescriptor: {
          "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
      },
    };

    if (this.options.decryptionPvk) {
      if (!decryptionCert) {
        throw new Error(
          "Missing decryptionCert while generating metadata for decrypting service provider"
        );
      }
    }
    if (this.options.privateKey) {
      if (!signingCert) {
        throw new Error(
          "Missing signingCert while generating metadata for signing service provider messages"
        );
      }
    }

    if (this.options.decryptionPvk || this.options.privateKey) {
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = [];
      if (this.options.privateKey) {
        signingCert = signingCert!.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "");
        signingCert = signingCert.replace(/-+END CERTIFICATE-+\r?\n?/, "");
        signingCert = signingCert.replace(/\r\n/g, "\n");

        metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
          "@use": "signing",
          "ds:KeyInfo": {
            "ds:X509Data": {
              "ds:X509Certificate": {
                "#text": signingCert,
              },
            },
          },
        });
      }

      if (this.options.decryptionPvk) {
        decryptionCert = decryptionCert!.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "");
        decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, "");
        decryptionCert = decryptionCert.replace(/\r\n/g, "\n");

        metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
          "@use": "encryption",
          "ds:KeyInfo": {
            "ds:X509Data": {
              "ds:X509Certificate": {
                "#text": decryptionCert,
              },
            },
          },
          EncryptionMethod: [
            // this should be the set that the xmlenc library supports
            { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc" },
            { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes128-cbc" },
            { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" },
          ],
        });
      }
    }

    if (this.options.logoutCallbackUrl) {
      metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
        "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Location": this.options.logoutCallbackUrl,
      };
    }

    if (this.options.identifierFormat) {
      metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = this.options.identifierFormat;
    }

    metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
      "@index": "1",
      "@isDefault": "true",
      "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "@Location": this.getCallbackUrl({}),
    };
    return xmlbuilder
      .create((metadata as unknown) as Record<string, any>)
      .end({ pretty: true, indent: "  ", newline: "\n" });
  }

  keyToPEM(key: crypto.KeyLike) {
    if (!key || typeof key !== "string") return key;

    const lines = key.split(/\r?\n/);
    if (lines.length !== 1) return key;

    const wrappedKey = [
      "-----BEGIN PRIVATE KEY-----",
      ...(key.match(/.{1,64}/g) ?? []),
      "-----END PRIVATE KEY-----",
      "",
    ].join("\n");
    return wrappedKey;
  }

  normalizeNewlines(xml: string): string {
    // we can use this utility before passing XML to `xml-crypto`
    // we are considered the XML processor and are responsible for newline normalization
    // https://github.com/node-saml/passport-saml/issues/431#issuecomment-718132752
    return xml.replace(/\r\n?/g, "\n");
  }
}

export { SAML };
