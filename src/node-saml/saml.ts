import Debug from "debug";
const debug = Debug("node-saml");
import * as zlib from "zlib";
import * as crypto from "crypto";
import { URL } from "url";
import * as querystring from "querystring";
import * as util from "util";
import { CacheProvider as InMemoryCacheProvider } from "./inmemory-cache-provider";
import * as algorithms from "./algorithms";
import { signAuthnRequestPost } from "./saml-post-signing";
import { ParsedQs } from "qs";
import {
  isValidSamlSigningOptions,
  AudienceRestrictionXML,
  AuthorizeRequestXML,
  CertCallback,
  LogoutRequestXML,
  SamlIDPListConfig,
  SamlIDPEntryConfig,
  SamlOptions,
  ServiceMetadataXML,
  XMLInput,
  XMLObject,
  XMLOutput,
} from "./types";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  Profile,
  SamlConfig,
  ErrorWithXmlStatus,
} from "../passport-saml/types";
import { assertRequired } from "./utility";
import {
  buildXml2JsObject,
  buildXmlBuilderObject,
  decryptXml,
  parseDomFromString,
  parseXml2JsFromString,
  validateXmlSignatureForCert,
  xpath,
} from "./xml";

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
    const nameID = await self._getNameIdAsync(self, dom);
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
  const format = xpath.selectAttributes(nameid, "@Format");
  return {
    value: nameid.textContent,
    format: format && format[0] && format[0].nodeValue,
  };
}

class SAML {
  // note that some methods in SAML are not yet marked as private as they are used in testing.
  // those methods start with an underscore, e.g. _generateUniqueID
  options: SamlOptions;
  // This is only for testing
  cacheProvider!: InMemoryCacheProvider;

  constructor(ctorOptions: SamlConfig) {
    this.options = this.initialize(ctorOptions);
    this.cacheProvider = this.options.cacheProvider;
  }

  initialize(ctorOptions: SamlConfig): SamlOptions {
    if (!ctorOptions) {
      throw new TypeError("SamlOptions required on construction");
    }

    const options = {
      ...ctorOptions,
      passive: ctorOptions.passive ?? false,
      disableRequestedAuthnContext: ctorOptions.disableRequestedAuthnContext ?? false,
      additionalParams: ctorOptions.additionalParams ?? {},
      additionalAuthorizeParams: ctorOptions.additionalAuthorizeParams ?? {},
      additionalLogoutParams: ctorOptions.additionalLogoutParams ?? {},
      forceAuthn: ctorOptions.forceAuthn ?? false,
      skipRequestCompression: ctorOptions.skipRequestCompression ?? false,
      disableRequestAcsUrl: ctorOptions.disableRequestAcsUrl ?? false,
      acceptedClockSkewMs: ctorOptions.acceptedClockSkewMs ?? 0,
      maxAssertionAgeMs: ctorOptions.maxAssertionAgeMs ?? 0,
      path: ctorOptions.path ?? "/saml/consume",
      host: ctorOptions.host ?? "localhost",
      issuer: ctorOptions.issuer ?? "onelogin_saml",
      identifierFormat:
        ctorOptions.identifierFormat === undefined
          ? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          : ctorOptions.identifierFormat,
      wantAssertionsSigned: ctorOptions.wantAssertionsSigned ?? false,
      authnContext: ctorOptions.authnContext ?? [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      validateInResponseTo: ctorOptions.validateInResponseTo ?? false,
      cert: assertRequired(ctorOptions.cert, "cert is required"),
      requestIdExpirationPeriodMs: ctorOptions.requestIdExpirationPeriodMs ?? 28800000, // 8 hours
      cacheProvider:
        ctorOptions.cacheProvider ??
        new InMemoryCacheProvider({
          keyExpirationPeriodMs: ctorOptions.requestIdExpirationPeriodMs,
        }),
      logoutUrl: ctorOptions.logoutUrl ?? ctorOptions.entryPoint ?? "", // Default to Entry Point
      signatureAlgorithm: ctorOptions.signatureAlgorithm ?? "sha1", // sha1, sha256, or sha512
      authnRequestBinding: ctorOptions.authnRequestBinding ?? "HTTP-Redirect",

      racComparison: ctorOptions.racComparison ?? "exact",
    };

    /**
     * List of possible values:
     * - exact : Assertion context must exactly match a context in the list
     * - minimum:  Assertion context must be at least as strong as a context in the list
     * - maximum:  Assertion context must be no stronger than a context in the list
     * - better:  Assertion context must be stronger than all contexts in the list
     */
    if (!["exact", "minimum", "maximum", "better"].includes(options.racComparison)) {
      throw new TypeError("racComparison must be one of ['exact', 'minimum', 'maximum', 'better']");
    }

    return options;
  }

  private getCallbackUrl(host?: string | undefined) {
    // Post-auth destination
    if (this.options.callbackUrl) {
      return this.options.callbackUrl;
    } else {
      const url = new URL("http://localhost");
      if (host) {
        url.host = host;
      } else {
        url.host = this.options.host;
      }
      if (this.options.protocol) {
        url.protocol = this.options.protocol;
      }
      url.pathname = this.options.path;
      return url.toString();
    }
  }

  _generateUniqueID() {
    return crypto.randomBytes(10).toString("hex");
  }

  private generateInstant() {
    return new Date().toISOString();
  }

  private signRequest(samlMessage: querystring.ParsedUrlQueryInput): void {
    this.options.privateKey = assertRequired(this.options.privateKey, "privateKey is required");

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
    samlMessage.Signature = signer.sign(this._keyToPEM(this.options.privateKey), "base64");
  }

  private async generateAuthorizeRequestAsync(
    isPassive: boolean,
    isHttpPostBinding: boolean,
    host: string | undefined
  ): Promise<string | undefined> {
    this.options.entryPoint = assertRequired(this.options.entryPoint, "entryPoint is required");

    const id = "_" + this._generateUniqueID();
    const instant = this.generateInstant();

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

    if (this.options.forceAuthn) {
      request["samlp:AuthnRequest"]["@ForceAuthn"] = true;
    }

    if (!this.options.disableRequestAcsUrl) {
      request["samlp:AuthnRequest"]["@AssertionConsumerServiceURL"] = this.getCallbackUrl(host);
    }

    if (this.options.identifierFormat != null) {
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
        "@Comparison": this.options.racComparison,
        "saml:AuthnContextClassRef": authnContextClassRefs,
      };
    }

    if (this.options.attributeConsumingServiceIndex != null) {
      request["samlp:AuthnRequest"]["@AttributeConsumingServiceIndex"] =
        this.options.attributeConsumingServiceIndex;
    }

    if (this.options.providerName != null) {
      request["samlp:AuthnRequest"]["@ProviderName"] = this.options.providerName;
    }

    if (this.options.scoping != null) {
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

    let stringRequest = buildXmlBuilderObject(request, false);
    // TODO: maybe we should always sign here
    if (isHttpPostBinding && isValidSamlSigningOptions(this.options)) {
      stringRequest = signAuthnRequestPost(stringRequest, this.options);
    }
    return stringRequest;
  }

  async _generateLogoutRequest(user: Profile) {
    const id = "_" + this._generateUniqueID();
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
          "@Format": user!.nameIDFormat,
          "#text": user!.nameID,
        },
      },
    } as LogoutRequestXML;

    if (user!.nameQualifier != null) {
      request["samlp:LogoutRequest"]["saml:NameID"]["@NameQualifier"] = user!.nameQualifier;
    }

    if (user!.spNameQualifier != null) {
      request["samlp:LogoutRequest"]["saml:NameID"]["@SPNameQualifier"] = user!.spNameQualifier;
    }

    if (user!.sessionIndex) {
      request["samlp:LogoutRequest"]["saml2p:SessionIndex"] = {
        "@xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        "#text": user!.sessionIndex,
      };
    }

    await this.cacheProvider.saveAsync(id, instant);
    return buildXmlBuilderObject(request, false);
  }

  _generateLogoutResponse(logoutRequest: Profile) {
    const id = "_" + this._generateUniqueID();
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

    return buildXmlBuilderObject(request, false);
  }

  async _requestToUrlAsync(
    request: string | null | undefined,
    response: string | null,
    operation: string,
    additionalParameters: querystring.ParsedUrlQuery
  ): Promise<string> {
    this.options.entryPoint = assertRequired(this.options.entryPoint, "entryPoint is required");

    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from((request || response)!, "utf8");
    } else {
      buffer = await deflateRawAsync((request || response)!);
    }

    const base64 = buffer.toString("base64");
    let target = new URL(this.options.entryPoint);

    if (operation === "logout") {
      if (this.options.logoutUrl) {
        target = new URL(this.options.logoutUrl);
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
    if (this.options.privateKey != null) {
      if (!this.options.entryPoint) {
        throw new Error('"entryPoint" config parameter is required for signed messages');
      }

      // sets .SigAlg and .Signature
      this.signRequest(samlMessage);
    }
    Object.keys(samlMessage).forEach((k) => {
      target.searchParams.set(k, samlMessage[k] as string);
    });

    return target.toString();
  }

  _getAdditionalParams(
    RelayState: string,
    operation: string,
    overrideParams?: querystring.ParsedUrlQuery
  ): querystring.ParsedUrlQuery {
    const additionalParams: querystring.ParsedUrlQuery = {};

    if (typeof RelayState === "string" && RelayState.length > 0) {
      additionalParams.RelayState = RelayState;
    }

    const optionsAdditionalParams = this.options.additionalParams;
    Object.keys(optionsAdditionalParams).forEach(function (k) {
      additionalParams[k] = optionsAdditionalParams[k];
    });

    let optionsAdditionalParamsForThisOperation: Record<string, string> = {};
    if (operation == "authorize") {
      optionsAdditionalParamsForThisOperation = this.options.additionalAuthorizeParams;
    }
    if (operation == "logout") {
      optionsAdditionalParamsForThisOperation = this.options.additionalLogoutParams;
    }

    Object.keys(optionsAdditionalParamsForThisOperation).forEach(function (k) {
      additionalParams[k] = optionsAdditionalParamsForThisOperation[k];
    });

    overrideParams = overrideParams ?? {};
    Object.keys(overrideParams).forEach(function (k) {
      additionalParams[k] = overrideParams![k];
    });

    return additionalParams;
  }

  async getAuthorizeUrlAsync(
    RelayState: string,
    host: string | undefined,
    options: AuthorizeOptions
  ): Promise<string> {
    const request = await this.generateAuthorizeRequestAsync(this.options.passive, false, host);
    const operation = "authorize";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      request,
      null,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams)
    );
  }

  async getAuthorizeFormAsync(RelayState: string, host?: string): Promise<string> {
    this.options.entryPoint = assertRequired(this.options.entryPoint, "entryPoint is required");

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

    const request = await this.generateAuthorizeRequestAsync(this.options.passive, true, host);
    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from(request!, "utf8");
    } else {
      buffer = await deflateRawAsync(request!);
    }

    const operation = "authorize";
    const additionalParameters = this._getAdditionalParams(RelayState, operation);
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

  async getLogoutUrlAsync(
    user: Profile,
    RelayState: string,
    options: AuthenticateOptions & AuthorizeOptions
  ) {
    const request = await this._generateLogoutRequest(user);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      request,
      null,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams)
    );
  }

  getLogoutResponseUrl(
    samlLogoutRequest: Profile,
    RelayState: string,
    options: AuthenticateOptions & AuthorizeOptions,
    callback: (err: Error | null, url?: string | null) => void
  ): void {
    util.callbackify(() => this.getLogoutResponseUrlAsync(samlLogoutRequest, RelayState, options))(
      callback
    );
  }
  private async getLogoutResponseUrlAsync(
    samlLogoutRequest: Profile,
    RelayState: string,
    options: AuthenticateOptions & AuthorizeOptions // add RelayState,
  ): Promise<string> {
    const response = this._generateLogoutResponse(samlLogoutRequest);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      null,
      response,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams)
    );
  }

  _certToPEM(cert: string): string {
    cert = cert.match(/.{1,64}/g)!.join("\n");

    if (cert.indexOf("-BEGIN CERTIFICATE-") === -1) cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    if (cert.indexOf("-END CERTIFICATE-") === -1) cert = cert + "\n-----END CERTIFICATE-----\n";

    return cert;
  }

  private async certsToCheck(): Promise<string[]> {
    let checkedCerts: string[];

    if (typeof this.options.cert === "function") {
      checkedCerts = await util
        .promisify(this.options.cert as CertCallback)()
        .then((certs) => {
          certs = assertRequired(certs, "callback didn't return cert");
          if (!Array.isArray(certs)) {
            certs = [certs];
          }
          return certs;
        });
    } else if (Array.isArray(this.options.cert)) {
      checkedCerts = this.options.cert;
    } else {
      checkedCerts = [this.options.cert];
    }

    checkedCerts.forEach((cert) => {
      assertRequired(cert, "unknown cert found");
    });

    return checkedCerts;
  }

  // This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
  //   signature of the |currentNode|.
  //
  // See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
  //   vectors against SAML signature verification.
  validateSignature(fullXml: string, currentNode: Element, certs: string[]): boolean {
    const xpathSigQuery =
      ".//*[" +
      "local-name(.)='Signature' and " +
      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
      "descendant::*[local-name(.)='Reference' and @URI='#" +
      currentNode.getAttribute("ID") +
      "']" +
      "]";
    const signatures = xpath.selectElements(currentNode, xpathSigQuery);
    // This function is expecting to validate exactly one signature, so if we find more or fewer
    //   than that, reject.
    if (signatures.length !== 1) {
      return false;
    }
    const xpathTransformQuery =
      ".//*[" +
      "local-name(.)='Transform' and " +
      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
      "ancestor::*[local-name(.)='Reference' and @URI='#" +
      currentNode.getAttribute("ID") +
      "']" +
      "]";
    const transforms = xpath.selectElements(currentNode, xpathTransformQuery);
    // Reject also XMLDSIG with more than 2 Transform
    if (transforms.length > 2) {
      // do not return false, throw an error so that it can be caught by tests differently
      throw new Error("Invalid signature, too many transforms");
    }

    const signature = signatures[0];
    return certs.some((certToCheck) => {
      return validateXmlSignatureForCert(
        signature,
        this._certToPEM(certToCheck),
        fullXml,
        currentNode
      );
    });
  }

  async validatePostResponseAsync(
    container: Record<string, string>
  ): Promise<{ profile?: Profile | null; loggedOut?: boolean }> {
    let xml: string, doc: Document, inResponseTo: string | null;
    try {
      xml = Buffer.from(container.SAMLResponse, "base64").toString("utf8");
      doc = parseDomFromString(xml);

      if (!Object.prototype.hasOwnProperty.call(doc, "documentElement"))
        throw new Error("SAMLResponse is not valid base64-encoded XML");

      const inResponseToNodes = xpath.selectAttributes(
        doc,
        "/*[local-name()='Response']/@InResponseTo"
      );

      if (inResponseToNodes) {
        inResponseTo = inResponseToNodes.length ? inResponseToNodes[0].nodeValue : null;

        await this.validateInResponseTo(inResponseTo);
      }
      const certs = await this.certsToCheck();
      // Check if this document has a valid top-level signature
      let validSignature = false;
      if (this.validateSignature(xml, doc.documentElement, certs)) {
        validSignature = true;
      }

      const assertions = xpath.selectElements(
        doc,
        "/*[local-name()='Response']/*[local-name()='Assertion']"
      );
      const encryptedAssertions = xpath.selectElements(
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
          (this.options.wantAssertionsSigned || !validSignature) &&
          !this.validateSignature(xml, assertions[0], certs)
        ) {
          throw new Error("Invalid signature");
        }
        return await this.processValidlySignedAssertionAsync(
          assertions[0].toString(),
          xml,
          inResponseTo!
        );
      }

      if (encryptedAssertions.length == 1) {
        this.options.decryptionPvk = assertRequired(
          this.options.decryptionPvk,
          "No decryption key for encrypted SAML response"
        );

        const encryptedAssertionXml = encryptedAssertions[0].toString();

        const decryptedXml = await decryptXml(encryptedAssertionXml, this.options.decryptionPvk);
        const decryptedDoc = parseDomFromString(decryptedXml);
        const decryptedAssertions = xpath.selectElements(
          decryptedDoc,
          "/*[local-name()='Assertion']"
        );
        if (decryptedAssertions.length != 1) throw new Error("Invalid EncryptedAssertion content");

        if (
          (this.options.wantAssertionsSigned || !validSignature) &&
          !this.validateSignature(decryptedXml, decryptedAssertions[0], certs)
        ) {
          throw new Error("Invalid signature from encrypted assertion");
        }

        return await this.processValidlySignedAssertionAsync(
          decryptedAssertions[0].toString(),
          xml,
          inResponseTo!
        );
      }

      // If there's no assertion, fall back on xml2js response parsing for the status &
      //   LogoutResponse code.

      const xmljsDoc = await parseXml2JsFromString(xml);
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
                if (!validSignature) {
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
                const statusXml = buildXml2JsObject("Status", status[0]);
                throw new ErrorWithXmlStatus(
                  "SAML provider returned " + msgType + " error: " + msg,
                  statusXml
                );
              }
            }
          }
        }
        throw new Error("Missing SAML assertion");
      } else {
        if (!validSignature) {
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

  private async validateInResponseTo(inResponseTo: string | null): Promise<undefined> {
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

    const dom = parseDomFromString(inflated.toString());
    const doc: XMLOutput = await parseXml2JsFromString(inflated);
    samlMessageType === "SAMLResponse"
      ? await this.verifyLogoutResponse(doc)
      : this.verifyLogoutRequest(doc);
    await this.hasValidSignatureForRedirect(container, originalQuery);
    return await processValidlySignedSamlLogoutAsync(this, doc, dom);
  }

  private async hasValidSignatureForRedirect(
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

    if (container.Signature) {
      let urlString = getParam("SAMLRequest") || getParam("SAMLResponse");

      if (getParam("RelayState")) {
        urlString += "&" + getParam("RelayState");
      }

      urlString += "&" + getParam("SigAlg");

      const certs = await this.certsToCheck();
      const hasValidQuerySignature = certs.some((cert) => {
        return this.validateSignatureForRedirect(
          urlString,
          container.Signature as string,
          container.SigAlg as string,
          cert
        );
      });
      if (!hasValidQuerySignature) {
        throw new Error("Invalid query signature");
      }
    } else {
      return true;
    }
  }

  private validateSignatureForRedirect(
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

    return verifier.verify(this._certToPEM(cert), signature, "base64");
  }

  private verifyLogoutRequest(doc: XMLOutput) {
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

  private async verifyLogoutResponse(doc: XMLOutput) {
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

  private verifyIssuer(samlMessage: XMLOutput) {
    if (this.options.idpIssuer != null) {
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

  private async processValidlySignedAssertionAsync(
    xml: string,
    samlResponseXml: string,
    inResponseTo: string
  ) {
    let msg;
    const nowMs = new Date().getTime();
    const profile = {} as Profile;
    const doc: XMLOutput = await parseXml2JsFromString(xml);
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
            const maxTimeLimitMs = this.processMaxAgeAssertionTime(
              this.options.maxAssertionAgeMs,
              subjectNotOnOrAfter,
              assertion.$.IssueInstant
            );

            const subjErr = this.checkTimestampsValidityError(
              nowMs,
              subjectNotBefore,
              subjectNotOnOrAfter,
              maxTimeLimitMs
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
      const maxTimeLimitMs = this.processMaxAgeAssertionTime(
        this.options.maxAssertionAgeMs,
        conditions.$.NotOnOrAfter,
        assertion.$.IssueInstant
      );
      const conErr = this.checkTimestampsValidityError(
        nowMs,
        conditions.$.NotBefore,
        conditions.$.NotOnOrAfter,
        maxTimeLimitMs
      );
      if (conErr) throw conErr;
    }

    if (this.options.audience != null) {
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
        const profileAttributes: Record<string, unknown> = {};

        attributes.forEach((attribute) => {
          if (!Object.prototype.hasOwnProperty.call(attribute, "AttributeValue")) {
            // if attributes has no AttributeValue child, continue
            return;
          }

          const name = attribute.$.Name;
          const value =
            attribute.AttributeValue.length === 1
              ? attrValueMapper(attribute.AttributeValue[0])
              : attribute.AttributeValue.map(attrValueMapper);

          profileAttributes[name] = value;

          // If any property is already present in profile and is also present
          // in attributes, then skip the one from attributes. Handle this
          // conflict gracefully without returning any error
          if (Object.prototype.hasOwnProperty.call(profile, name)) {
            return;
          }

          profile[name] = value;
        });

        profile.attributes = profileAttributes;
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

  private checkTimestampsValidityError(
    nowMs: number,
    notBefore: string,
    notOnOrAfter: string,
    maxTimeLimitMs?: number
  ) {
    if (this.options.acceptedClockSkewMs == -1) return null;

    if (notBefore) {
      const notBeforeMs = this.dateStringToTimestamp(notBefore, "NotBefore");
      if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs)
        return new Error("SAML assertion not yet valid");
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = this.dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
      if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs)
        return new Error("SAML assertion expired: clocks skewed too much");
    }
    if (maxTimeLimitMs) {
      if (nowMs - this.options.acceptedClockSkewMs >= maxTimeLimitMs)
        return new Error("SAML assertion expired: assertion too old");
    }

    return null;
  }

  private checkAudienceValidityError(
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
    const dom = parseDomFromString(xml);
    const doc = await parseXml2JsFromString(xml);
    const certs = await this.certsToCheck();
    if (!this.validateSignature(xml, dom.documentElement, certs)) {
      throw new Error("Invalid signature on documentElement");
    }
    return await processValidlySignedPostRequestAsync(this, doc, dom);
  }

  async _getNameIdAsync(self: SAML, doc: Node): Promise<NameID> {
    const nameIds = xpath.selectElements(
      doc,
      "/*[local-name()='LogoutRequest']/*[local-name()='NameID']"
    );
    const encryptedIds = xpath.selectElements(
      doc,
      "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']"
    );

    if (nameIds.length + encryptedIds.length > 1) {
      throw new Error("Invalid LogoutRequest");
    }
    if (nameIds.length === 1) {
      return promiseWithNameID(nameIds[0]);
    }
    if (encryptedIds.length === 1) {
      self.options.decryptionPvk = assertRequired(
        self.options.decryptionPvk,
        "No decryption key found getting name ID for encrypted SAML response"
      );

      const encryptedDatas = xpath.selectElements(
        encryptedIds[0],
        "./*[local-name()='EncryptedData']"
      );

      if (encryptedDatas.length !== 1) {
        throw new Error("Invalid LogoutRequest");
      }
      const encryptedDataXml = encryptedDatas[0].toString();

      const decryptedXml = await decryptXml(encryptedDataXml, self.options.decryptionPvk);
      const decryptedDoc = parseDomFromString(decryptedXml);
      const decryptedIds = xpath.selectElements(decryptedDoc, "/*[local-name()='NameID']");
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

    if (this.options.decryptionPvk != null) {
      if (!decryptionCert) {
        throw new Error(
          "Missing decryptionCert while generating metadata for decrypting service provider"
        );
      }
    }
    if (this.options.privateKey != null) {
      if (!signingCert) {
        throw new Error(
          "Missing signingCert while generating metadata for signing service provider messages"
        );
      }
    }

    if (this.options.decryptionPvk != null || this.options.privateKey != null) {
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = [];
      if (this.options.privateKey != null) {
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

      if (this.options.decryptionPvk != null) {
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
            { "@Algorithm": "http://www.w3.org/2009/xmlenc11#aes256-gcm" },
            { "@Algorithm": "http://www.w3.org/2009/xmlenc11#aes128-gcm" },
            { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc" },
            { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes128-cbc" },
          ],
        });
      }
    }

    if (this.options.logoutCallbackUrl != null) {
      metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
        "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Location": this.options.logoutCallbackUrl,
      };
    }

    if (this.options.identifierFormat != null) {
      metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = this.options.identifierFormat;
    }

    if (this.options.wantAssertionsSigned) {
      metadata.EntityDescriptor.SPSSODescriptor["@WantAssertionsSigned"] = true;
    }

    metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
      "@index": "1",
      "@isDefault": "true",
      "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "@Location": this.getCallbackUrl(),
    };
    return buildXmlBuilderObject(metadata, true);
  }

  _keyToPEM(key: string | Buffer): typeof key extends string | Buffer ? string | Buffer : Error {
    key = assertRequired(key, "key is required");

    if (typeof key !== "string") return key;
    if (key.split(/\r?\n/).length !== 1) return key;

    const matchedKey = key.match(/.{1,64}/g);

    if (matchedKey) {
      const wrappedKey = [
        "-----BEGIN PRIVATE KEY-----",
        ...matchedKey,
        "-----END PRIVATE KEY-----",
        "",
      ].join("\n");
      return wrappedKey;
    }

    throw new Error("Invalid key");
  }

  /**
   * Process max age assertion and use it if it is more restrictive than the NotOnOrAfter age
   * assertion received in the SAMLResponse.
   *
   * @param maxAssertionAgeMs Max time after IssueInstant that we will accept assertion, in Ms.
   * @param notOnOrAfter Expiration provided in response.
   * @param issueInstant Time when response was issued.
   * @returns {*} The expiration time to be used, in Ms.
   */
  private processMaxAgeAssertionTime(
    maxAssertionAgeMs: number,
    notOnOrAfter: string,
    issueInstant: string
  ): number {
    const notOnOrAfterMs = this.dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
    const issueInstantMs = this.dateStringToTimestamp(issueInstant, "IssueInstant");

    if (maxAssertionAgeMs === 0) {
      return notOnOrAfterMs;
    }

    const maxAssertionTimeMs = issueInstantMs + maxAssertionAgeMs;
    return maxAssertionTimeMs < notOnOrAfterMs ? maxAssertionTimeMs : notOnOrAfterMs;
  }

  /**
   * Convert a date string to a timestamp (in milliseconds).
   *
   * @param dateString A string representation of a date
   * @param label Descriptive name of the date being passed in, e.g. "NotOnOrAfter"
   * @throws Will throw an error if parsing `dateString` returns `NaN`
   * @returns {number} The timestamp (in milliseconds) representation of the given date
   */
  private dateStringToTimestamp(dateString: string, label: string): number {
    const dateMs = Date.parse(dateString);

    if (isNaN(dateMs)) {
      throw new Error(`Error parsing ${label}: '${dateString}' is not a valid date`);
    }

    return dateMs;
  }
}

export { SAML };
