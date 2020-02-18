var debug = require('debug')('passport-saml');
var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var url = require('url');
var querystring = require('querystring');
var xmlbuilder = require('xmlbuilder');
var xmlenc = require('xml-encryption');
var xpath = xmlCrypto.xpath;
var InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider;
var algorithms = require('./algorithms');
var signAuthnRequestPost = require('./saml-post-signing').signAuthnRequestPost;
var Q = require('q');

var SAML = function (options) {
  this.options = this.initialize(options);
  this.cacheProvider = this.options.cacheProvider;
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (Object.prototype.hasOwnProperty.call(options, 'cert') && !options.cert) {
    throw new Error('Invalid property: cert must not be empty');
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }

  if (!options.host) {
    options.host = 'localhost';
  }

  if (!options.issuer) {
    options.issuer = 'onelogin_saml';
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

  if(!options.validateInResponseTo){
    options.validateInResponseTo = false;
  }

  if(!options.requestIdExpirationPeriodMs){
    options.requestIdExpirationPeriodMs = 28800000;  // 8 hours
  }

  if(!options.cacheProvider){
      options.cacheProvider = new InMemoryCacheProvider(
          {keyExpirationPeriodMs: options.requestIdExpirationPeriodMs });
  }

  if (!options.logoutUrl) {
    // Default to Entry Point
    options.logoutUrl = options.entryPoint || '';
  }

  // sha1, sha256, or sha512
  if (!options.signatureAlgorithm) {
    options.signatureAlgorithm = 'sha1';
  }

  /**
   * List of possible values:
   * - exact : Assertion context must exactly match a context in the list
   * - minimum:  Assertion context must be at least as strong as a context in the list
   * - maximum:  Assertion context must be no stronger than a context in the list
   * - better:  Assertion context must be stronger than all contexts in the list
   */
  if (!options.RACComparison || ['exact','minimum','maximum','better'].indexOf(options.RACComparison) === -1){
    options.RACComparison = 'exact';
  }

  return options;
};

SAML.prototype.getProtocol = function (req) {
  return this.options.protocol || (req.protocol || 'http').concat('://');
};

SAML.prototype.getCallbackUrl = function (req) {
    // Post-auth destination
  if (this.options.callbackUrl) {
    return this.options.callbackUrl;
  } else {
    var host;
    if (req.headers) {
      host = req.headers.host;
    } else {
      host = this.options.host;
    }
    return this.getProtocol(req) + host + this.options.path;
  }
};

SAML.prototype.generateUniqueID = function () {
  return crypto.randomBytes(10).toString('hex');
};

SAML.prototype.generateInstant = function () {
  return new Date().toISOString();
};

SAML.prototype.signRequest = function (samlMessage) {
  var signer;
  var samlMessageToSign = {};
  samlMessage.SigAlg = algorithms.getSigningAlgorithm(this.options.signatureAlgorithm);
  signer = algorithms.getSigner(this.options.signatureAlgorithm);
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
  samlMessage.Signature = signer.sign(this.keyToPEM(this.options.privateCert), 'base64');
};

SAML.prototype.generateAuthorizeRequest = function (req, isPassive, isHttpPostBinding, callback) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();
  var forceAuthn = this.options.forceAuthn || false;

  Q.fcall(() => {
    if(this.options.validateInResponseTo) {
      return Q.ninvoke(this.cacheProvider, 'save', id, instant);
    } else {
      return Q();
    }
  })
  .then(() => {
    var request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@Destination': this.options.entryPoint,
        'saml:Issuer' : {
          '@xmlns:saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': this.options.issuer
        }
      }
    };

    if (isPassive)
      request['samlp:AuthnRequest']['@IsPassive'] = true;

    if (forceAuthn) {
      request['samlp:AuthnRequest']['@ForceAuthn'] = true;
    }

    if (!this.options.disableRequestACSUrl) {
      request['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = this.getCallbackUrl(req);
    }

    if (this.options.identifierFormat) {
      request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Format': this.options.identifierFormat,
        '@AllowCreate': 'true'
      };
    }

    if (!this.options.disableRequestedAuthnContext) {
      var authnContextClassRefs = [];
      this.options.authnContext.forEach(function(value) {
        authnContextClassRefs.push({
            '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': value
        });
      });

      request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Comparison': this.options.RACComparison,
        'saml:AuthnContextClassRef': authnContextClassRefs
      };
    }

    if (this.options.attributeConsumingServiceIndex != null) {
      request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] = this.options.attributeConsumingServiceIndex;
    }

    if (this.options.providerName) {
      request['samlp:AuthnRequest']['@ProviderName'] = this.options.providerName;
    }

    var stringRequest = xmlbuilder.create(request).end();
    if (isHttpPostBinding && this.options.privateCert) {
      stringRequest = signAuthnRequestPost(stringRequest, this.options);
    }
    callback(null, stringRequest);
  })
  .fail(function(err){
    callback(err);
  })
  .done();
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  var request = {
    'samlp:LogoutRequest' : {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': instant,
      '@Destination': this.options.logoutUrl,
      'saml:Issuer' : {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': this.options.issuer
      },
      'saml:NameID' : {
        '@Format': req.user.nameIDFormat,
        '#text': req.user.nameID
      }
    }
  };

  if (req.user.nameQualifier != null) {
    request['samlp:LogoutRequest']['saml:NameID']['@NameQualifier'] = req.user.nameQualifier;
  }

  if (req.user.spNameQualifier != null) {
    request['samlp:LogoutRequest']['saml:NameID']['@SPNameQualifier'] = req.user.spNameQualifier;
  }

  if (req.user.sessionIndex) {
    request['samlp:LogoutRequest']['saml2p:SessionIndex'] = {
      '@xmlns:saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '#text': req.user.sessionIndex
    };
  }

  return Q.ninvoke(this.cacheProvider, 'save', id, instant)
    .then(function() {
      return xmlbuilder.create(request).end();
    });
};

SAML.prototype.generateLogoutResponse = function (req, logoutRequest) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  var request = {
    'samlp:LogoutResponse' : {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': instant,
      '@Destination': this.options.logoutUrl,
      '@InResponseTo': logoutRequest.ID,
      'saml:Issuer' : {
        '#text': this.options.issuer
      },
      'samlp:Status': {
        'samlp:StatusCode': {
          '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
        }
      }
    }
  };

  return xmlbuilder.create(request).end();
};

SAML.prototype.requestToUrl = function (request, response, operation, additionalParameters, callback) {

  const requestToUrlHelper = (err, buffer) => {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = url.parse(this.options.entryPoint, true);

    if (operation === 'logout') {
      if (this.options.logoutUrl) {
        target = url.parse(this.options.logoutUrl, true);
      }
    } else if (operation !== 'authorize') {
        return callback(new Error("Unknown operation: "+operation));
    }

    var samlMessage = request ? {
      SAMLRequest: base64
    } : {
      SAMLResponse: base64
    };
    Object.keys(additionalParameters).forEach(k => {
      samlMessage[k] = additionalParameters[k];
    });

    if (this.options.privateCert) {
      try {
        if (!this.options.entryPoint) {
          throw new Error('"entryPoint" config parameter is required for signed messages');
        }

        // sets .SigAlg and .Signature
        this.signRequest(samlMessage);

      } catch (ex) {
        return callback(ex);
      }
    }
    Object.keys(samlMessage).forEach(k => {
      target.query[k] = samlMessage[k];
    });

    // Delete 'search' to for pulling query string from 'query'
    // https://nodejs.org/api/url.html#url_url_format_urlobj
    delete target.search;

    callback(null, url.format(target));
  };

  if (this.options.skipRequestCompression) {
    requestToUrlHelper(null, Buffer.from(request || response, 'utf8'));
  }
  else {
    zlib.deflateRaw(request || response, requestToUrlHelper);
  }
};

SAML.prototype.getAdditionalParams = function (req, operation, overrideParams) {
  var additionalParams = {};

  var RelayState = req.query && req.query.RelayState || req.body && req.body.RelayState;
  if (RelayState) {
    additionalParams.RelayState = RelayState;
  }

  var optionsAdditionalParams = this.options.additionalParams || {};
  Object.keys(optionsAdditionalParams).forEach(function(k) {
    additionalParams[k] = optionsAdditionalParams[k];
  });

  var optionsAdditionalParamsForThisOperation = {};
  if (operation == "authorize") {
    optionsAdditionalParamsForThisOperation = this.options.additionalAuthorizeParams || {};
  }
  if (operation == "logout") {
    optionsAdditionalParamsForThisOperation = this.options.additionalLogoutParams || {};
  }

  Object.keys(optionsAdditionalParamsForThisOperation).forEach(function(k) {
    additionalParams[k] = optionsAdditionalParamsForThisOperation[k];
  });

  overrideParams = overrideParams || {};
  Object.keys(overrideParams).forEach(function(k) {
    additionalParams[k] = overrideParams[k];
  });

  return additionalParams;
};

SAML.prototype.getAuthorizeUrl = function (req, options, callback) {
  this.generateAuthorizeRequest(req, this.options.passive, false, (err, request) => {
    if (err)
      return callback(err);
    var operation = 'authorize';
    var overrideParams = options ? options.additionalParams || {} : {};
    this.requestToUrl(request, null, operation, this.getAdditionalParams(req, operation, overrideParams), callback);
  });
};

SAML.prototype.getAuthorizeForm = function (req, callback) {
  // The quoteattr() function is used in a context, where the result will not be evaluated by javascript
  // but must be interpreted by an XML or HTML parser, and it must absolutely avoid breaking the syntax
  // of an element attribute.
  var quoteattr = function(s, preserveCR) {
    preserveCR = preserveCR ? '&#13;' : '\n';
    return ('' + s) // Forces the conversion to string.
      .replace(/&/g, '&amp;') // This MUST be the 1st replacement.
      .replace(/'/g, '&apos;') // The 4 other predefined entities, required.
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
       // Add other replacements here for HTML only
       // Or for XML, only if the named entities are defined in its DTD.
      .replace(/\r\n/g, preserveCR) // Must be before the next replacement.
      .replace(/[\r\n]/g, preserveCR);
  };

  const getAuthorizeFormHelper = (err, buffer) => {
    if (err) {
      return callback(err);
    }

    var operation = 'authorize';
    var additionalParameters = this.getAdditionalParams(req, operation);
    var samlMessage = {
      SAMLRequest: buffer.toString('base64')
    };

    Object.keys(additionalParameters).forEach(k => {
      samlMessage[k] = additionalParameters[k] || '';
    });

    var formInputs = Object.keys(samlMessage).map(k => {
      return '<input type="hidden" name="' + k + '" value="' + quoteattr(samlMessage[k]) + '" />';
    }).join('\r\n');

    callback(null, [
      '<!DOCTYPE html>',
      '<html>',
      '<head>',
      '<meta charset="utf-8">',
      '<meta http-equiv="x-ua-compatible" content="ie=edge">',
      '</head>',
      '<body onload="document.forms[0].submit()">',
      '<noscript>',
      '<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>',
      '</noscript>',
      '<form method="post" action="' + encodeURI(this.options.entryPoint) + '">',
      formInputs,
      '<input type="submit" value="Submit" />',
      '</form>',
      '<script>document.forms[0].style.display="none";</script>', // Hide the form if JavaScript is enabled
      '</body>',
      '</html>'
    ].join('\r\n'));
  };

  this.generateAuthorizeRequest(req, this.options.passive, true, (err, request) => {
    if (err) {
      return callback(err);
    }

    if (this.options.skipRequestCompression) {
      getAuthorizeFormHelper(null, Buffer.from(request, 'utf8'));
    } else {
      zlib.deflateRaw(request, getAuthorizeFormHelper);
    }
  });

};

SAML.prototype.getLogoutUrl = function(req, options, callback) {
  return this.generateLogoutRequest(req)
    .then(request => {
      const operation = 'logout';
      const overrideParams = options ? options.additionalParams || {} : {};
      return this.requestToUrl(request, null, operation, this.getAdditionalParams(req, operation, overrideParams), callback);
    });
};

SAML.prototype.getLogoutResponseUrl = function(req, options, callback) {
  var response = this.generateLogoutResponse(req, req.samlLogoutRequest);
  var operation = 'logout';
  var overrideParams = options ? options.additionalParams || {} : {};
  this.requestToUrl(null, response, operation, this.getAdditionalParams(req, operation, overrideParams), callback);
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');

  if (cert.indexOf('-BEGIN CERTIFICATE-') === -1)
    cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  if (cert.indexOf('-END CERTIFICATE-') === -1)
    cert = cert + "\n-----END CERTIFICATE-----\n";

  return cert;
};

SAML.prototype.certsToCheck = function () {
  if (!this.options.cert) {
    return Q();
  }
  if (typeof(this.options.cert) === 'function') {
    return Q.nfcall(this.options.cert)
    .then(certs => {
      if (!Array.isArray(certs)) {
        certs = [certs];
      }
      return Q(certs);
    });
  }
  var certs = this.options.cert;
  if (!Array.isArray(certs)) {
    certs = [certs];
  }
  return Q(certs);
};

// This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
//   signature of the |currentNode|.
//
// See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
//   vectors against SAML signature verification.
SAML.prototype.validateSignature = function (fullXml, currentNode, certs) {
  const xpathSigQuery = ".//*[local-name(.)='Signature' and " +
                      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  const signatures = xpath(currentNode, xpathSigQuery);
  // This function is expecting to validate exactly one signature, so if we find more or fewer
  //   than that, reject.
  if (signatures.length != 1) {
    return false;
  }

  const signature = signatures[0];
  return certs.some(certToCheck => {
    return this.validateSignatureForCert(signature, certToCheck, fullXml, currentNode);
  });
};

// This function checks that the |signature| is signed with a given |cert|.
SAML.prototype.validateSignatureForCert = function (signature, cert, fullXml, currentNode) {
  const sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: key => "<X509Data></X509Data>",
    getKey: keyInfo => this.certToPEM(cert),
  };
  sig.loadSignature(signature);
  // We expect each signature to contain exactly one reference to the top level of the xml we
  //   are validating, so if we see anything else, reject.
  if (sig.references.length != 1 )
    return false;
  var refUri = sig.references[0].uri;
  var refId = (refUri[0] === '#') ? refUri.substring(1) : refUri;
  // If we can't find the reference at the top level, reject
  var idAttribute = currentNode.getAttribute('ID') ? 'ID' : 'Id';
  if (currentNode.getAttribute(idAttribute) != refId)
    return false;
  // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  //   multiple candidate references is bad news)
  var totalReferencedNodes = xpath(currentNode.ownerDocument,
                                  "//*[@" + idAttribute + "='" + refId + "']");

  if (totalReferencedNodes.length > 1) {
    return false;
  }
  return sig.checkSignature(fullXml);
};

SAML.prototype.validatePostResponse = function (container, callback) {
  var xml, doc, inResponseTo;

  Q.fcall(() => {
    xml = Buffer.from(container.SAMLResponse, 'base64').toString('utf8');
    doc = new xmldom.DOMParser({
    }).parseFromString(xml);

    if (!Object.prototype.hasOwnProperty.call(doc, 'documentElement'))
      throw new Error('SAMLResponse is not valid base64-encoded XML');

    inResponseTo = xpath(doc, "/*[local-name()='Response']/@InResponseTo");

    if (inResponseTo) {
      inResponseTo = inResponseTo.length ? inResponseTo[0].nodeValue : null;

      return this.validateInResponseTo(inResponseTo);
    }
  })
  .then(() => this.certsToCheck())
  .then(certs => {
    // Check if this document has a valid top-level signature
    var validSignature = false;
    if (this.options.cert && this.validateSignature(xml, doc.documentElement, certs)) {
      validSignature = true;
    }

    var assertions = xpath(doc, "/*[local-name()='Response']/*[local-name()='Assertion']");
    var encryptedAssertions = xpath(doc,
                                    "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");

    if (assertions.length + encryptedAssertions.length > 1) {
      // There's no reason I know of that we want to handle multiple assertions, and it seems like a
      //   potential risk vector for signature scope issues, so treat this as an invalid signature
      throw new Error('Invalid signature: multiple assertions');
    }

    if (assertions.length == 1) {
      if (this.options.cert &&
          !validSignature &&
            !this.validateSignature(xml, assertions[0], certs)) {
        throw new Error('Invalid signature');
      }
      return this.processValidlySignedAssertion(assertions[0].toString(), xml, inResponseTo, callback);
    }

    if (encryptedAssertions.length == 1) {
      if (!this.options.decryptionPvk)
        throw new Error('No decryption key for encrypted SAML response');

      var encryptedAssertionXml = encryptedAssertions[0].toString();

      var xmlencOptions = { key: this.options.decryptionPvk };
      return Q.ninvoke(xmlenc, 'decrypt', encryptedAssertionXml, xmlencOptions)
      .then(decryptedXml => {
        var decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
        var decryptedAssertions = xpath(decryptedDoc, "/*[local-name()='Assertion']");
        if (decryptedAssertions.length != 1)
          throw new Error('Invalid EncryptedAssertion content');

        if (this.options.cert &&
            !validSignature &&
              !this.validateSignature(decryptedXml, decryptedAssertions[0], certs))
          throw new Error('Invalid signature from encrypted assertion');

        this.processValidlySignedAssertion(decryptedAssertions[0].toString(), xml, inResponseTo, callback);
      });
    }

    // If there's no assertion, fall back on xml2js response parsing for the status &
    //   LogoutResponse code.

    var parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    };
    var parser = new xml2js.Parser(parserConfig);
    return Q.ninvoke( parser, 'parseString', xml)
    .then(doc => {
      var response = doc.Response;
      if (response) {
        var assertion = response.Assertion;
        if (!assertion) {
          var status = response.Status;
          if (status) {
            var statusCode = status[0].StatusCode;
            if (statusCode && statusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder") {
              var nestedStatusCode = statusCode[0].StatusCode;
              if (nestedStatusCode && nestedStatusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive") {
                if (this.options.cert && !validSignature) {
                  throw new Error('Invalid signature: NoPassive');
                }
                return callback(null, null, false);
              }
            }

            // Note that we're not requiring a valid signature before this logic -- since we are
            //   throwing an error in any case, and some providers don't sign error results,
            //   let's go ahead and give the potentially more helpful error.
            if (statusCode && statusCode[0].$.Value) {
              var msgType = statusCode[0].$.Value.match(/[^:]*$/)[0];
              if (msgType != 'Success') {
                  var msg = 'unspecified';
                  if (status[0].StatusMessage) {
                    msg = status[0].StatusMessage[0]._;
                  } else if (statusCode[0].StatusCode) {
                    msg = statusCode[0].StatusCode[0].$.Value.match(/[^:]*$/)[0];
                  }
                  var error = new Error('SAML provider returned ' + msgType + ' error: ' + msg);
                  var builderOpts = {
                    rootName: 'Status',
                    headless: true
                  };
                  error.statusXml = new xml2js.Builder(builderOpts).buildObject(status[0]);
                  throw error;
                }
              }
            }
            throw new Error('Missing SAML assertion');
          }
        } else {
          if (this.options.cert && !validSignature) {
            throw new Error('Invalid signature: No response found');
          }
          var logoutResponse = doc.LogoutResponse;
          if (logoutResponse){
            return callback(null, null, true);
          } else {
            throw new Error('Unknown SAML response message');
          }
        }
      });
  })
  .fail(err => {
    debug('validatePostResponse resulted in an error: %s', err);
    if (this.options.validateInResponseTo) {
      Q.ninvoke(this.cacheProvider, 'remove', inResponseTo)
      .then(function() {
        callback(err);
      });
    } else {
      callback(err);
    }
  })
  .done();
};

SAML.prototype.validateInResponseTo = function (inResponseTo) {
  if (this.options.validateInResponseTo) {
    if (inResponseTo) {
      return Q.ninvoke(this.cacheProvider, 'get', inResponseTo)
        .then(result => {
          if (!result)
            throw new Error('InResponseTo is not valid');
          return Q();
        });
    } else {
      throw new Error('InResponseTo is missing from response');
    }
  } else {
    return Q();
  }
};

SAML.prototype.validateRedirect = function(container, originalQuery, callback) {
  const samlMessageType = container.SAMLRequest ? 'SAMLRequest' : 'SAMLResponse';

  const data = Buffer.from(container[samlMessageType], "base64");
  zlib.inflateRaw(data, (err, inflated) => {
    if (err) {
      return callback(err);
    }

    const dom = new xmldom.DOMParser().parseFromString(inflated.toString());
    const parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    };
    const parser = new xml2js.Parser(parserConfig);
    parser.parseString(inflated, (err, doc) => {
      if (err) {
        return callback(err);
      }

      Q.fcall(() => {
        return samlMessageType === 'SAMLResponse' ?
          this.verifyLogoutResponse(doc) : this.verifyLogoutRequest(doc);
      })
      .then(() => this.hasValidSignatureForRedirect(container, originalQuery))
      .then(() => processValidlySignedSamlLogout(this, doc, dom, callback))
      .fail(err => callback(err));
    });
  });
};

function processValidlySignedSamlLogout(self, doc, dom, callback) {
  var response = doc.LogoutResponse;
  var request = doc.LogoutRequest;

  if (response){
    return callback(null, null, true);
  } else if (request) {
    processValidlySignedPostRequest(self, doc, dom, callback);
  } else {
    throw new Error('Unknown SAML response message');
  }
}

SAML.prototype.hasValidSignatureForRedirect = function (container, originalQuery) {
  const tokens = originalQuery.split('&');
  var getParam = key => {
    var exists = tokens.filter(t => { return new RegExp(key).test(t); });
    return exists[0];
  };

  if (container.Signature && this.options.cert) {
    var urlString = getParam('SAMLRequest') || getParam('SAMLResponse');

    if (getParam('RelayState')) {
      urlString += '&' + getParam('RelayState');
    }

    urlString += '&' + getParam('SigAlg');

    return this.certsToCheck()
      .then(certs => {
        var hasValidQuerySignature = certs.some(cert => {
          return this.validateSignatureForRedirect(
            urlString, container.Signature, container.SigAlg, cert
          );
        });

        if (!hasValidQuerySignature) {
          throw 'Invalid signature';
        }
      });
  } else {
    return Q(true);
  }
};

SAML.prototype.validateSignatureForRedirect = function (urlString, signature, alg, cert) {
  // See if we support a matching algorithm, case-insensitive. Otherwise, throw error.
  function hasMatch (ourAlgo) {
    // The incoming algorithm is forwarded as a URL.
    // We trim everything before the last # get something we can compare to the Node.js list
    const algFromURI = alg.toLowerCase().replace(/.*#(.*)$/,'$1');
    return ourAlgo.toLowerCase() === algFromURI;
  }
  let i = crypto.getHashes().findIndex(hasMatch);
  let matchingAlgo;
  if (i > -1) {
    matchingAlgo = crypto.getHashes()[i];
  }
  else {
    throw alg + ' is not supported';
  }

  var verifier = crypto.createVerify(matchingAlgo);
  verifier.update(urlString);

  return verifier.verify(this.certToPEM(cert), signature, 'base64');
};

SAML.prototype.verifyLogoutRequest = function (doc) {
  this.verifyIssuer(doc.LogoutRequest);
  var nowMs = new Date().getTime();
  var conditions = doc.LogoutRequest.$;
  var conErr = this.checkTimestampsValidityError(
    nowMs, conditions.NotBefore, conditions.NotOnOrAfter
  );
  if (conErr) {
    throw conErr;
  }
};

SAML.prototype.verifyLogoutResponse = function (doc) {
  return Q.fcall(() => {
    var statusCode = doc.LogoutResponse.Status[0].StatusCode[0].$.Value;
    if (statusCode !== "urn:oasis:names:tc:SAML:2.0:status:Success")
      throw 'Bad status code: ' + statusCode;

    this.verifyIssuer(doc.LogoutResponse);
    var inResponseTo = doc.LogoutResponse.$.InResponseTo;
    if (inResponseTo) {
      return this.validateInResponseTo(inResponseTo);
    }

    return Q(true);
  });
};

SAML.prototype.verifyIssuer = function (samlMessage) {
  if(this.options.idpIssuer) {
    var issuer = samlMessage.Issuer;
    if (issuer) {
      if (issuer[0]._ !== this.options.idpIssuer)
        throw 'Unknown SAML issuer. Expected: ' + this.options.idpIssuer + ' Received: ' + issuer[0]._;
    } else {
      throw 'Missing SAML issuer';
    }
  }
};

SAML.prototype.processValidlySignedAssertion = function(xml, samlResponseXml, inResponseTo, callback) {
  var msg;
  var parserConfig = {
    explicitRoot: true,
    explicitCharkey: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var nowMs = new Date().getTime();
  var profile = {};
  var assertion;
  var parsedAssertion;
  var parser = new xml2js.Parser(parserConfig);
  Q.ninvoke(parser, 'parseString', xml)
  .then(doc => {
    parsedAssertion = doc;
    assertion = doc.Assertion;

    var issuer = assertion.Issuer;
    if (issuer && issuer[0]._) {
      profile.issuer = issuer[0]._;
    }

    if (inResponseTo) {
      profile.inResponseTo = inResponseTo;
    }

    var authnStatement = assertion.AuthnStatement;
    if (authnStatement) {
      if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
        profile.sessionIndex = authnStatement[0].$.SessionIndex;
      }
    }

    var subject = assertion.Subject;
    var subjectConfirmation, confirmData;
    if (subject) {
      var nameID = subject[0].NameID;
      if (nameID && nameID[0]._) {
        profile.nameID = nameID[0]._;

        if (nameID[0].$ && nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
          profile.nameQualifier = nameID[0].$.NameQualifier;
          profile.spNameQualifier = nameID[0].$.SPNameQualifier;
        }
      }

      subjectConfirmation = subject[0].SubjectConfirmation ?
                            subject[0].SubjectConfirmation[0] : null;
      confirmData = subjectConfirmation && subjectConfirmation.SubjectConfirmationData ?
                    subjectConfirmation.SubjectConfirmationData[0] : null;
      if (subject[0].SubjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
        msg = 'Unable to process multiple SubjectConfirmations in SAML assertion';
        throw new Error(msg);
      }

      if (subjectConfirmation) {
        if (confirmData && confirmData.$) {
          var subjectNotBefore = confirmData.$.NotBefore;
          var subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;

          var subjErr = this.checkTimestampsValidityError(
                          nowMs, subjectNotBefore, subjectNotOnOrAfter);
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
          var subjectInResponseTo = confirmData.$.InResponseTo;
          if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
            return Q.ninvoke(this.cacheProvider, 'remove', inResponseTo)
              .then(() => {
                throw new Error('InResponseTo is not valid');
              });
          } else if (subjectInResponseTo) {
            var foundValidInResponseTo = false;
            return Q.ninvoke(this.cacheProvider, 'get', subjectInResponseTo)
              .then(result => {
                if (result) {
                  var createdAt = new Date(result);
                  if (nowMs < createdAt.getTime() + this.options.requestIdExpirationPeriodMs)
                    foundValidInResponseTo = true;
                }
                return Q.ninvoke(this.cacheProvider, 'remove', inResponseTo );
              })
              .then(() => {
                if (!foundValidInResponseTo) {
                  throw new Error('InResponseTo is not valid');
                }
                return Q();
              });
          }
        }
      } else {
        return Q.ninvoke(this.cacheProvider, 'remove', inResponseTo);
      }
    } else {
      return Q();
    }
  })
  .then(() => {
    var conditions = assertion.Conditions ? assertion.Conditions[0] : null;
    if (assertion.Conditions && assertion.Conditions.length > 1) {
      msg = 'Unable to process multiple conditions in SAML assertion';
      throw new Error(msg);
    }
    if(conditions && conditions.$) {
      var conErr = this.checkTimestampsValidityError(
                    nowMs, conditions.$.NotBefore, conditions.$.NotOnOrAfter);
      if(conErr)
        throw conErr;
    }

    if (this.options.audience) {
      var audienceErr = this.checkAudienceValidityError(
                    this.options.audience, conditions.AudienceRestriction);
      if(audienceErr)
        throw audienceErr;
    }

    var attributeStatement = assertion.AttributeStatement;
    if (attributeStatement) {
      var attributes = [].concat
                         .apply([],
                                attributeStatement.filter(attr => Array.isArray(attr.Attribute))
                                                  .map(attr => attr.Attribute)
                               );

      var attrValueMapper = function(value) {
        return typeof value === 'string' ? value : value._;
      };

      if (attributes) {
        attributes.forEach(attribute => {
         if(!Object.prototype.hasOwnProperty.call(attribute, 'AttributeValue')) {
            // if attributes has no AttributeValue child, continue
            return;
          }
          var value = attribute.AttributeValue;
          if (value.length === 1) {
            profile[attribute.$.Name] = attrValueMapper(value[0]);
          } else {
            profile[attribute.$.Name] = value.map(attrValueMapper);
          }
        });
      }
    }

    if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
      // See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary
      // for definition of attribute OIDs
      profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    profile.getAssertionXml = () => xml;
    profile.getAssertion = () => parsedAssertion;
    profile.getSamlResponseXml = () => samlResponseXml;

    callback(null, profile, false);
  })
  .fail(err => callback(err))
  .done();
};

SAML.prototype.checkTimestampsValidityError = function(nowMs, notBefore, notOnOrAfter) {
  if (this.options.acceptedClockSkewMs == -1)
      return null;

  if (notBefore) {
    var notBeforeMs = Date.parse(notBefore);
    if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs)
        return new Error('SAML assertion not yet valid');
  }
  if (notOnOrAfter) {
    var notOnOrAfterMs = Date.parse(notOnOrAfter);
    if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs)
      return new Error('SAML assertion expired');
  }

  return null;
};

SAML.prototype.checkAudienceValidityError = function(expectedAudience, audienceRestrictions) {
  if (!audienceRestrictions || audienceRestrictions.length < 1) {
    return new Error('SAML assertion has no AudienceRestriction');
  }
  var errors = audienceRestrictions.map(function(restriction) {
    if (!restriction.Audience || !restriction.Audience[0] || !restriction.Audience[0]._) {
      return new Error('SAML assertion AudienceRestriction has no Audience value');
    }
    if (restriction.Audience[0]._ !== expectedAudience) {
      return new Error('SAML assertion audience mismatch');
    }
    return null;
  }).filter(result => {
    return result !== null;
  });
  if (errors.length > 0) {
    return errors[0];
  }
  return null;
};

SAML.prototype.validatePostRequest = function (container, callback) {
  const xml = Buffer.from(container.SAMLRequest, 'base64').toString('utf8');
  const dom = new xmldom.DOMParser().parseFromString(xml);
  const parserConfig = {
    explicitRoot: true,
    explicitCharkey: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  const parser = new xml2js.Parser(parserConfig);
  parser.parseString(xml, (err, doc) => {
    if (err) {
      return callback(err);
    }

    this.certsToCheck()
    .then(certs => {
      // Check if this document has a valid top-level signature
      if (this.options.cert && !this.validateSignature(xml, dom.documentElement, certs)) {
        return callback(new Error('Invalid signature on documentElement'));
      }

      processValidlySignedPostRequest(this, doc, dom, callback);
    })
    .fail(err => callback(err));
  });
};

function callBackWithNameID(nameid, callback) {
  var format = xpath(nameid, "@Format");
  return callback(null, {
    value: nameid.textContent,
    format: format && format[0] && format[0].nodeValue
  });
}

SAML.prototype.getNameID = function(self, doc, callback) {
  var nameIds = xpath(doc, "/*[local-name()='LogoutRequest']/*[local-name()='NameID']");
  var encryptedIds = xpath(doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']");

  if (nameIds.length + encryptedIds.length > 1) {
    return callback(new Error('Invalid LogoutRequest'));
  }
  if (nameIds.length === 1) {
    return callBackWithNameID(nameIds[0], callback);
  }
  if (encryptedIds.length === 1) {
    if (!self.options.decryptionPvk) {
      return callback(new Error('No decryption key for encrypted SAML response'));
    }

    var encryptedDatas = xpath(encryptedIds[0], "./*[local-name()='EncryptedData']");

    if (encryptedDatas.length !== 1) {
      return callback(new Error('Invalid LogoutRequest'));
    }
    var encryptedDataXml = encryptedDatas[0].toString();

    var xmlencOptions = { key: self.options.decryptionPvk };
    return Q.ninvoke(xmlenc, 'decrypt', encryptedDataXml, xmlencOptions)
      .then(function (decryptedXml) {
        var decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
        var decryptedIds = xpath(decryptedDoc, "/*[local-name()='NameID']");
        if (decryptedIds.length !== 1) {
          return callback(new Error('Invalid EncryptedAssertion content'));
        }
        return callBackWithNameID(decryptedIds[0], callback);
      });
  }
  callback(new Error('Missing SAML NameID'));
};

function processValidlySignedPostRequest(self, doc, dom, callback) {
    var request = doc.LogoutRequest;
    if (request) {
      var profile = {};
      if (request.$.ID) {
          profile.ID = request.$.ID;
      } else {
        return callback(new Error('Missing SAML LogoutRequest ID'));
      }
      var issuer = request.Issuer;
      if (issuer && issuer[0]._) {
        profile.issuer = issuer[0]._;
      } else {
        return callback(new Error('Missing SAML issuer'));
      }
      self.getNameID(self, dom, function (err, nameID) {
        if(err) {
          return callback(err);
        }

        if (nameID) {
          profile.nameID = nameID.value;
          if (nameID.format) {
            profile.nameIDFormat = nameID.format;
          }
        } else {
          return callback(new Error('Missing SAML NameID'));
        }
        var sessionIndex = request.SessionIndex;
        if (sessionIndex) {
          profile.sessionIndex = sessionIndex[0]._;
        }
        callback(null, profile, true);
      });
    } else {
      return callback(new Error('Unknown SAML request message'));
    }
}

SAML.prototype.generateServiceProviderMetadata = function( decryptionCert, signingCert ) {
  var metadata = {
    'EntityDescriptor' : {
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      '@entityID': this.options.issuer,
      '@ID': this.options.issuer.replace(/\W/g, '_'),
      'SPSSODescriptor' : {
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
      },
    }
  };

  if (this.options.decryptionPvk) {
    if (!decryptionCert) {
      throw new Error(
        "Missing decryptionCert while generating metadata for decrypting service provider");
    }
  }

  if(this.options.privateCert){
    if(!signingCert){
      throw new Error(
        "Missing signingCert while generating metadata for signing service provider messages");
    }
  }

  if(this.options.decryptionPvk || this.options.privateCert){
    metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor=[];
    if (this.options.privateCert) {

      signingCert = signingCert.replace( /-+BEGIN CERTIFICATE-+\r?\n?/, '' );
      signingCert = signingCert.replace( /-+END CERTIFICATE-+\r?\n?/, '' );
      signingCert = signingCert.replace( /\r\n/g, '\n' );

      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        '@use': 'signing',
        'ds:KeyInfo' : {
          'ds:X509Data' : {
            'ds:X509Certificate': {
              '#text': signingCert
            }
          }
        }
      });
    }

    if (this.options.decryptionPvk) {

      decryptionCert = decryptionCert.replace( /-+BEGIN CERTIFICATE-+\r?\n?/, '' );
      decryptionCert = decryptionCert.replace( /-+END CERTIFICATE-+\r?\n?/, '' );
      decryptionCert = decryptionCert.replace( /\r\n/g, '\n' );

      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        '@use': 'encryption',
        'ds:KeyInfo' : {
          'ds:X509Data' : {
            'ds:X509Certificate': {
              '#text': decryptionCert
            }
          }
        },
        'EncryptionMethod' : [
          // this should be the set that the xmlenc library supports
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' },
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' },
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' }
        ]
      });
    }
  }

  if (this.options.logoutCallbackUrl) {
    metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
      '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Location': this.options.logoutCallbackUrl
    };
  }

  if (this.options.identifierFormat) {
    metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = this.options.identifierFormat;
  }

  metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
    '@index': '1',
    '@isDefault': 'true',
    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    '@Location': this.getCallbackUrl({})
  };
  return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
};

SAML.prototype.keyToPEM = function (key) {
  if (!key || typeof key !== 'string') return key;

  const lines = key.split('\n');
  if (lines.length !== 1) return key;

  const wrappedKey = [
    '-----BEGIN PRIVATE KEY-----',
    ...key.match(/.{1,64}/g),
    '-----END PRIVATE KEY-----',
    ''
  ].join('\n');
  return wrappedKey;
};

exports.SAML = SAML;
