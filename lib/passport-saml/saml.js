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
var Q = require('q');

var SAML = function (options) {
  var self = this;

  this.options = this.initialize(options);
  this.cacheProvider = this.options.cacheProvider;
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (options.hasOwnProperty('cert') && !options.cert) {
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

  // Start suomifi additions configuration parameters
  //
  // Default values must be set so that with default configuration (i.e. if there are no values
  // given in configuration) default behaviour is to enable following checks / enforcements (i.e.
  //   suomifiAdditions.disable*
  // options default values must be false
  if (!options.suomifiAdditions) {
    options.suomifiAdditions = {};
  }

  if (!options.suomifiAdditions.disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes) {
    options.suomifiAdditions.disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes = false;
  }

  if (!options.suomifiAdditions.disableValidateInResponseEnforcementForUnitTestingPurposes) {
    options.suomifiAdditions.disableValidateInResponseEnforcementForUnitTestingPurposes = false;
  }

  if (!options.suomifiAdditions.disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes) {
    options.suomifiAdditions.disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes = false;
  }

  if (!options.suomifiAdditions.disableAssertionSignatureVerificationEnforcementForUnitTestPurposes) {
    options.suomifiAdditions.disableAssertionSignatureVerificationEnforcementForUnitTestPurposes = false;
  }

  if (!options.suomifiAdditions.disableAudienceCheckEnforcementForUnitTestPurposes) {
    options.suomifiAdditions.disableAudienceCheckEnforcementForUnitTestPurposes = false;
  }
  // End suomifi additions configuration parameters

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
  switch(this.options.signatureAlgorithm) {
    case 'sha256':
      samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
      signer = crypto.createSign('RSA-SHA256');
      break;
    case 'sha512':
      samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
      signer = crypto.createSign('RSA-SHA512');
      break;
    default:
      samlMessage.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      signer = crypto.createSign('RSA-SHA1');
      break;
  }
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
  samlMessage.Signature = signer.sign(this.options.privateCert, 'base64');
};

SAML.prototype.generateAuthorizeRequest = function (req, isPassive, reqOptions, callback) {
  var self = this;
  var id = "_" + self.generateUniqueID();
  var instant = self.generateInstant();
  var forceAuthn = self.options.forceAuthn || false;

  Q.fcall(function() {
    if(self.options.validateInResponseTo) {
      return Q.ninvoke(self.cacheProvider, 'save', id, instant);
    } else {
      return Q();
    }
  })
  .then(function(){
    var request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@AssertionConsumerServiceURL': self.getCallbackUrl(req),
        '@Destination': self.options.entryPoint,
        'saml:Issuer' : {
          '@xmlns:saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': self.options.issuer
        }
      }
    };

    if (isPassive)
      request['samlp:AuthnRequest']['@IsPassive'] = true;

    if (forceAuthn) {
      request['samlp:AuthnRequest']['@ForceAuthn'] = true;
    }

    if (self.options.identifierFormat) {
      request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Format': self.options.identifierFormat,
        '@AllowCreate': 'true'
      };
    }

    if (!self.options.disableRequestedAuthnContext) {
      var authnContextClassRefs = [];
      self.options.authnContext.forEach(function(value) {
        authnContextClassRefs.push({
            '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': value
        });
      });

      request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Comparison': 'exact',
        'saml:AuthnContextClassRef': authnContextClassRefs
      };
    }

    if (self.options.attributeConsumingServiceIndex) {
      request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] = self.options.attributeConsumingServiceIndex;
    }

    if (self.options.providerName) {
      request['samlp:AuthnRequest']['@ProviderName'] = self.options.providerName;
    }

    if (reqOptions && reqOptions.vetumaLang) {
      addVetumaLangExtension(request['samlp:AuthnRequest'], reqOptions.vetumaLang);
    }

    callback(null, xmlbuilder.create(request).end());
  })
  .fail(function(err){
    callback(err);
  })
  .done();
};

/*jshint -W069 */
function addVetumaLangExtension(parentTag, lang) {
  if (!parentTag['samlp:Extensions']) {
    parentTag['samlp:Extensions'] = {};
  }
  var extensionsTag = parentTag['samlp:Extensions'];

  var entry = extensionsTag['vetuma'] = {};
  entry['LG'] = {};
  entry['LG']['#text'] = lang;
  entry['@xmlns'] = 'urn:vetuma:SAML:2.0:extensions';
}
/*jshint +W069 */

SAML.prototype.generateLogoutRequest = function (req, options) {
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

  if (options && options.vetumaLang) {
    addVetumaLangExtension(request['samlp:LogoutRequest'], options.vetumaLang);
  }

  return xmlbuilder.create(request).end();
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
  var self = this;
  if (self.options.skipRequestCompression)
    requestToUrlHelper(null, Buffer.from(request || response, 'utf8'));
  else
    zlib.deflateRaw(request || response, requestToUrlHelper);

  function requestToUrlHelper(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = url.parse(self.options.entryPoint, true);

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = url.parse(self.options.logoutUrl, true);
      }
    } else if (operation !== 'authorize') {
        return callback(new Error("Unknown operation: "+operation));
    }

    var samlMessage = request ? {
      SAMLRequest: base64
    } : {
      SAMLResponse: base64
    };
    Object.keys(additionalParameters).forEach(function(k) {
      samlMessage[k] = additionalParameters[k];
    });

    if (self.options.privateCert) {
      try {
        if (!self.options.entryPoint) {
          throw new Error('"entryPoint" config parameter is required for signed messages');
        }

        // sets .SigAlg and .Signature
        self.signRequest(samlMessage);

      } catch (ex) {
        return callback(ex);
      }
    }
    Object.keys(samlMessage).forEach(function(k) {
      target.query[k] = samlMessage[k];
    });

    // Delete 'search' to for pulling query string from 'query'
    // https://nodejs.org/api/url.html#url_url_format_urlobj
    delete target.search;

    callback(null, url.format(target));
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
  var self = this;
  self.generateAuthorizeRequest(req, self.options.passive, options, function(err, request){
    if (err)
      return callback(err);
    var operation = 'authorize';
    var overrideParams = options ? options.additionalParams || {} : {};
    self.requestToUrl(request, null, operation, self.getAdditionalParams(req, operation, overrideParams), callback);
  });
};

SAML.prototype.getAuthorizeForm = function (req, reqOptions, callback) {
  var self = this;

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

  var getAuthorizeFormHelper = function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var operation = 'authorize';
    var additionalParameters = self.getAdditionalParams(req, operation);
    var samlMessage = {
      SAMLRequest: buffer.toString('base64')
    };

    Object.keys(additionalParameters).forEach(function(k) {
      samlMessage[k] = additionalParameters[k] || '';
    });

    var formInputs = Object.keys(samlMessage).map(function(k) {
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
      '<form method="post" action="' + encodeURI(self.options.entryPoint) + '">',
      formInputs,
      '<input type="submit" value="Submit" />',
      '</form>',
      '<script>document.forms[0].style.display="none";</script>', // Hide the form if JavaScript is enabled
      '</body>',
      '</html>'
    ].join('\r\n'));
  };

  self.generateAuthorizeRequest(req, self.options.passive, reqOptions, function(err, request) {
    if (err) {
      return callback(err);
    }

    if (self.options.skipRequestCompression) {
      getAuthorizeFormHelper(null, Buffer.from(request, 'utf8'));
    } else {
      zlib.deflateRaw(request, getAuthorizeFormHelper);
    }
  });

};

SAML.prototype.getLogoutUrl = function(req, options, callback) {
  var request = this.generateLogoutRequest(req, options);
  var operation = 'logout';
  var overrideParams = options ? options.additionalParams || {} : {};
  this.requestToUrl(request, null, operation, this.getAdditionalParams(req, operation, overrideParams), callback);
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
  var self = this;
  if (!self.options.cert) {
    return Q();
  }
  if (typeof(self.options.cert) === 'function') {
    return Q.nfcall(self.options.cert)
    .then(function(certs) {
      if (!Array.isArray(certs)) {
        certs = [certs];
      }
      return Q(certs);
    });
  }
  var certs = self.options.cert;
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
  var self = this;
  var xpathSigQuery = ".//*[local-name(.)='Signature' and " +
                      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  var signatures = xpath(currentNode, xpathSigQuery);
  // This function is expecting to validate exactly one signature, so if we find more or fewer
  //   than that, reject.
  if (signatures.length != 1)
    return false;
  var signature = signatures[0];
  return certs.some(function (certToCheck) {
    return self.validateSignatureForCert(signature, certToCheck, fullXml, currentNode);
  });
};

// This function checks that the |signature| is signed with a given |cert|.
SAML.prototype.validateSignatureForCert = function (signature, cert, fullXml, currentNode) {
  var self = this;
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
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
  if (totalReferencedNodes.length > 1)
    return false;
  return sig.checkSignature(fullXml);
};

SAML.prototype.validatePostResponse = function (container, callback) {
  var self = this;

  var xml, doc, inResponseTo;

  Q.fcall(function(){
    xml = Buffer.from(container.SAMLResponse, 'base64').toString('utf8');
    doc = new xmldom.DOMParser({
    }).parseFromString(xml);

    if (!doc.hasOwnProperty('documentElement'))
      throw new Error('SAMLResponse is not valid base64-encoded XML');

    inResponseTo = xpath(doc, "/*[local-name()='Response']/@InResponseTo");

    if (inResponseTo) {
      inResponseTo = inResponseTo.length ? inResponseTo[0].nodeValue : null;

      return self.validateInResponseTo(inResponseTo);
    }
  })
  .then(function() {
    return self.certsToCheck();
  })
  .then(function(certs) {
    // Check if this document has a valid top-level signature
    var validSignature = false;
    if (self.options.cert && self.validateSignature(xml, doc.documentElement, certs)) {
      validSignature = true;
    }
    // start suomifi additions
    if (validSignature !== true &&
      self.options.suomifiAdditions.disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes !== true)
    {
      // Enforce document level signature checking.
      //
      // According to this comment ( https://github.com/bergie/passport-saml/issues/180#issuecomment-289998792 ):
      // "Signatures are optional, and may not be provided by some IDPs..."
      // But this is not the case with the IdP being used at the moment (so there should not be any reason
      // to silently allow unsigned top responses).
      // Thus throw error if response documents' signature is not valid AND/OR if
      // options.cert was not configured (in which case signature was not even checked).
      //
      // NOTE: baseline passport-saml (1.0.0) does not cause hard failure in following situations:
      //
      // 1) top/message level signature does not match with content
      // 2) validateSignature method encounters more than one Signature elements when it tries to process message (i.e.
      //    when it tries to validate message level signature)
      //
      // About (1): passport-saml continues to process response and if response contains assertions it validates
      // assertions signature (if IdP certificates were configured)
      //
      // About (2): this situation can happen e.g. when IdP sends SAML login response so that message AND assertion
      // are signed BUT assertion is not encrypted. I.e. in this particular case this:
      // https://github.com/bergie/passport-saml/blob/d2c89947fca1fa79365f5819a0e7326ebc94728a/lib/passport-saml/saml.js#L519-L525
      // code blocks xpath picks up two Signature elements (during message's signature is verification) and ends up
      // returning false (due reasons described in code commens above that particular method).
      //
      // What this means from suomi.fi point of view is that unencrypted assertions shall NOT work (because suomi.fi
      // IdP signs message and assertion) BUT this is not a problem because SP should / must not accept unencrypted
      // assertions (see EncryptedAssertionsOnlyPolicyEnforcement)

      throw new Error('Invalid top level signature');
    }
    // end suomifi additions

    var assertions = xpath(doc, "/*[local-name()='Response']/*[local-name()='Assertion']");
    var encryptedAssertions = xpath(doc,
      "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");

    if (assertions.length + encryptedAssertions.length > 1) {
      // There's no reason I know of that we want to handle multiple assertions, and it seems like a
      //   potential risk vector for signature scope issues, so treat this as an invalid signature
      throw new Error('Invalid signature: multiple assertions');
    }

    // start suomifi additions
    if (assertions.length > 0 &&
      self.options.suomifiAdditions.disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes !== true )
    {
      // There should not be any reason to process unencrypted assertion.
      // I.e. if assertion(s) are not encrypted there must be some configuration
      // error either with SAML SP's metadata or in IdP
      //
      // That being said unencrypted assertions are allowed if passport-saml
      // is explicitly configured to allow those (for example to debugging purposes)
      //
      // "encrypted assertion(s) only" policy enforcement is one piece in the puzzle of preventing
      // SAML login response replay attacks. Other pieces of the puzzle are "audience check" policy
      // enforcement and "validateInResponseTo" feature. For more comments about these check
      // code comments of "audience check" policy enforcement code block from the assertion processing
      // section of this passport-saml fork...starting with "// Audience validation is one piece in...").
      //
      throw new Error('Unencrypted assertion(s) are not allowed');
    }
    // end suomifi additions

    if (assertions.length == 1) {
      // start suomifi addition
      if (self.options.suomifiAdditions.disableAssertionSignatureVerificationEnforcementForUnitTestPurposes !== true)
      {
        // At the time of writing this comment passport-saml's (0.32.1) default behaviour is/was that if
        // documents top level signature is valid then validation of assertion's signature is skipped.
        //
        // Validity of assertion's signature must also be done thus this sparated code block which
        // performs validateSignature check regardless of value of "validSignature" variable.
        //
        // NOTE: SAML SP metadata MUST have WantAssertionsSigned="true" in SPSSODescriptor in
        //       order to receive signed assertions
        // NOTE2: if you change this code block keep in mind that validateSignature check
        //        is done in two places (when handling unencrypted assertions and when handling encrypted
        //        assertions)
        // NOTE3: if - e.g. due some passport-saml upgrade merge - signature validation code
        //        outside of this suomifi addition code block is changed check that same changes
        //        are reflected inside this code block also

        if (self.validateSignature(xml, assertions[0], certs) !== true) {
          throw new Error('Invalid assertion signature');
        }
      }
      // end suomifi addition...passport-saml's default code block is executed also...
      if (self.options.cert &&
          !validSignature &&
          !self.validateSignature(xml, assertions[0], certs)) {
        throw new Error('Invalid signature');
      }
      return self.processValidlySignedAssertion(assertions[0].toString(), inResponseTo, callback);
    }

    if (encryptedAssertions.length == 1) {
      if (!self.options.decryptionPvk)
        throw new Error('No decryption key for encrypted SAML response');

      var encryptedAssertionXml = encryptedAssertions[0].toString();

      var xmlencOptions = { key: self.options.decryptionPvk };
      return Q.ninvoke(xmlenc, 'decrypt', encryptedAssertionXml, xmlencOptions)
        .then(function(decryptedXml) {
          var decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
          var decryptedAssertions = xpath(decryptedDoc, "/*[local-name()='Assertion']");
          if (decryptedAssertions.length != 1)
            throw new Error('Invalid EncryptedAssertion content');

          // start suomifi addition
          if (self.options.suomifiAdditions.disableAssertionSignatureVerificationEnforcementForUnitTestPurposes !== true)
          {
            // At the time of writing this comment passport-saml's (0.32.1) default behaviour is/was that if
            // documents top level signature is valid then validation of assertion's signature is skipped.
            //
            // Validity of assertion's signature must also be done thus this sparated code block which
            // performs validateSignature check regardless of value of "validSignature" variable.
            //
            // NOTE: SAML SP metadata MUST have WantAssertionsSigned="true" in SPSSODescriptor in
            //       order to receive signed assertions
            // NOTE2: if you change this code block keep in mind that validateSignature check
            //        is done in two places (when handling unencrypted assertions and when handling encrypted
            //        assertions)
            // NOTE3: if - e.g. due some passport-saml upgrade merge - signature validation code
            //        outside of this suomifi addition code block is changed check that same changes
            //        are reflected inside this code block also

            // NOTE4: this processes decryptedXml and decryptedAssertions (just a side note if following
            //        check is copy pasted at some point in the future due some change from unencrypted
            //        assertions code block)
            if (self.validateSignature(decryptedXml, decryptedAssertions[0], certs) !== true) {
              throw new Error('Invalid assertion signature');
            }
          }
          // end suomifi addition...passport-saml's default code block is executed also...
          if (self.options.cert &&
              !validSignature &&
              !self.validateSignature(decryptedXml, decryptedAssertions[0], certs))
            throw new Error('Invalid signature from encrypted assertion');

          self.processValidlySignedAssertion(decryptedAssertions[0].toString(), inResponseTo, callback);
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
      .then(function(doc) {
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
                  if (self.options.cert && !validSignature) {
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
          if (self.options.cert && !validSignature) {
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
  .fail(function(err) {
    debug('validatePostResponse resulted in an error: %s', err);
    callback(err);
  })
  .done();
};

SAML.prototype.validateInResponseTo = function (inResponseTo) {
  if (this.options.validateInResponseTo) {
    if (inResponseTo) {
      return Q.ninvoke(this.cacheProvider, 'get', inResponseTo)
        .then(function(result) {
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

SAML.prototype.validateRedirect = function(container, callback) {
  var self = this;
  var samlMessageType = container.SAMLRequest ? 'SAMLRequest' : 'SAMLResponse';

  var data = Buffer.from(container[samlMessageType], "base64");
  zlib.inflateRaw(data, function(err, inflated) {
    if (err) {
      return callback(err);
    }

    var dom = new xmldom.DOMParser().parseFromString(inflated.toString());
    var parserConfig = {
      explicitRoot: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    };
    var parser = new xml2js.Parser(parserConfig);
    parser.parseString(inflated, function (err, doc) {
      if (err) {
        return callback(err);
      }

      Q.fcall(function () {
        return samlMessageType === 'SAMLResponse' ?
          self.verifyLogoutResponse(doc) : self.verifyLogoutRequest(doc);
      })
      .then(function() {
        return self.hasValidSignatureForRedirect(samlMessageType, container);
      })
      .then(function () {
        processValidlySignedSamlLogout(self, doc, callback);
      })
      .fail(function(err) {
        callback(err);
      });
    });
  });
};

function processValidlySignedSamlLogout(self, doc, callback) {
  var response = doc.LogoutResponse;
  var request = doc.LogoutRequest;

  if (response){
    return callback(null, null, true);
  } else if (request) {
    processValidlySignedPostRequest(self, doc, callback);
  } else {
    throw new Error('Unknown SAML response message');
  }
}

SAML.prototype.hasValidSignatureForRedirect = function (samlMessageType, container) {
  var signature = container.Signature;
  if (signature && this.options.cert) {
    var urlString = samlMessageType + '=' + encodeURIComponent(container[samlMessageType]);

    if (container.RelayState) {
      urlString += '&RelayState=' +
        encodeURIComponent(container.RelayState);
    }

    urlString += '&SigAlg=' + encodeURIComponent(container.SigAlg);

    return this.certsToCheck()
      .then(function(certs) {
        var hasValidQuerySignature = certs.some(function (cert) {
          return validateSignatureForRedirect(
            urlString, signature, container.SigAlg, cert
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

function validateSignatureForRedirect (urlString, signature, alg, cert) {
  var supportedAlgs = crypto.getHashes().filter(
    function(h) { return new RegExp(h).test(alg); }
  );

  if (supportedAlgs.length === 0) {
    throw alg + ' is not supported';
  }

  var verifier = crypto.createVerify(supportedAlgs[supportedAlgs.length-1]);
  verifier.update(urlString);

  return verifier.verify(cert, signature, 'base64');
}

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
  var self = this;

  return Q.fcall(function() {
    var statusCode = doc.LogoutResponse.Status[0].StatusCode[0].$.Value;
    if (statusCode !== "urn:oasis:names:tc:SAML:2.0:status:Success")
      throw 'Bad status code: ' + statusCode;

    self.verifyIssuer(doc.LogoutResponse);
    var inResponseTo = doc.LogoutResponse.$.InResponseTo;
    if (inResponseTo) {
      return self.validateInResponseTo(inResponseTo);
    }

    return Q(true);
  });
};

SAML.prototype.verifyIssuer = function (samlMessage) {
  if(this.options.idpIssuer) {
    var issuer = samlMessage.Issuer;
    if (issuer) {
      if (issuer[0] !== this.options.idpIssuer && issuer[0]._ !== this.options.idpIssuer)
        throw 'Unknown SAML issuer. Expected: ' + this.options.idpIssuer + ' Received: ' + issuer[0];
    } else {
      throw 'Missing SAML issuer';
    }
  }
};

SAML.prototype.processValidlySignedAssertion = function(xml, inResponseTo, callback) {
  var self = this;
  var msg;
  var parserConfig = {
    explicitRoot: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var nowMs = new Date().getTime();
  var profile = {};
  var assertion;
  var parsedAssertion;
  var parser = new xml2js.Parser(parserConfig);
  Q.ninvoke(parser, 'parseString', xml)
  .then(function(doc) {
	parsedAssertion = doc;
    assertion = doc.Assertion;

    var issuer = assertion.Issuer;
    if (issuer) {
      profile.issuer = issuer[0];
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
      if (nameID) {
        profile.nameID = nameID[0]._ || nameID[0];

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

          var subjErr = self.checkTimestampsValidityError(
                          nowMs, subjectNotBefore, subjectNotOnOrAfter);
          if (subjErr) {
            throw subjErr;
          }
        }
      }
    }

    // start suomifi additions
    if ( ! self.options.validateInResponseTo &&
      self.options.suomifiAdditions.disableValidateInResponseEnforcementForUnitTestingPurposes !== true )
    {
      // Assertions must not be processed if validateInResponseTo check is switched off due e.g.
      // configuration error.
      //
      // "validateInResponseTo" feature is one piece in the puzzle of preventing replay attacks.
      // Other pieces are "audience checking" and "enforce encrypted asserion(s) only" policy (see
      // code comment about these from "audience check" enforcement part of this passport-saml fork (see few
      // lines below starting with "// Audience validation is one piece...")).
      //
      // That being said disableValidateInResponseEnforcementForUnitTestingPurposes flag
      // is used to control whether this enforcing is active e.g. in unit tests in order
      // to be able to test this stack with predefined SAML responsens
      throw new Error('validateInResponseTo feature is not configured on');
    }
    // end suomifi additions

    // Test to see that if we have a SubjectConfirmation InResponseTo that it matches
    // the 'InResponseTo' attribute set in the Response
    if (self.options.validateInResponseTo) {
      if (subjectConfirmation) {
        if (confirmData && confirmData.$) {
          var subjectInResponseTo = confirmData.$.InResponseTo;
          if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
            return Q.ninvoke(self.cacheProvider, 'remove', inResponseTo)
              .then(function(){
                throw new Error('InResponseTo is not valid');
              });
          } else if (subjectInResponseTo) {
            var foundValidInResponseTo = false;
            return Q.ninvoke(self.cacheProvider, 'get', subjectInResponseTo)
              .then(function(result){
                if (result) {
                  var createdAt = new Date(result);
                  if (nowMs < createdAt.getTime() + self.options.requestIdExpirationPeriodMs)
                    foundValidInResponseTo = true;
                }
                return Q.ninvoke(self.cacheProvider, 'remove', inResponseTo );
              })
              .then(function(){
                if (!foundValidInResponseTo) {
                  throw new Error('InResponseTo is not valid');
                }
                return Q();
              });
          }
        }
      } else {
        return Q.ninvoke(self.cacheProvider, 'remove', inResponseTo);
      }
    } else {
      return Q();
    }
  })
  .then(function(){
    var conditions = assertion.Conditions ? assertion.Conditions[0] : null;
    if (assertion.Conditions && assertion.Conditions.length > 1) {
      msg = 'Unable to process multiple conditions in SAML assertion';
      throw new Error(msg);
    }
    if(conditions && conditions.$) {
      var conErr = self.checkTimestampsValidityError(
                    nowMs, conditions.$.NotBefore, conditions.$.NotOnOrAfter);
      if(conErr)
        throw conErr;
    }

    if (self.options.audience) {
      var audienceErr = self.checkAudienceValidityError(
                    self.options.audience, conditions.AudienceRestriction);
      if(audienceErr)
        throw audienceErr;
    }

    // start suomifi additions
    if ( ! self.options.audience &&
      self.options.suomifiAdditions.disableAudienceCheckEnforcementForUnitTestPurposes !== true )
    {
      // Enforce that audience check was done. I.e. if options.audience was not configured
      // (and thus audience checking is not performed) throw exception.
      //
      // Audience validation is one piece in the puzzle of preventing replay attacks. E.g.
      // capturing and replaying SAML login response (signed with same IdP's certificate which is used
      // by the application that is using this passport-saml fork) but targeted to some other SAML SP (i.e.
      // to another audience).
      //
      // Other pieces in the mentioned puzzle are:
      // - "validateInResponseTo" feature which is meant to prevent replaying any SAML response including but not
      //   limited to SAML response that was actually a response to SAML request initiated by the application
      //   that is using instance of this passport-saml fork (i.e. regardless of audience)
      // - "allow only encrypted assertion(s)" policy enforcement. I.e. by not allowing plain text assertion(s)
      //   instances of the application using this passport-saml fork are not able to process assertion(s) which
      //   cannot be decrypted with this passport-saml fork instance's private key (i.e. in order to perform
      //   replay attack with SAML response captured from another SAML SP that particular SAML SP would have to
      //   have same private key). "Allow only encrypted assertion" policy makes it also hard
      //   to replay SAML login response targeted for the application using this passport-saml fork to another
      //   SAML SP (because that another SAML SP would have to have same private key in order to decrypt assertion)
      //
      // So...audience check enforcement somewhat overlaps with "allow only encrypted assertion" policy but there
      // might be times when "encrypted assertion(s) only" policy must be turned off e.g. for debugging purposes.
      //
      // NOTE: passport-saml has issue https://github.com/bergie/passport-saml/issues/137
      // which is not marked as closed (at the time of writing this code comment) even though commit
      // https://github.com/bergie/passport-saml/commit/c2ce79d51d93b68e34911e74bb06cf915d8a754b
      // has introduced audience checking to passport-saml (starting from passport-saml 0.32.0)
      // (at the time of writing this code comment baseline for this passport-saml fork is passport-saml 0.32.1 )
      //
      throw new Error('options.audience was not configured');
    }
    // end suomifi additions

    var attributeStatement = assertion.AttributeStatement;
    if (attributeStatement) {
      var attributes = [].concat.apply([], attributeStatement.filter(function (attr) {
        return Array.isArray(attr.Attribute);
      }).map(function (attr) {
        return attr.Attribute;
      }));

      var attrValueMapper = function(value) {
        return typeof value === 'string' ? value : value._;
      };

      if (attributes) {
        attributes.forEach(function (attribute) {
         if(!attribute.hasOwnProperty('AttributeValue')) {
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

    profile.getAssertionXml = function() { return xml; };
    profile.getAssertion = function() { return parsedAssertion; };

    callback(null, profile, false);
  })
  .fail(function(err) {
    callback(err);
  })
  .done();
};

SAML.prototype.checkTimestampsValidityError = function(nowMs, notBefore, notOnOrAfter) {
  var self = this;
  if (self.options.acceptedClockSkewMs == -1)
      return null;

  if (notBefore) {
    var notBeforeMs = Date.parse(notBefore);
    if (nowMs + self.options.acceptedClockSkewMs < notBeforeMs)
        return new Error('SAML assertion not yet valid');
  }
  if (notOnOrAfter) {
    var notOnOrAfterMs = Date.parse(notOnOrAfter);
    if (nowMs - self.options.acceptedClockSkewMs >= notOnOrAfterMs)
      return new Error('SAML assertion expired');
  }

  return null;
};

SAML.prototype.checkAudienceValidityError = function(expectedAudience, audienceRestrictions) {
  var self = this;
  if (!audienceRestrictions || audienceRestrictions.length < 1) {
    return new Error('SAML assertion has no AudienceRestriction');
  }
  var errors = audienceRestrictions.map(function(restriction) {
    if (!restriction.Audience || !restriction.Audience[0]) {
      return new Error('SAML assertion AudienceRestriction has no Audience value');
    }
    if (restriction.Audience[0] !== expectedAudience) {
      return new Error('SAML assertion audience mismatch');
    }
    return null;
  }).filter(function(result) {
    return result !== null;
  });
  if (errors.length > 0) {
    return errors[0];
  }
  return null;
};

SAML.prototype.validatePostRequest = function (container, callback) {
  var self = this;
  var xml = Buffer.from(container.SAMLRequest, 'base64').toString('utf8');
  var dom = new xmldom.DOMParser().parseFromString(xml);
  var parserConfig = {
    explicitRoot: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var parser = new xml2js.Parser(parserConfig);
  parser.parseString(xml, function (err, doc) {
    if (err) {
      return callback(err);
    }

    self.certsToCheck()
    .then(function(certs) {
      // Check if this document has a valid top-level signature
      if (self.options.cert && !self.validateSignature(xml, dom.documentElement, certs)) {
        return callback(new Error('Invalid signature on documentElement'));
      }

      processValidlySignedPostRequest(self, doc, callback);
    })
    .fail(function(err) {
      callback(err);
    });
  });
};

function processValidlySignedPostRequest(self, doc, callback) {
    var request = doc.LogoutRequest;
    if (request) {
      var profile = {};
      if (request.$.ID) {
          profile.ID = request.$.ID;
      } else {
        return callback(new Error('Missing SAML LogoutRequest ID'));
      }
      var issuer = request.Issuer;
      if (issuer) {
        profile.issuer = issuer[0];
      } else {
        return callback(new Error('Missing SAML issuer'));
      }

      var nameID = request.NameID;
      if (nameID) {
        profile.nameID = nameID[0]._ || nameID[0];

        if (nameID[0].$ && nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
        }
      } else {
        return callback(new Error('Missing SAML NameID'));
      }
      var sessionIndex = request.SessionIndex;
      if (sessionIndex) {
        profile.sessionIndex = sessionIndex[0];
      }

      callback(null, profile, true);
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

  metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = this.options.identifierFormat;
  metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
    '@index': '1',
    '@isDefault': 'true',
    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    '@Location': this.getCallbackUrl({})
  };
  return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
};

exports.SAML = SAML;
