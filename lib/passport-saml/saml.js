var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');
var xmlbuilder = require('xmlbuilder');
var xmlenc = require('xml-encryption');
var xpath = xmlCrypto.xpath;
var InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider;

var SAML = function (options) {
  var self = this;

  this.options = this.initialize(options);
  this.cacheProvider = this.options.cacheProvider;
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.path) {
    options.path = '/saml/consume';
  }

  if (!options.issuer) {
    options.issuer = 'onelogin_saml';
  }

  if (options.identifierFormat === undefined) {
    options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
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

  return options;
};

SAML.prototype.generateUniqueID = function () {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

SAML.prototype.generateInstant = function () {
  return new Date().toISOString();
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
};

SAML.prototype.generateAuthorizeRequest = function (req, isPassive) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();
  var protocol = this.options.protocol || (req.protocol || 'http').concat('://');
  var callbackUrl;

  if(this.options.validateInResponseTo) {
    this.cacheProvider.save(id, instant);
  }

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    callbackUrl = protocol + req.headers.host + this.options.path;
  }

  var request = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': instant,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@AssertionConsumerServiceURL': callbackUrl,
      '@Destination': this.options.entryPoint,
      'saml:Issuer' : {
        '@xmlns:saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': this.options.issuer
      },
      'samlp:RequestedAuthnContext' : {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Comparison': 'exact',
        'saml:AuthnContextClassRef': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        }
      }
    }
  };

  if (isPassive)
    request['samlp:AuthnRequest']['@IsPassive'] = true;

  if (this.options.identifierFormat) {
    request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@Format': this.options.identifierFormat,
      '@AllowCreate': 'true'
    };
  }

  return xmlbuilder.create(request).end();
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
      '@Destination': this.options.entryPoint,
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
  zlib.deflateRaw(request || response, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = self.options.entryPoint + '?';

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = self.options.logoutUrl + '?';
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
      samlMessage.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlMessage.Signature = self.signRequest(querystring.stringify(samlMessage));
    }
    target += querystring.stringify(samlMessage);

    callback(null, target);
  });
};

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest(req, this.options.passive);
  var RelayState = req.query && req.query.RelayState || req.body && req.body.RelayState;
  this.requestToUrl(request, null, 'authorize', RelayState ? { RelayState: RelayState } : {}, callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var request = this.generateLogoutRequest(req);
  var RelayState = req.query && req.query.RelayState || req.body && req.body.RelayState;
  this.requestToUrl(request, null, 'logout', RelayState ? { RelayState: RelayState } : {}, callback);
};

SAML.prototype.getLogoutResponseUrl = function(req, callback) {
  var response = this.generateLogoutResponse(req, req.samlLogoutRequest);
  var RelayState = req.query && req.query.RelayState || req.body && req.body.RelayState;
  this.requestToUrl(null, response, 'logout', RelayState ? { RelayState: RelayState } : {}, callback);
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

// This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
//   signature of the |currentNode|.
//
// See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
//   vectors against SAML signature verification.
SAML.prototype.validateSignature = function (fullXml, currentNode, cert) {
  var self = this;
  var xpathSigQuery = ".//*[local-name(.)='Signature' and " +
                      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  var signatures = xpath(currentNode, xpathSigQuery);
  // This function is expecting to validate exactly one signature, so if we find more or fewer
  //   than that, reject.
  if (signatures.length != 1)
    return false;
  var signature = signatures[0].toString();
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
  if (currentNode.getAttribute('ID') != refId)
    return false;
  // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  //   multiple candidate references is bad news)
  var totalReferencedNodes = xpath(currentNode.ownerDocument, "//*[@ID='" + refId + "']");
  if (totalReferencedNodes.length > 1)
    return false;
  return sig.checkSignature(fullXml);
};

SAML.prototype.validatePostResponse = function (container, callback) {
  var self = this;
  var xml = new Buffer(container.SAMLResponse, 'base64').toString('ascii');
  var doc = new xmldom.DOMParser().parseFromString(xml);

  var inResponseTo = xpath(doc, "/*[local-name()='Response']/@InResponseTo");
  if(inResponseTo){
    inResponseTo = inResponseTo.length ? inResponseTo[0].nodeValue : null;
  }

  if(self.options.validateInResponseTo){
    if(inResponseTo && !self.cacheProvider.get(inResponseTo)){
      return callback(new Error('InResponseTo is not valid'), null, false);
    }
  }

  // Check if this document has a valid top-level signature
  var validSignature = false;
  if (self.options.cert && self.validateSignature(xml, doc.documentElement, self.options.cert)) {
    validSignature = true;
  }

  var assertions = xpath(doc, "/*[local-name()='Response']/*[local-name()='Assertion']");
  var encryptedAssertions = xpath(doc,
    "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");

  if (assertions.length + encryptedAssertions.length > 1) {
    // There's no reason I know of that we want to handle multiple assertions, and it seems like a
    //   potential risk vector for signature scope issues, so treat this as an invalid signature
    return callback(new Error('Invalid signature'), null, false);
  }

  if (assertions.length == 1) {
    if (self.options.cert &&
        !validSignature &&
        !self.validateSignature(xml, assertions[0], self.options.cert)) {
      return callback(new Error('Invalid signature'), null, false);
    }
    return self.processValidlySignedAssertion(assertions[0].toString(), inResponseTo, callback);
  }

  if (encryptedAssertions.length == 1) {
    if (!self.options.decryptionPvk)
      return callback(new Error('No decryption key for encrypted SAML response', null, false));

    var encryptedDatas = xpath( encryptedAssertions[0], "./*[local-name()='EncryptedData']");
    if (encryptedDatas.length != 1)
      return callback(new Error('Invalid signature'), null, false);
    var encryptedDataXml = encryptedDatas[0].toString();

    var xmlencOptions = { key: self.options.decryptionPvk };
    return xmlenc.decrypt(encryptedDataXml, xmlencOptions, function(err, decryptedXml) {
      if ( err )
        return callback(err, null, false);

      var decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
      var decryptedAssertions = xpath(decryptedDoc, "/*[local-name()='Assertion']");
      if (decryptedAssertions.length != 1)
        return callback(new Error('Invalid EncryptedAssertion content'), null, false);

      if (self.options.cert && !self.validateSignature(decryptedXml, decryptedAssertions[0], self.options.cert))
        return callback(new Error('Invalid signature'), null, false);

      return self.processValidlySignedAssertion(decryptedAssertions[0].toString(), inResponseTo, callback);
    });
  }

  // If there's no assertion, and there is a top-level signature, fall back on xml2js response
  //   parsing for the passive status & LogoutResponse code.
  if (self.options.cert && !validSignature) {
    return callback(new Error('Invalid signature'), null, false);
  }
  var parserConfig = {
    explicitRoot: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var parser = new xml2js.Parser(parserConfig);
  parser.parseString(xml, function (err, doc) {
    if (err) {
      return callback(err, null, false);
    }
    var response = doc.Response;
    if (response) {
      var assertion = response.Assertion;
      if (!assertion) {
        var status = response.Status;
        if (status) {
          status = status[0].StatusCode;
          if (status && status[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder") {
            status = status[0].StatusCode;
            if (status && status[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive") {
              return callback(null, null, false);
            }
          }
        }
        return callback(new Error('Missing SAML assertion'), null, false);
      }
    } else {
      var logoutResponse = doc.LogoutResponse;
      if (logoutResponse){
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }
    }
  });
};

SAML.prototype.processValidlySignedAssertion = function(xml, inResponseTo, callback) {
  var self = this;
  var msg;
  var parserConfig = {
    explicitRoot: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var parser = new xml2js.Parser(parserConfig);
  parser.parseString(xml, function (err, doc) {
    if (err) {
      return callback(err, null, false);
    }

    var assertion = doc.Assertion;

    var profile = {};
    var issuer = assertion.Issuer;
    if (issuer) {
      profile.issuer = issuer[0];
    }

    var subject = assertion.Subject;
    if (subject) {
      var nameID = subject[0].NameID;
      if (nameID) {
          profile.nameID = nameID[0]._;

        if (nameID[0].$ && nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
        }
      }
    }

    var nowMs = new Date().getTime();
    var subjectConfirmation = subject[0].SubjectConfirmation ?
                              subject[0].SubjectConfirmation[0] : null;
    var confirmData = subjectConfirmation && subjectConfirmation.SubjectConfirmationData ?
                      subjectConfirmation.SubjectConfirmationData[0] : null;
    if (subject[0].SubjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
      msg = 'Unable to process multiple SubjectConfirmations in SAML assertion';
      return callback(new Error(msg), null, false);
    }

    // Test to see that if we have a SubjectConfirmation InResponseTo that it matches
    // the 'InResponseTo' attribute set in the Response
    if (self.options.validateInResponseTo) {
      if (subjectConfirmation) {
        if (confirmData && confirmData.$) {
          var subjectInResponseTo = confirmData.$.InResponseTo;
          if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
            self.cacheProvider.remove(inResponseTo);
            return callback(new Error('InResponseTo is not valid'), null, false);
          } else if (subjectInResponseTo) {
            var foundValidInResponseTo = false;
            if (self.cacheProvider.get(subjectInResponseTo)) {
              var createdAt = new Date(self.cacheProvider.get(subjectInResponseTo));
              if (nowMs < createdAt.getTime() + self.options.requestIdExpirationPeriodMs)
                foundValidInResponseTo = true;
            }
            if (!foundValidInResponseTo) {
              self.cacheProvider.remove(inResponseTo);
              return callback(new Error('InResponseTo is not valid'), null, false);
            }
          }
        }
      }
      self.cacheProvider.remove(inResponseTo);
    }

    if (subjectConfirmation) {
      if (confirmData && confirmData.$) {
        var subjectNotBefore = confirmData.$.NotBefore;
        var subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;

        var subjErr = self.checkTimestampsValidityError(
                        nowMs, subjectNotBefore, subjectNotOnOrAfter);
        if (subjErr) {
          return callback(subjErr, null, false);
        }
      }
    }

    var conditions = assertion.Conditions ? assertion.Conditions[0] : null;
    if (assertion.Conditions && assertion.Conditions.length > 1) {
      msg = 'Unable to process multiple conditions in SAML assertion';
      return callback(new Error(msg), null, false);
    }
    if(conditions && conditions.$) {
      var conErr = self.checkTimestampsValidityError(
                    nowMs, conditions.$.NotBefore, conditions.$.NotOnOrAfter);
      if(conErr){
        return callback(conErr, null, false);
      }
    }

    var attributeStatement = assertion.AttributeStatement;
    if (attributeStatement) {
      var attributes = attributeStatement[0].Attribute;

      var attrValueMapper = function(value) {
        return typeof value === 'string' ? value : value._;
      };

      if (attributes) {
        attributes.forEach(function (attribute) {
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
      // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
      profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
    }

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    profile.getAssertionXml = function() { return xml; };

    callback(null, profile, false);
  });
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

SAML.prototype.validatePostRequest = function (container, callback) {
  var self = this;
  var xml = new Buffer(container.SAMLRequest, 'base64').toString('ascii');
  var parserConfig = {
    explicitRoot: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var parser = new xml2js.Parser(parserConfig);
  parser.parseString(xml, function (err, doc) {
    if (err) {
      return callback(err, null, false);
    }

    // Check if this document has a valid top-level signature
    if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
      return callback(new Error('Invalid signature'), null, false);
    }

    processValidlySignedPostRequest(self, doc, callback);
  });
};

function processValidlySignedPostRequest(self, doc, callback) {
    var request = doc.LogoutRequest;
    if (request) {
      var profile = {};
      if (request.$.ID) {
          profile.ID = request.$.ID;
      } else {
        return callback(new Error('Missing SAML LogoutRequest ID'), null, false);
      }
      var issuer = request.Issuer;
      if (issuer) {
        profile.issuer = issuer[0];
      } else {
        return callback(new Error('Missing SAML issuer'), null, false);
      }

      var nameID = request.NameID;
      if (nameID) {
        profile.nameID = nameID[0]._;
        if (nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
        }
      } else {
        return callback(new Error('Missing SAML NameID'), null, false);
      }

      callback(null, profile, true);
    } else {
      return callback(new Error('Unknown SAML request message'), null, false);
    }
}

SAML.prototype.generateServiceProviderMetadata = function( decryptionCert ) {
  var keyDescriptor = null;
  if (this.options.decryptionPvk) {
    if (!decryptionCert) {
      throw new Error(
        "Missing decryptionCert while generating metadata for decrypting service provider");
    }

    decryptionCert = decryptionCert.replace( /-+BEGIN CERTIFICATE-+\r?\n?/, '' );
    decryptionCert = decryptionCert.replace( /-+END CERTIFICATE-+\r?\n?/, '' );

    keyDescriptor = {
      'ds:KeyInfo' : {
        'ds:X509Data' : {
          'ds:X509Certificate': {
            '#text': decryptionCert
          }
        }
      },
      '#list' : [
        // this should be the set that the xmlenc library supports
        { 'EncryptionMethod': { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' } },
        { 'EncryptionMethod': { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' } },
        { 'EncryptionMethod': { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' } },
      ]
    };
  }

  if (!this.options.callbackUrl) {
    throw new Error(
      "Unable to generate service provider metadata when callbackUrl option is not set");
  }

  var metadata = {
    'EntityDescriptor' : {
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      '@entityID': this.options.issuer,
      'SPSSODescriptor' : {
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'KeyDescriptor' : keyDescriptor,
        'NameIDFormat' : this.options.identifierFormat,
        'AssertionConsumerService' : {
          '@index': '1',
          '@isDefault': 'true',
          '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          '@Location': this.options.callbackUrl
        }
      },
    }
  };

  return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
};

exports.SAML = SAML;
