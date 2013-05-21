var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var SAML = function(options) {
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function(options) {
  if (!options) {
    options = {};
  }

  return options;
};

SAML.prototype.generateUniqueID = function() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random() * 15)), 1);
  }
  return uniqueID;
};

SAML.prototype.generateInstant = function() {
  return new Date().toISOString();
};

SAML.prototype.signRequest = function(xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
};

SAML.prototype.generateAuthorizeRequest = function(opt, req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  var request =
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
    "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + this.options.callbackUrl.replace(/&/g, '&amp;') + "\" Destination=\"" + opt.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + opt.issuer + "</saml:Issuer>\n";

  if (opt.includeIdentifierFormatInRequests && opt.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat +
      "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }

  request +=
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
    "</samlp:AuthnRequest>";

  if (this.options.logging) {
    console.log("about to send authorize request: " + request);
  }
  return request;
};

SAML.prototype.generateLogoutRequest = function(opt, req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  var logoutEntryPoint = opt.entryPoint;

  if (opt.logoutEntryPoint) {
    logoutEntryPoint = opt.logoutEntryPoint;
  }

  var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant + "\" Destination=\"" + logoutEntryPoint + "\">" +
    "<Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + opt.issuer + "</Issuer>" +
    "<NameID xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"" + opt.identifierFormat + "\">" + req.user.nameID + "</NameID>";

  if (opt.includeSessionIdInLogoutRequests) {
    request += "<samlp:SessionIndex>" + req.user.sessionIndex + "</samlp:SessionIndex>";
  }

  request += "</samlp:LogoutRequest>";

  if (this.options.logging) {
    console.log("about to send logout request: " + request);
  }

  return request;
};

SAML.prototype.requestToUrl = function(request, target, callback) {
  var self = this;
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var samlRequest = {
      SAMLRequest: base64
    };

    if (self.options.privateCert) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }

    target += "?" + querystring.stringify(samlRequest);

    callback(null, target);
  });
};

SAML.prototype.validateSignature = function(req, cert) {
  var verifier = crypto.createVerify('RSA-SHA1');
  var regex = /(?:SAMLRequest|SAMLResponse)=[^&]*&(?:RelayState=value&){0,1}SigAlg=[^&]*/;

  var matches = regex.exec(req.originalUrl);
  if (!matches) {
    if (this.options.logging) {
      console.log("No matches found in req.originalUrl: " + req.originalUrl);
    }
    return false;
  }

  if (matches.length < 1) {
    if (this.options.logging) {
      console.log("Could not parse req.originalUrl: " + req.originalUrl);
    }
    return false;
  }

  verifier.update(matches[0]);
  return verifier.verify(this.certToPEM(cert), req.query.Signature, 'base64');
};

SAML.prototype.getAuthorizeUrl = function(issuer, req, callback) {
  var request = this.generateAuthorizeRequest(this.options, req);
  this.requestToUrl(request, this.options.entryPoint, callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var target = this.options.entryPoint;

  if (this.options.logoutEntryPoint) {
    target = this.options.logoutEntryPoint;
  }

  var request = this.generateLogoutRequest(this.options, req);
  this.requestToUrl(request, target, callback);
};

SAML.prototype.certToPEM = function(cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateXmlSignature = function(xml, cert) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath.SelectNodes(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function(key) {
      return "<X509Data></X509Data>";
    },
    getKey: function(keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function(parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:' + elementName]) {
    return parentElement['samlp:' + elementName];
  }
  return parentElement[elementName];
};


SAML.prototype.validateGETLogoutResponse = function(req, callback) {
  var self = this;

  var issuer = req.user.issuer;

  if (!req.query) {
    callback(new Error('No querystring'));
  }

  if (!req.query.SAMLResponse) {
    callback(new Error('No SAMLResponse in querystring'));
  }

  var signature = req.query.Signature;
  var sigAlg = req.query.SigAlg;

  if (this.options.cert) {
    if (signature && sigAlg) {
      if (sigAlg !== 'http://www.w3.org/2000/09/xmldsig#rsa-sha1') {
        return callback(new Error('Invalid sigAlg, expected \"http://www.w3.org/2000/09/xmldsig#rsa-sha1\", got \"' + sigAlg + '\".'));
      }

      if (!self.validateSignature(req, this.options.cert)) {
        return callback(new Error('Invalid signature on logout response.'));
      }
    } else {
      return callback(new Error('Expected logout response to be signed but it was not.'));
    }
  }

  zlib.inflateRaw(new Buffer(req.query.SAMLResponse, 'base64'), function(err, buffer) {
    if (err) {
      return callback(err);
    }
    self.validateLogoutResponse(issuer, buffer.toString('ascii'), 'ascii', true, callback);
  });


}

SAML.prototype.validateLogoutResponse = function(issuer, samlResponse, samlResponseFormat, signatureValidated, callback) {
  var self = this;
  var xml;

  if (samlResponseFormat == 'base64') {
    xml = new Buffer(samlResponse, 'base64').toString('ascii');
  } else if (samlResponseFormat == 'ascii') {
    xml = samlResponse;
  } else {
    callback(new Error('samlResponseFormat = \'' + samlResponseFormat + '\', expected either base64 or ascii'));
  }

  if (self.options.logging) {
    console.log("Got logout response: " + xml);
  }

  var parser = new xml2js.Parser();
  parser.parseString(xml, function(err, doc) {

    if (self.options.cert && !signatureValidated) {
      // validate XML signature in a POSTed response
      if (!self.validateXmlSignature(xml, self.options.cert)) {
        return callback(new Error('Invalid xml signature in SAML logout response.'));
      }
    }

    var logoutResponse = self.getElement(doc, 'LogoutResponse');

    if (logoutResponse) {
      if (self.validateStatusCode(logoutResponse, callback)) {
        callback(null);
      }
    } else {
      callback(new Error('SAML logout response root node was not LogoutResponse.'));
    }
  });
}

SAML.prototype.validateStatusCode = function(node, callback) {
  var logoutStatus = this.getElement(node, 'Status');
  if (logoutStatus) {
    var statusCode = this.getElement(logoutStatus[0], 'StatusCode');
    if (statusCode) {
      if (statusCode[0].$ && statusCode[0].$.Value) {
        var code = statusCode[0].$.Value.toString();
        if (code == 'urn:oasis:names:tc:SAML:2.0:status:Success') {
          return true;
        } else {
          callback(new Error('Unexpected StatusCode.  Expected \'urn:oasis:names:tc:SAML:2.0:status:Success\', got \'' + code + '\''));
        }
      } else {
        callback(new Error('StatusCode value not found in SAML logout response.'));
      }
    } else {
      callback(new Error('StatusCode not found in SAML logout response.'));
    }
  } else {
    callback(new Error('Status not found in SAML logout response.'));
  }

  return false;
}

// this only supports POSTs
SAML.prototype.validateAuthenticateResponse = function(samlResponse, callback) {

  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');

  if (self.options.logging) {
    console.log("Got authenticate response: " + xml);
  }

  var parser = new xml2js.Parser();
  parser.parseString(xml, function(err, doc) {
    // Verify signature
    if (self.options.cert && !self.validateXmlSignature(xml, self.options.cert)) {
      return callback(new Error('Invalid signature'), null);
    }

    var response = self.getElement(doc, 'Response');
    if (response) {

      if (!self.validateStatusCode(response, callback)) {
        // validateStatusCode returns calls callback with an error and returns false if the status code is invalid.
        return;
      }

      var assertion = self.getElement(response, 'Assertion');
      if (!assertion) {
        return callback(new Error('Missing SAML assertion'), null);
      }

      profile = {};
      var issuer = self.getElement(assertion[0], 'Issuer');
      if (issuer) {
        if (issuer.toString() !== self.options.expectedIssuer.toString()) {
          return callback(new Error('Issuer in SAML response did not match expected issuer. Expected: \'' + self.options.expectedIssuer + '\' Got: \'' + issuer + '\''));
        }

        profile.issuer = issuer[0];
      }

      if (self.options.includeSessionIdInLogoutRequests) {
        var authnStatement = self.getElement(assertion[0], 'AuthnStatement');
        if (authnStatement && authnStatement[0] && authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
          profile.sessionIndex = authnStatement[0].$.SessionIndex;
        } else {
          return callback(new Error('Missing SessionIndex in AuthnStatement. This is required when the option includeSessionIdInLogoutRequests is enabled.'), null);
        }
      }

      var subject = self.getElement(assertion[0], 'Subject');
      if (subject) {
        var nameID = self.getElement(subject[0], 'NameID');
        if (nameID) {
          profile.nameID = nameID[0]._;
        }
      }

      var attributeStatement = self.getElement(assertion[0], 'AttributeStatement');
      if (!attributeStatement) {
        return callback(new Error('Missing AttributeStatement.'), null);
      }

      var attributes = self.getElement(attributeStatement[0], 'Attribute');

      profile.samlClaims = new Object();

      if (attributes) {
        attributes.forEach(function(attribute) {
          var value = self.getElement(attribute, 'AttributeValue');
          var name = attribute.$.Name;
          var value;
          if (typeof value[0] === 'string') {
            value = value[0];
          } else {
            value = value[0]._;
          }

          // always save this claim in samlClaims
          profile.samlClaims[name] = value;

          if (self.options.claimTranslations && self.options.claimTranslations[name]) {
            // translate the claim into the profile itself if it exists
            var translatedName = self.options.claimTranslations[name];
            profile[translatedName] = value;
          }

        });
      }

      callback(null, profile);
    } else {
      return callback(new Error('Missing Response.'), null);
    }


  });
};

exports.SAML = SAML;