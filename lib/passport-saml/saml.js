var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var SAML = function (options) {
  this.options = this.initialize(options);
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
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

SAML.prototype.generateAuthorizeRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();
  var callbackUrl;

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    callbackUrl = this.options.protocol + req.headers.host + this.options.path;
  }

  var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant + 
   "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" + 
   this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.includeIdentifierFormatInRequests && this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat + 
    "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }
   
  request += 
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";

  if (this.options.logging) { 
    console.log("about to send authorize request: "+request);
  }
  return request;
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  //samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  // ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/" 
  //IssueInstant="2008-06-03T12:59:57Z"><saml:Issuer>myhost</saml:Issuer><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" 
  //NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe
  //</samlp:SessionIndex></samlp:LogoutRequest>

  var logoutEntryPoint = this.options.entryPoint;

  if (this.options.logoutEntryPoint) {
    logoutEntryPoint = this.options.logoutEntryPoint;
  }

  var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "+
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
    "\" Destination=\"" + logoutEntryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>" +
    "<saml:NameID Format=\"" + this.options.identifierFormat + "\">" + req.user.nameID + "</saml:NameID>"+
    "</samlp:LogoutRequest>";
  
  if (this.options.logging) { 
    console.log("about to send logout request: "+request);
  }

  return request;
};

SAML.prototype.requestToUrl = function (request, target, callback) {
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
    target += "?"+querystring.stringify(samlRequest);

    callback(null, target);
  });
};

SAML.prototype.validateSignature = function(samlResponse, signature, cert) {
  var verifier = crypto.createVerify('RSA-SHA1');
  var request = {
    SAMLResponse: samlResponse
  };
  verifier.update(querystring.stringify(request));
  console.log("signature: "+signature);
  return verifier.verify(this.certToPEM(cert), signature, 'base64');
};

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest(req);
  
  this.requestToUrl(request, this.options.entryPoint, callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var request = this.generateLogoutRequest(req);

  var target = this.options.entryPoint;

  if (this.options.logoutEntryPoint) {
    target = this.options.logoutEntryPoint;
  }

  this.requestToUrl(request, target, callback);
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateXmlSignature = function (xml, cert) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath.SelectNodes(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:'+elementName]) {
    return parentElement['samlp:'+elementName];
  } 
  return parentElement[elementName];
};


SAML.prototype.validateGETLogoutResponse = function(samlResponse, signature, sigAlg, callback) {
  var self = this;
  
  if (self.options.cert) {
    if (signature && sigAlg){
      if (sigAlg !== 'http://www.w3.org/2000/09/xmldsig#rsa-sha1') {
        return callback(new Error('Invalid sigAlg, expected \"http://www.w3.org/2000/09/xmldsig#rsa-sha1\", got \"'+sigAlg+'\".'));
      }
        
      if (!self.validateSignature(samlResponse, signature, self.options.cert)) {
        return callback(new Error('Invalid signature on logout request.'));
      }
    } else {
      return callback(new Error('Expected logout response to be signed but it was not.'));
    }
  }

  zlib.inflateRaw(samlResponse, function(err, buffer) {
    if (err) {
      return callback(err);
    }
    self.validateLogoutResponse(buffer.toString('base64'), true, callback);
  });


}

SAML.prototype.validateLogoutResponse = function(samlResponse, signatureValidated, callback) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');

  if (self.options.logging) {
    console.log("Got logout response: "+xml);
  }

  var parser = new xml2js.Parser();
  parser.parseString(xml, function (err, doc) {
    
    if (self.options.cert && !signatureValidated) {
      if (signature && sigAlg) {
        // validate samlResponse using supplied signature and sigAlg
        
      } else {
        // validate XML signature in a POSTed response
        if (!self.validateXmlSignature(xml, self.options.cert)) {
          return callback(new Error('Invalid xml signature on logout request'));
        }
      }
    }

    var logoutResponse = self.getElement(doc, 'LogoutResponse');

    if (logoutResponse){
      callback(null);
    } else {
      callback(new Error('LogoutResponse not found.'));
    }
  });
}

// this only supports POSTs
SAML.prototype.validateAuthenticateResponse = function (samlResponse, callback) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');
  
  if (self.options.logging) {
    console.log("Got authenticate response: "+xml);
  }

  var parser = new xml2js.Parser();
  parser.parseString(xml, function (err, doc) {
    // Verify signature
    if (self.options.cert && !self.validateXmlSignature(xml, self.options.cert)) {
      return callback(new Error('Invalid signature'), null);
    }

    var response = self.getElement(doc, 'Response');
    if (response) {
      var assertion = self.getElement(response, 'Assertion');
      if (!assertion) {
        return callback(new Error('Missing SAML assertion'), null);
      }

      profile = {};
      var issuer = self.getElement(assertion[0], 'Issuer');
      if (issuer) {
        profile.issuer = issuer[0];
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
        return callback(new Error('Missing AttributeStatement'), null);
      }

      var attributes = self.getElement(attributeStatement[0], 'Attribute');

      if (attributes) {
        attributes.forEach(function (attribute) {
          var value = self.getElement(attribute, 'AttributeValue');
          if (typeof value[0] === 'string') {
            profile[attribute.$.Name] = value[0];
          } else {
            profile[attribute.$.Name] = value[0]._;
          }
        });
      }
        

      if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
        // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
        profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
      }

      if (!profile.email && profile.mail) {
        profile.email = profile.mail;
      }

      callback(null, profile);
    } else {
        return callback(new Error('Unknown SAML response message'), null);
    }


  });
};

exports.SAML = SAML;
