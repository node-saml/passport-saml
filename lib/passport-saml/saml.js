var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');
var xmlbuilder = require('xmlbuilder');

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
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
};

SAML.prototype.generateAuthorizeRequest = function (req, isPassive) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();
  var callbackUrl;

  // Post-auth destination
  if (this.options.callbackUrl) {
    callbackUrl = this.options.callbackUrl;
  } else {
    callbackUrl = this.options.protocol + req.headers.host + this.options.path;
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

//    <samlp:LogoutResponse ID="_f0961a83-d071-4be5-a18c-9ae7b22987a4" Version="2.0" IssueInstant="2013-03-18T08:49:24.405Z" InResponseTo="iddce91f96e56747b5ace6d2e2aa9d4f8c" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
//        <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/82869000-6ad1-48f0-8171-272ed18796e9/</Issuer>
//        <samlp:Status>
//            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
//        </samlp:Status>
//    </samlp:LogoutResponse>

  // var request = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "+
  //   "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\""+id+"\" Version=\"2.0\" IssueInstant=\""+instant+
  //   "\" InResponseTo=\""+logoutRequest.ID + "\">" +
  //   "<saml:Issuer>" + this.options.issuer + "</saml:Issuer>"+
  //   "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status>"+
  //   "</samlp:LogoutResponse>";
  // return request;

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

SAML.prototype.validateSignature = function (xml, cert, signature) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  if (signature === "") { return true; }
  signature = signature || xmlCrypto.xpath(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0].toString();
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
  return sig.checkSignature(xml);
};

SAML.prototype.validatePostResponse = function (container, callback) {
  var xml = new Buffer(container.SAMLResponse, 'base64').toString('ascii');
  return this.validateXML(xml, null, validateResponse, callback);
};

SAML.prototype.validatePostRequest = function (container, callback) {
  var xml = new Buffer(container.SAMLRequest, 'base64').toString('ascii');
  return this.validateXML(xml, null, validateRequest, callback);
};

SAML.prototype.validateRedirectResponse = function (container, callback) {
  var data = new Buffer(container.SAMLResponse, "base64");
  var signature = null; //new Buffer(container.Signature, 'base64').toString('ascii');
  this.validateRedirect(data, signature, validateResponse, callback);
};

SAML.prototype.validateRedirectRequest = function (container, callback) {
  var data = new Buffer(container.SAMLRequest, "base64");
  var signature = null; //new Buffer(container.Signature, 'base64').toString('ascii');
  this.validateRedirect(data, signature, validateRequest, callback);
};

SAML.prototype.validateRedirect = function(data, signature, validate, callback) {
  var self = this;
  // TODO verify redirect

  zlib.inflateRaw(data, function(err, inflated) {
    if (err) {
      return callback(err);
    }

    self.validateXML(inflated.toString("utf8"), "", validate, callback);
  });
};

SAML.prototype.validateXML = function (xml, signature, validate, callback) {
  var self = this;
  var parserConfig = {
    explicitRoot: true,
    tagNameProcessors: [xml2js.processors.stripPrefix]
  };
  var parser = new xml2js.Parser(parserConfig);
  parser.parseString(xml, function (err, doc) {
    if (err) {
      return callback(err, null, false);
    }

    // Verify signature
    if (self.options.cert && !self.validateSignature(xml, self.options.cert, signature)) {
      return callback(new Error('Invalid signature'), null, false);
    }

    validate(self, doc, callback);
  });
};

function validateResponse(self, doc, callback) {
    var response = doc['Response'];
    if (response) {
      var assertion = response['Assertion'];
      if (!assertion) {
        var status = response['Status'];
        if (status) {
          status = status[0]['StatusCode'];
          if (status && status[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder") {
            status = status[0]['StatusCode'];
            if (status && status[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive") {
              return callback(null, null, false);
            }
          }
        }
        return callback(new Error('Missing SAML assertion'), null, false);
      }

      var profile = {};
      var issuer = assertion[0]['Issuer'];
      if (issuer) {
        profile.issuer = issuer[0];
      }

      var subject = assertion[0]['Subject'];
      if (subject) {
        var nameID = subject[0]['NameID'];
        if (nameID) {
            profile.nameID = nameID[0]._;

          if (nameID[0].$.Format) {
            profile.nameIDFormat = nameID[0].$.Format;
          }
        }
      }

      var attributeStatement = assertion[0]['AttributeStatement'];
      if (attributeStatement) {
        var attributes = attributeStatement[0]['Attribute'];

        var attrValueMapper = function(value) {
          return typeof value === 'string' ? value : value._;
        };

        if (attributes) {
          attributes.forEach(function (attribute) {
            var value = attribute['AttributeValue'];
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

      callback(null, profile, false);
    } else {
      var logoutResponse = doc['LogoutResponse'];

      if (logoutResponse){
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }

    }
}

function validateRequest(self, doc, callback) {
    var request = doc['LogoutRequest'];
    if (request) {
      var profile = {};
      if (request.$.ID) {
          profile.ID = request.$.ID;
      } else {
        return callback(new Error('Missing SAML LogoutRequest ID'), null, false);
      }
      var issuer = request['Issuer'];
      if (issuer) {
        profile.issuer = issuer[0];
      } else {
        return callback(new Error('Missing SAML issuer'), null, false);
      }

      var nameID = request['NameID'];
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

exports.SAML = SAML;
