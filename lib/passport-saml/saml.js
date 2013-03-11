var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');
var util = require('util');
var exec = require('child_process').exec;
var LocalStore = require('./localstore').LocalStore;

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

  if (!options.antiReplayStore) {
    options.antiReplayStore = LocalStore;
  }

  if (!options.isShibboleth) {
    options.isShibboleth = false;
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
  return signer.sign(this.keyToPEM(this.options.privateCert), 'base64');
};

SAML.prototype.generateAuthorizeRequest = function (req, callback) {
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
   "<samlp:AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
   "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" +
   this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat +
    "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }

  request +=
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
      "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>" +
    "</samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";

  // Store the ID in the anti-replay store.
  this.options.antiReplayStore.set(id, instant, function(err) {
    if (err) {
      return callback(err);
    }

    callback(null, request);
  });
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  //samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  // ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/"
  //IssueInstant="2008-06-03T12:59:57Z"><saml:Issuer>myhost</saml:Issuer><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  //NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe
  //</samlp:SessionIndex></samlp:LogoutRequest>

  var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "+
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\""+id+"\" Version=\"2.0\" IssueInstant=\""+instant+
    "\" Destination=\""+this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>"+
    "<saml:NameID Format=\""+req.user.nameIDFormat+"\">"+req.user.nameID+"</saml:NameID>"+
    "</samlp:LogoutRequest>";
  return request;
};

SAML.prototype.requestToUrl = function (request, operation, callback) {
  var self = this;
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = self.options.entryPoint + '?';

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = self.options.logoutUrl + '?';
      }
    }

    var samlRequest = {
      SAMLRequest: base64
    };

    if (self.options.privateCert) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }
    target += querystring.stringify(samlRequest);

    callback(null, target);
  });
};

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var self = this;
  var request = self.generateAuthorizeRequest(req, function(err, request) {
    if (err) {
      return callback(err);
    }

    self.requestToUrl(request, 'authorize', callback);
  });
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var request = this.generateLogoutRequest(req);

  this.requestToUrl(request, 'logout', callback);
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.keyToPEM = function (key) {
  key = key.match(/.{1,64}/g).join('\n');
  key = "-----BEGIN PRIVATE KEY-----\n" + key;
  key = key + "\n-----END PRIVATE KEY-----\n";
  return key;
};

SAML.prototype.validateSignature = function (xml, cert) {
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
  } else if (parentElement['saml2:'+elementName]) {
    return parentElement['saml2:'+elementName];
  } else if (parentElement['saml2p:'+elementName]) {
    return parentElement['saml2p:'+elementName];
  }
  return parentElement[elementName];
};

SAML.prototype.getXml = function(samlResponse, callback) {
  var self = this;

  /**
   * Tries to parse the passed in data to XML.
   *
   * @param  {String} data Base64 encoded XML.
   * @return {Object}      The root object.
   * @api private
   */
  var parseXml = function(data) {
    var xml = new Buffer(data, 'base64').toString('ascii');
    var parser = new xml2js.Parser({explicitRoot:true});
    parser.parseString(xml, function(err, doc) {
      if (err) {
        return callback(err);
      }
      callback(null, doc, xml);
    });
  };

  if (self.options.isShibboleth && self.options.converter) {
    // If we're dealing with Shibboleth,
    // some of the Assertion's will be encrypted.
    // Run it trough the Java converter.
    // The unencrypted data will be placed on standard out.
    var cmd = util.format('java -jar "%s" "%s" "%s" "%s" "%s" base64 base64', self.options.converter, self.options.cert, self.options.publicCert, self.options.privateCert, samlResponse);
    var child = exec(cmd, { 'timeout': 200000 }, function (err, stdout, stderr) {
      if (err) {
          return callback(new Error('Could not parse the SAMLResponse: ' + stderr));
      }

      parseXml(stdout);
    });
  } else {
    // Plain old OpenSAML.
    parseXml(samlResponse);
  }
};

SAML.prototype.validateResponse = function (samlResponse, callback) {
  var self = this;
  self.getXml(samlResponse, function(err, doc, xml) {
    if (err) {
      return callback(err);
    }

    // Verify signature
    // In case we're using shibboleth, the signature will be verified by the java utility.
    if (!self.options.isShibboleth && self.options.cert && !self.validateSignature(xml, self.options.cert)) {
      return callback(new Error('Invalid signature'), null, false);
    }

    var response = self.getElement(doc, 'Response');
    if (response) {

      // Perform anti-replay check.
      var inResponseToID = response['$']['InResponseTo'];
      self.options.antiReplayStore.get(inResponseToID, function(err, instant) {
        if (err) {
          return callback(err);
        }

        if (!instant) {
          // If no ID could be found, it means it was already removed from the store.
          // In that case, this is a replay attack.
          return callback(new Error('Replay attack.'));
        }

        // This is a valid message.
        // Delete the ID from the anti replay store so it can't be re-used.
        self.options.antiReplayStore.del(inResponseToID, function(err) {
          if (err) {
            return callback(err);
          }

          var assertion = self.getElement(response, 'Assertion');
          if (!assertion) {
            return callback(new Error('Missing SAML assertion'), null, false);
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

              if (nameID[0].$.Format) {
                profile.nameIDFormat = nameID[0].$.Format;
              }
            }
          }

          var attributeStatement = self.getElement(assertion[0], 'AttributeStatement');
          if (!attributeStatement) {
            return callback(new Error('Missing AttributeStatement'), null, false);
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

          callback(null, profile, false);
        });
      });
    } else {
      var logoutResponse = self.getElement(doc, 'LogoutResponse');

      if (logoutResponse){
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }

    }


  });
};

SAML.prototype.getShibbolethMetadata = function() {
  var metadata = [
  '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_957cf08a6730ac2e70ce094b8262cdf79ce25120" entityID="${entityID}">',
      '<md:Extensions xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport">',
        '<alg:SigningMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>',
      '</md:Extensions>',
      '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">',
        '<md:KeyDescriptor>',
          '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
            '<ds:KeyName>${publicCertSubjectName}</ds:KeyName>',
            '<ds:X509Data>',
              '<ds:X509SubjectName>CN=${publicCertSubjectName}</ds:X509SubjectName>',
              '<ds:X509Certificate>${publicCert}</ds:X509Certificate>',
            '</ds:X509Data>',
          '</ds:KeyInfo>',
          '<md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>',
        '</md:KeyDescriptor>',
        '<md:AssertionConsumerService Location="${callbackUrl}" index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" />',
      '</md:SPSSODescriptor>',
    '</md:EntityDescriptor>'
  ].join('\n');
  metadata = metadata.replace('${entityID}', this.options.issuer);
  metadata = metadata.replace('${publicCert}', this.options.publicCert);
  metadata = metadata.replace(/\$\{publicCertSubjectName\}/g, this.options.publicCertSubjectName);
  metadata = metadata.replace('${callbackUrl}', this.options.callbackUrl);
  return metadata;
};

exports.SAML = SAML;
