var zlib = require('zlib');
var xml2js = require('xml2js');

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

  if (!options.identifierFormat) {
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
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours()+2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z"; 
};

SAML.prototype.generateRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  // Post-auth destination
  var callbackUrl = this.options.protocol + req.headers.host + this.options.path;

  var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant + "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n" +
    "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat + "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n" +
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";

  return request;
};

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var self = this;
  var request = this.generateRequest(req);
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64   = buffer.toString('base64');
    var encoded  = encodeURIComponent(base64);

    callback(null, self.options.entryPoint + '?SAMLRequest=' + encoded);
  });
};

SAML.prototype.validateResponse = function (samlResponse, callback) {
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');
  var parser = new xml2js.Parser();
  parser.parseString(xml, function (err, doc) {
    profile = {};
    profile.issuer = doc['saml:Assertion']['saml:Issuer'];

    var attributes = doc['saml:Assertion']['saml:AttributeStatement']['saml:Attribute'];
    attributes.forEach(function (attribute) {
      profile[attribute['@'].Name] = attribute['saml:AttributeValue']['#'];
    });

    if (!profile.email && profile.mail) {
      profile.email = profile.mail;
    }

    callback(null, profile);
  });
};

exports.SAML = SAML;
