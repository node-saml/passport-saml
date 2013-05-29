var passport = require('passport');
var util = require('util');
var Saml = require('./saml');

function Strategy(verify) {

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  var saml = new Saml.SAML(options);
  var self = this;
  if (req.body && req.body.SAMLResponse) {
    // We have a response, get the user identity out of it
    var response = req.body.SAMLResponse;

    saml.validateAuthenticateResponse(response, function(err, profile) {
      if (err) {
        return self.error(err);
      }

      var verified = function(err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      self._verify(options, profile, verified);
    });
  } else {
    // Initiate new SAML authentication request
    saml.getAuthorizeUrl(options.issuer, req, function(err, url) {
      if (err) {
        console.log(err);
        return self.fail();
      }

      if (saml.options.logging) {
        console.log('about to redirect to url: ' + url);
      }
      self.redirect(url);
    });
  }
};

// Strategy.prototype.logoutCallback = function(req, callback) {
//   saml = new saml.SAML(options);
//   var self = this;
//   if (req.body && req.body.SAMLResponse) { 
//     saml.validateLogoutResponse(req.user.issuer, req.body.SAMLResponse, 'base64', false, callback);
//   } else if (req.query && req.query.SAMLResponse) {
//     saml.validateGETLogoutResponse(req, callback);
//   } else {
//     callback(new Error('Did not find SAML logout response.'))
//   }
// };

// Strategy.prototype.logout = function(req, callback) {
//   this._saml.getLogoutUrl(req, callback);
// };

module.exports = Strategy;