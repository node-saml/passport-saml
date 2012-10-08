var passport = require('passport');
var util = require('util');
var saml = require('./saml');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  this.name = 'saml';

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;
  if (req.body && req.body.SAMLResponse) {
    // We have a response, get the user identity out of it
    var response = req.body.SAMLResponse;

    this._saml.validateAuthenticateResponse(req.session.expectedIssuer, response, function (err, profile) {
      if (err) {
        return self.error(err);
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      self._verify(profile, verified);
    });
  } else {
    // Initiate new SAML authentication request
    req.session.expectedIssuer = options.issuer;
    this._saml.getAuthorizeUrl(options.issuer, req, function (err, url) {
      if (err) {
        return self.fail();
      }

      if (self._saml.options.logging) {
        console.log('about to redirect to url: '+url);
      }
      self.redirect(url);
    });
  }
};

Strategy.prototype.logoutCallback = function(req, callback) {
  var self = this;
  if (req.body && req.body.SAMLResponse) { 
    this._saml.validateLogoutResponse(req.user.issuer, req.body.SAMLResponse, 'base64', false, callback);
  } else if (req.query && req.query.SAMLResponse) {
    this._saml.validateGETLogoutResponse(req, callback);
  } else {
    callback(new Error('Did not find SAML logout response.'))
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

module.exports = Strategy;
