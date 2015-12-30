var passport = require('passport-strategy');
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
  this._passReqToCallback = !!options.passReqToCallback;
  this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  options.samlFallback = options.samlFallback || 'login-request';

  function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return self._saml.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();
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

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
  }

  function redirectIfSuccess(err, url) {
    if (err) {
      self.error(err);
    } else {
      self.redirect(url);
    }
  }

  if (req.body && req.body.SAMLResponse) {
      this._saml.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
      this._saml.validatePostRequest(req.body, validateCallback);
  } else {
    var requestHandler = {
      'login-request': function() {
        if (self._authnRequestBinding === 'HTTP-POST') {
          this._saml.getAuthorizeForm(req, function(err, data) {
            if (err) {
              self.error(err);
            } else {
              var res = req.res;
              res.send(data);
            }
          });
        } else { // Defaults to HTTP-Redirect
          this._saml.getAuthorizeUrl(req, redirectIfSuccess);
        }
      }.bind(self),
      'logout-request': function() {
          this._saml.getLogoutUrl(req, redirectIfSuccess);
      }.bind(self)
    }[options.samlFallback];

    if (typeof requestHandler !== 'function') {
      return self.fail();
    }

    requestHandler();
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert ) {
  return this._saml.generateServiceProviderMetadata( decryptionCert );
};

module.exports = Strategy;
