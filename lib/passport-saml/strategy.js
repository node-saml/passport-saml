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

  if (typeof options.createProvider === "function") {
    // This will get called when the request authenticates
    // And the SAML Provider will be defined at this time, for each request
    this._createProvider = options.createProvider;
  } else {

    // if no provider to create just initialize the options that were sent.
    const provider = new saml.SAML(options);

    this._createProvider = function(req, cb) { cb(null, provider) };

  }
  this._verify = verify;
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

  self._createProvider(req, function(err, provider) {
    // Handle error
    if (err) {
      // Non standard string error
      if (typeof err === "string") {
        // Fail the strategy with the error message
        return self.fail(err);
      } else {
        // Error the strategy with the error object
        return self.error(err);
      }
    }

    self._saml = provider;

    if (req.body && req.body.SAMLResponse) {
        provider.validatePostResponse(req.body, validateCallback);
    } else if (req.body && req.body.SAMLRequest) {
        provider.validatePostRequest(req.body, validateCallback);
    } else {
      var requestHandler = {
        'login-request': function() {
          if (self._authnRequestBinding === 'HTTP-POST') {
            provider.getAuthorizeForm(req, function(err, data) {
              if (err) {
                self.error(err);
              } else {
                var res = req.res;
                res.send(data);
              }
            });
          } else { // Defaults to HTTP-Redirect
            provider.getAuthorizeUrl(req, redirectIfSuccess);
          }
        }.bind(self),
        'logout-request': function() {
            provider.getLogoutUrl(req, redirectIfSuccess);
        }.bind(self)
      }[options.samlFallback];

      if (typeof requestHandler !== 'function') {
        return self.fail();
      }

      requestHandler();
    }
  });
};

Strategy.prototype.logout = function(req, callback) {
  provider.getLogoutUrl(req, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert ) {
  return provider.generateServiceProviderMetadata( decryptionCert );
};

module.exports = Strategy;
