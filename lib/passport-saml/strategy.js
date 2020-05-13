const passport = require('passport-strategy');
const util = require('util');
const saml = require('./saml');
const url = require('url');

class Strategy extends passport.Strategy {
  constructor(options, verify) {
    super();

    if (typeof options == 'function') {
      verify = options;
      options = {};
    }

    if (!verify) {
      throw new Error('SAML authentication strategy requires a verify function');
    }

    // Customizing the name can be useful to support multiple SAML configurations at the same time.
    // Unlike other options, this one gets deleted instead of passed along.
    if  (options.name) {
      this.name  = options.name;
    }
    else {
      this.name = 'saml';
    }

    this._verify = verify;
    this._saml = new saml.SAML(options);
    this._passReqToCallback = !!options.passReqToCallback;
    this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
  }

  authenticate(req, options) {
    const self = this;

    options.samlFallback = options.samlFallback || 'login-request';

    function validateCallback(err, profile, loggedOut) {
        if (err) {
          return self.error(err);
        }

        if (loggedOut) {
          req.logout();
          if (profile) {
            req.samlLogoutRequest = profile;
            return self._saml.getLogoutResponseUrl(req, options, redirectIfSuccess);
          }
          return self.pass();
        }

        const verified = (err, user, info) => {
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

    if (req.query && (req.query.SAMLResponse || req.query.SAMLRequest)) {
      const originalQuery = url.parse(req.url).query;
      this._saml.validateRedirect(req.query, originalQuery, validateCallback);
    } else if (req.body && req.body.SAMLResponse) {
      this._saml.validatePostResponse(req.body, validateCallback);
    } else if (req.body && req.body.SAMLRequest) {
      this._saml.validatePostRequest(req.body, validateCallback);
    } else {
      const requestHandler = {
        'login-request': function() {
          if (self._authnRequestBinding === 'HTTP-POST') {
            this._saml.getAuthorizeForm(req, (err, data) => {
              if (err) {
                self.error(err);
              } else {
                const res = req.res;
                res.send(data);
              }
            });
          } else { // Defaults to HTTP-Redirect
            this._saml.getAuthorizeUrl(req, options, redirectIfSuccess);
          }
        }.bind(self),
        'logout-request': function() {
            this._saml.getLogoutUrl(req, options, redirectIfSuccess);
        }.bind(self)
      }[options.samlFallback];

      if (typeof requestHandler !== 'function') {
        return self.fail();
      }

      requestHandler();
    }
  }

  logout(req, callback) {
    this._saml.getLogoutUrl(req, {}, callback);
  }

  generateServiceProviderMetadata(decryptionCert, signingCert) {
    return this._saml.generateServiceProviderMetadata( decryptionCert, signingCert );
  }
}

module.exports = Strategy;
