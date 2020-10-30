import * as passport from 'passport-strategy';
import * as util from 'util';
import * as saml from './saml';
import * as url from 'url';
import { AuthenticateOptions, AuthorizeOptions, SamlConfig, VerifyWithoutRequest, VerifyWithRequest } from './types';
import type { Request } from 'express';
import { Profile } from './types';

interface SAMLRequest extends Request {
  samlLogoutRequest?: Profile
}

function Strategy (options: SamlConfig, verify: VerifyWithRequest | VerifyWithoutRequest) {
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

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
  this._passReqToCallback = !!options.passReqToCallback;
  this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req: SAMLRequest, options: AuthenticateOptions & AuthorizeOptions): void {

  options.samlFallback = options.samlFallback || 'login-request';

  const validateCallback = (err, profile: Profile, loggedOut) => {
      if (err) {
        return this.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return this._saml.getLogoutResponseUrl(req, options, redirectIfSuccess);
        }
        return this.pass();
      }

      const verified = (err, user, info) => {
        if (err) {
          return this.error(err);
        }

        if (!user) {
          return this.fail(info);
        }

        this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, profile, verified);
      } else {
        this._verify(profile, verified);
      }
  };

  const redirectIfSuccess = (err: Error | null, url: string | null) => {
    if (err) {
      this.error(err);
    } else {
      this.redirect(url);
    }
  };

  if (req.query && (req.query.SAMLResponse || req.query.SAMLRequest)) {
    const originalQuery = url.parse(req.url).query;
    this._saml.validateRedirect(req.query, originalQuery, validateCallback);
  } else if (req.body && req.body.SAMLResponse) {
    this._saml.validatePostResponse(req.body, validateCallback);
  } else if (req.body && req.body.SAMLRequest) {
    this._saml.validatePostRequest(req.body, validateCallback);
  } else {
    const requestHandler = {
      'login-request': () => {
        if (this._authnRequestBinding === 'HTTP-POST') {
          this._saml.getAuthorizeForm(req, (err, data) => {
            if (err) {
              this.error(err);
            } else {
              const res = req.res;
              res.send(data);
            }
          });
        } else { // Defaults to HTTP-Redirect
          this._saml.getAuthorizeUrl(req, options, redirectIfSuccess);
        }
      },
      'logout-request': () => {
          this._saml.getLogoutUrl(req, options, redirectIfSuccess);
      }
    }[options.samlFallback];

    if (typeof requestHandler !== 'function') {
      return this.fail();
    }

    requestHandler();
  }
};

Strategy.prototype.logout = function(req: SAMLRequest, callback: (err: Error | null, url?: string) => void): void {
  this._saml.getLogoutUrl(req, {}, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert: string | null, signingCert?: string | null ): string {
  return this._saml.generateServiceProviderMetadata( decryptionCert, signingCert );
};

export = Strategy as any;
