
const passport = require('passport-strategy')
const util = require('util')
const saml = require('./saml')

class Strategy {
  
  constructor(options, verify) {
    if (typeof options == 'function') {
      verify = options
      options = {}
    }

    if (!verify) {
      throw new Error('SAML authentication strategy requires a verify function')
    }

    this.name = 'saml'

    passport.Strategy.call(this)

    this._verify = verify
    this._saml = new saml.SAML(options)
    this._passReqToCallback = !!options.passReqToCallback
    this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect'
  }

  authenticate(req, options) {
    let self = this

    options.samlFallback = (options.samlFallback || 'login-request')

    const validateCallback = (err, profile, loggedOut) => {
        if (err) {
          return self.error(err)
        }

        if (loggedOut) {
          req.logout()

          if (profile) {
            req.samlLogoutRequest = profile
            return self._saml.getLogoutResponseUrl(req, redirectIfSuccess)
          }
          return self.pass()
        }

        const verified = (err, user, info) => {
          if (err) {
            return self.error(err)
          }

          if (!user) {
            return self.fail(info)
          }

          self.success(user, info)
        }

        if (self._passReqToCallback) {
          self._verify(req, profile, verified)
          return
        }

        self._verify(profile, verified)
    }

    const redirectIfSuccess = (err, url) => {
      if (err) {
        self.error(err)
        return
      }

      self.redirect(url)
    }

    if (req.body && req.body.SAMLResponse) {
      this._saml.validatePostResponse(req.body, validateCallback)
      return
    }

    if (req.body && req.body.SAMLRequest) {
      this._saml.validatePostRequest(req.body, validateCallback)
      return
    }

    const requestHandler = {
      'login-request': function() {
        if (self._authnRequestBinding === 'HTTP-POST') {
          self._saml.getAuthorizeForm(req, (err, data) => {
            if (err) {
              self.error(err)
            } else {
              req.res.send(data)
            }
          })
        } else { // Defaults to HTTP-Redirect
          self._saml.getAuthorizeUrl(req, redirectIfSuccess)
        }
      },
      'logout-request': function() {
        self._saml.getLogoutUrl(req, redirectIfSuccess)
      }
    }[options.samlFallback]

    if (typeof requestHandler !== 'function') {
      return self.fail()
    }

    requestHandler()
  }

  logout(req, callback) {
    this._saml.getLogoutUrl(req, callback)
  }

  generateServiceProviderMetadata(decryptionCert) {
    return this._saml.generateServiceProviderMetadata(decryptionCert)
  }

}

util.inherits(Strategy, passport.Strategy)

module.exports = Strategy
