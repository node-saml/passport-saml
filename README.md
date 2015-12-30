Passport-SAML
=============

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for [Passport](http://passportjs.org/), the Node.js authentication library.

The code was originally based on Michael Bosworth's [express-saml](https://github.com/bozzltron/express-saml) library.

Passport-SAML has been tested to work with Onelogin, Okta, Shibboleth, [SimpleSAMLphp](http://simplesamlphp.org/) based Identity Providers, and with [Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Installation

    $ npm install passport-saml

## Usage

### Configure strategy

This example utilizes the [Feide OpenIdp identity provider](https://openidp.feide.no/). You need an account there to log in with this. You also need to [register your site](https://openidp.feide.no/simplesaml/module.php/metaedit/index.php) as a service provider.

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
var SamlStrategy = require('passport-saml').Strategy;
[...]

passport.use(new SamlStrategy(
  {
    path: '/login/callback',
    entryPoint: 'https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php',
    issuer: 'passport-saml'
  },
  function(profile, done) {
    findByEmail(profile.email, function(err, user) {
      if (err) {
        return done(err);
      }
      return done(null, user);
    });
  })
);
```

Config parameter details:
* Core
 * `callbackUrl`: full callbackUrl (overrides path/protocol if supplied)
 * `path`: path to callback; will be combined with protocol and server host information to construct callback url if `callbackUrl` is not specified (default: `/saml/consume`)
 * `protocol`: protocol for callback; will be combined with path and server host information to construct callback url if `callbackUrl` is not specified (default: `http://`)
 * `host`: host for callback; will be combined with path and protocol to construct callback url if `callbackUrl` is not specified (default: `localhost`)
 * `entryPoint`: identity provider entrypoint
 * `issuer`: issuer string to supply to identity provider
 * `cert`: see 'security and signatures'
 * `privateCert`: see 'security and signatures'
 * `decryptionPvk`: optional private key that will be used to attempt to decrypt any encrypted assertions that are received
 * `signatureAlgorithm`: optionally set the signature algorithm for signing requests, valid values are 'sha1' (default) or 'sha256'
* Additional SAML behaviors
 * `additionalParams`: dictionary of additional query params to add to all requests
 * `additionalAuthorizeParams`: dictionary of additional query params to add to 'authorize' requests
 * `identifierFormat`: if truthy, name identifier format to request from identity provider (default: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`)
 * `acceptedClockSkewMs`: Time in milliseconds of skew that is acceptable between client and server when checking `OnBefore` and `NotOnOrAfter` assertion condition validity timestamps.  Setting to `-1` will disable checking these conditions entirely.  Default is `0`.
 * `attributeConsumingServiceIndex`: optional `AttributeConsumingServiceIndex` attribute to add to AuthnRequest to instruct the IDP which attribute set to attach to the response ([link](http://blog.aniljohn.com/2014/01/data-minimization-front-channel-saml-attribute-requests.html))
 * `disableRequestedAuthnContext`: if truthy, do not request a specific auth context
 * `authnContext`: if truthy, name identifier format to request auth context (default: `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`)
 * `forceAuthn`: if set to true, the initial SAML request from the service provider specifies that the IdP should force re-authentication of the user, even if they possess a valid session.
 * `skipRequestCompression`: if set to true, the SAML request from the service provider won't be compressed.
 * `authnRequestBinding`: if set to `HTTP-POST`, will request authentication from IDP via HTTP POST binding, otherwise defaults to HTTP Redirect
* InResponseTo Validation
 * `validateInResponseTo`: if truthy, then InResponseTo will be validated from incoming SAML responses
 * `requestIdExpirationPeriodMs`: Defines the expiration time when a Request ID generated for a SAML request will not be valid if seen in a SAML response in the `InResponseTo` field.  Default is 8 hours.
 * `cacheProvider`: Defines the implementation for a cache provider used to store request Ids generated in SAML requests as part of `InResponseTo` validation.  Default is a built-in in-memory cache provider.  For details see the 'Cache Provider' section.
* Passport
 * `passReqToCallback`: if truthy, `req` will be passed as the first argument to the verify callback (default: `false`)
* Logout
 * `logoutUrl`: base address to call with logout requests (default: `entryPoint`)
 * `additionalLogoutParams`: dictionary of additional query params to add to 'logout' requests
 * `logoutCallbackUrl`: The value with which to populate the `Location` attribute in the `SingleLogoutService` elements in the generated service provider metadata.

### Provide the authentication callback

You need to provide a route corresponding to the `path` configuration parameter given to the strategy:

```javascript
app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);
```

### Authenticate requests

Use `passport.authenticate()`, specifying `saml` as the strategy:

```javascript
app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);
```

### generateServiceProviderMetadata( decryptionCert )

As a convenience, the strategy object exposes a `generateServiceProviderMetadata` method which will generate a service provider metadata document suitable for supplying to an identity provider.  This method will only work on strategies which are configured with a `callbackUrl` (since the relative path for the callback is not sufficient information to generate a complete metadata document).

The `decryptionCert` argument should be a certificate matching the `decryptionPvk` and is required if the strategy is configured with a `decryptionPvk`.


## Security and signatures

Passport-SAML uses the HTTP Redirect Binding for its `AuthnRequest`s (unless overridden with the `authnRequestBinding` parameter), and expects to receive the messages back via the HTTP POST binding.

Authentication requests sent by Passport-SAML can be signed using RSA-SHA1. To sign them you need to provide a private key in the PEM format via the `privateCert` configuration key. For example:

```javascript
    privateCert: fs.readFileSync('./cert.pem', 'utf-8')
```

It is a good idea to validate the incoming SAML Responses. For this, you can provide the Identity Provider's certificate using the `cert` confguration key:

```javascript
    cert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W=='
```

## Usage with Active Directory Federation Services

Here is a configuration that has been proven to work with ADFS:

```javascript
  {
    entryPoint: 'https://ad.example.net/adfs/ls/',
    issuer: 'https://your-app.example.net/login/callback',
    callbackUrl: 'https://your-app.example.net/login/callback',
    cert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==',
    authnContext: 'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows',
    identifierFormat: null
  }
```

Please note that ADFS needs to have a trust established to your service in order for this to work.

For more detailed instructions, see [this document from Tim Brody](docs/adfs/README.md).

## SAML Response Validation - NotBefore and NotOnOrAfter

If the `NotBefore` or the `NotOnOrAfter` attributes are returned in the SAML response, Passport-SAML will validate them
against the current time +/- a configurable clock skew value.  The default for the skew is 0s.  This is to account for
differences between the clock time on the client (Node server with Passport-SAML) and the server (Identity provider).

`NotBefore` and `NotOnOrAfter` can be part of either the `SubjectConfirmation` element, or within in the `Assertion/Conditions` element
in the SAML response.

## Subject confirmation validation

When configured (turn `validateInResponseTo` to `true` in the Passport-SAML config), the `InResponseTo` attribute will be validated.
Validation will succeed if Passport-SAML previously generated a SAML request with an id that matches the value of `InResponseTo`.

Also note that `InResponseTo` is validated as an attribute of the top level `Response` element in the SAML response, as well
as part of the `SubjectConfirmation` element.

Previous request id's generated for SAML requests will eventually expire.  This is controlled with the `requestIdExpirationPeriodMs` option
passed into the Passport-SAML config.  The default is 28,800,000 ms (8 hours).  Once expired, a subsequent SAML response
received with an `InResponseTo` equal to the expired id will not validate and an error will be returned.

## Cache Provider

When `InResponseTo` validation is turned on, Passport-SAML will store generated request ids used in SAML requests to the IdP.  The implementation
of how things are stored, checked to see if they exist, and eventually removed is from the Cache Provider used by Passport-SAML.

The default implementation is a simple in-memory cache provider.  For multiple server/process scenarios, this will not be sufficient as
the server/process that generated the request id and stored in memory could be different than the server/process handling the
SAML response.  The `InResponseTo` could fail in this case erroneously.

To support this scenario you can provide an implementation for a cache provider by providing an object with following functions:

```javascript
{
    save: function(key, value, callback) {
      // save the key with the optional value, invokes the callback with the value saves
    },
    get: function(key, callback) {
      // invokes 'callback' and passes the value if found, null otherwise
    },
    remove: function(key, callback) {
      // removes the key from the cache, invokes `callback` with the
      // key removed, null if no key is removed
    }
}
```

The `callback` argument is a function in the style of normal Node callbacks:
```
function callback(err, result)
{

}
```

Provide an instance of an object which has these functions passed to the `cacheProvider` config option when using Passport-SAML.

## FAQ

### What if I have multiple SAML providers that my users may be connecting to?

A single instance of passport-saml will only authenticate users against a single identity provider.  If you have a use case where different logins need to be routed to different identity providers, you can create multiple instances of passport-saml, and either dispatch to them with your own routing code, or use a library like https://www.npmjs.org/package/passports.

### Is there an example I can look at?

Gerard Braad has provided an example app at https://github.com/gbraad/passport-saml-example/
