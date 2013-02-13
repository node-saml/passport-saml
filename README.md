Passport-SAML
=============

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for [Passport](http://passportjs.org/), the Node.js authentication library.

The code was originally based on Michael Bosworth's [express-saml](https://github.com/bozzltron/express-saml) library.

Passport-SAML has been tested to work with both [SimpleSAMLphp](http://simplesamlphp.org/) based Identity Providers, and with [Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Installation

    $ npm install passport-saml

## Usage

### Configure strategy

This example utilizes the [Feide OpenIdp identity provider](https://openidp.feide.no/). You need an account there to log in with this. You also need to [register your site](https://openidp.feide.no/simplesaml/module.php/metaedit/index.php) as a service provider.

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
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
));
```

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

## Security and signatures

Passport-SAML uses the HTTP Redirect Binding for its `AuthnRequest`s, and expects to receive the messages back via the HTTP POST binding.

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
    identifierFormat: null
  }
```

Please note that ADFS needs to have a trust established to your service in order for this to work.


## Usage with Shibboleth

Warning: Running with this configuration will *NOT* bring you on feature parity with the full-fledged Shibboleth SP and only supports the most basic SSO operations.

You will need to have a Java Runtime present as Java is used to parse incoming encrypted requests.

It assumes you use HTTP-REDIRECT to initiate the shib process with the IdP and expects an HTTP-POST as answer. This means you'll need 2 routes. One for the outgoing request and one for the incoming request, similar as the [OAuth passport routes](http://passportjs.org/guide/oauth/).

The following configuration has been tested with the [Test Shibboleth IdP](http://www.testshib.org).

```
{
// Wether we'll be talking to shibboleth
'isShibboleth': true,

// The URL where the IdP should redirect the user to.
'callbackUrl': 'https://oae.cam.ac.uk/api/auth/shibboleth/callback',

// The URL where we should redirect the user to.
'entryPoint': 'https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO',

// The entityID that we used to register our SP
'issuer': 'https://oae.cam.ac.uk/shibboleth',

// The public certificate of the TestShib IdP
// Find the full one at https://www.testshib.org/metadata/testshib-providers.xml
'cert': 'MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQ...nl+ev0peYzxFyF5sQA==',

// The path to the parser jar.
// The parser will be used to decrypt anything that the IdP sends us.
// See https://github.com/sakaiproject/SAMLParser
'converter': '/path/to/the/parser.jar',

// Your public certificate
'publicCert': 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==',

// The subject name you used in your certificate (CN)
'publicCertSubjectName': 'oae.cam.ac.uk',

// Your private certificate
'privateCert': 'MIvjVG3NaSG6 ... 32ea+',
'identifierFormat': null

// It would not be un-wise to pass in an implementation of the AntiReplayStore if you're
// running in a cluster as you might be vulnerable to replay attacks otherwise.
}
```

You will have to register your Node application as a SP with the Shibboleth IdP. This usually involves passing on an XML file that contains all the metadata for your SP. To facilitate this process, the SamlStrategy exposes a `getShibbolethMetadata` method which returns the XML as a string. You could add a third route which dumps this info.

```javascript
var samlStrategy = new SamlStrategy({ /* .. */ });
// ..
app.get('/shibboleth/metadata', function(req, res) {
    res.send(200, samlStrategy.getShibbolethMetadata());
});
```


## Anti Replay

To thwart anti-replay attacks, some state is kept to check if a returning opensaml response was initiated by us.

Warning: The default implementation uses local in-memory storage and will *NOT* work in a cluster.

The following is an implementation of the anti replay store that can be used in a cluster and can be passed in as an option to the strategy. It uses Redis as a canonical source to store data in. (This obviously assumes that all app nodes are connected to the same Redis instance.)

```
'antiReplayStore': {
    // callback is of the form callback(error, value);
    'get': function(id, callback) {
        var key = util.format('shibboleth:%s', id);
        Redis.getClient().get(key, callback);
    },

    // callback is of the form callback(error);
    'set': function(id, data, callback) {
        var key = util.format('shibboleth:%s', id);
        Redis.getClient().setex(key, 5 * 60, data, callback);
    },

    // callback is of the form callback(error);
    'del': function(id, callback) {
        var key = util.format('shibboleth:%s', id);
        Redis.getClient().del(key, callback);
    }
}
```