# Passport-SAML

[![Build Status](https://github.com/node-saml/passport-saml/workflows/Build%20Status/badge.svg)](https://github.com/node-saml/passport-saml/actions?query=workflow%3ABuild%Status)
[![npm version](https://badge.fury.io/js/@node-saml%2Fpassport-saml.svg)](https://badge.fury.io/js/@node-saml%2Fpassport-saml)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)
[![codecov](https://codecov.io/gh/node-saml/passport-saml/branch/master/graph/badge.svg?token=2JJrPZN29A)](https://codecov.io/gh/node-saml/passport-saml)
[![DeepScan grade](https://deepscan.io/api/teams/17569/projects/20921/branches/586237/badge/grade.svg)](https://deepscan.io/dashboard#view=project&tid=17569&pid=20921&bid=586237)

[![NPM](https://nodei.co/npm/@node-saml/passport-saml.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/@node-saml/passport-saml)

This is a [SAML 2.0](http://en.wikipedia.org/wiki/SAML_2.0) authentication provider for
[Passport](http://passportjs.org/), the Node.js authentication library.

Passport-SAML has been tested to work with Onelogin, Okta, Shibboleth,
[SimpleSAMLphp](http://simplesamlphp.org/) based Identity Providers, and with
[Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Sponsors

We gratefully acknowledge support from our sponsors:

<div align="center">
  <a href="https://stytch.com">
    <picture>
      <source width="200px" media="(prefers-color-scheme: dark)" srcset="./sponsor/stytch-light.svg">
      <source width="200px" media="(prefers-color-scheme: light)" srcset="./sponsor/stytch-dark.svg">
      <img width="200px" src="./sponsor/stytch-dark.svg" />
    </picture>
  </a>
   <p align="center">
      <a href="https://stytch.com/?utm_source=oss-sponsorship&utm_medium=paid_sponsorship&utm_campaign=passportsaml">
        <b>The identity platform for humans & AI agents</b><br/>
        One integration for authentication, authorization, and security
      </a>
   </p>
</div>

## Installation

```shell
npm install @node-saml/passport-saml
```

## Usage

The examples utilize the [Feide OpenIdp identity provider](https://openidp.feide.no/). You need an
account there to log in with this. You also need to
[register your site](https://openidp.feide.no/simplesaml/module.php/metaedit/index.php) as a service
provider.

### Configure strategy

Most of the configuration options for the Strategy constructor are passed through to the
underlying `node-saml` library. For more details on the configuration options and how the underlying
SAML flows work, see the
[node-saml documentation](https://github.com/node-saml/node-saml/blob/master/README.md)

#### Config parameter details

These are the Strategy parameters related directly to `passport-saml`. For the full list
of parameters, see the [node-saml documentation](https://github.com/node-saml/node-saml/blob/master/README.md)

- `additionalParams`: dictionary of additional query params to add to all requests; if an object
  with this key is passed to `authenticate`, the dictionary of additional query params will be
  appended to those present on the returned URL, overriding any specified by initialization options'
  additional parameters (`additionalParams`, `additionalAuthorizeParams`, and
  `additionalLogoutParams`)
- `passReqToCallback`: if truthy, `req` will be passed as the first argument to the verify callback
  (default: `false`)
- `name`: Optionally, provide a custom name. (default: `saml`). Useful If you want to instantiate
  the strategy multiple times with different configurations, allowing users to authenticate against
  multiple different SAML targets from the same site. You'll need to use a unique set of URLs for
  each target, and use this custom name when calling `passport.authenticate()` as well.

#### Examples

The SAML identity provider will redirect you to the URL provided by the `path` configuration.

```javascript
const SamlStrategy = require('@node-saml/passport-saml').Strategy;
[...]

passport.use(
  new SamlStrategy(
    {
      callbackURL: "/login/callback",
      entryPoint:
        "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php",
      issuer: "passport-saml",
      idpCert: "fake cert", // cert must be provided
    },
    function (profile, done) {
      // for signon
      findByEmail(profile.email, function (err, user) {
        if (err) {
          return done(err);
        }
        return done(null, user);
      });
    },
    function (profile, done) {
      // for logout
      findByNameID(profile.nameID, function (err, user) {
        if (err) {
          return done(err);
        }
        return done(null, user);
      });
    }
  )
);
```

### Configure strategy for multiple providers

You can pass a `getSamlOptions` parameter to `MultiSamlStrategy` which will be called before the
SAML flows. Passport-SAML will pass in the request object so you can decide which configuration is
appropriate.

```javascript
const { MultiSamlStrategy } = require('@node-saml/passport-saml');
[...]

passport.use(
  new MultiSamlStrategy(
    {
      passReqToCallback: true, // makes req available in callback
      getSamlOptions: function (request, done) {
        findProvider(request, function (err, provider) {
          if (err) {
            return done(err);
          }
          return done(null, provider.configuration);
        });
      },
    },
    function (req, profile, done) {
      // for signon
      findByEmail(profile.email, function (err, user) {
        if (err) {
          return done(err);
        }
        return done(null, user);
      });
    },
    function (req, profile, done) {
      // for logout
      findByNameID(profile.nameID, function (err, user) {
        if (err) {
          return done(err);
        }
        return done(null, user);
      });
    }
  )
);
```

The options passed when the `MultiSamlStrategy` is initialized are also passed as default values to
each provider. e.g. If you provide an `issuer` on `MultiSamlStrategy`, this will be also a default
value for every provider. You can override these defaults by passing a new value through the
`getSamlOptions` function.

Using multiple providers supports `validateInResponseTo`, but all the `InResponse` values are stored
on the same Cache. This means, if you're using the default `InMemoryCache`, that all providers have
access to it and a provider might get its response validated against another's request.
[Issue Report](https://github.com/node-saml/passport-saml/issues/334). To amend this you should
provide a different cache provider per SAML provider, through the `getSamlOptions` function.

Please note that in the above examples, `findProvider()`, `findByNameId()`, and `findByEmail()` are
examples of functions you need to implement yourself. These are just examples. You can implement
this functionality any way you see fit. Please note that calling `getSamlOptions()` should result in
`done()` being called with a proper SAML Configuration (see the TypeScript typings for more
information) and the `done()` callbacks for the second and third arguments should be called with an
object that represents the user.

### Provide the authentication callback

You need to provide a route corresponding to the `path` configuration parameter given to the
strategy:

The authentication callback must be invoked after the `body-parser` middleware.

```javascript
const bodyParser = require("body-parser");

app.post(
  "/login/callback",
  bodyParser.urlencoded({ extended: false }),
  passport.authenticate("saml", {
    failureRedirect: "/",
    failureFlash: true,
  }),
  function (req, res) {
    res.redirect("/");
  },
);
```

### Authenticate requests

Use `passport.authenticate()`, specifying `saml` as the strategy:

```javascript
app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/", failureFlash: true }),
  function (req, res) {
    res.redirect("/");
  },
);
```

...or, if you wish to add or override query string parameters:

```javascript
app.get(
  "/login",
  passport.authenticate("saml", {
    additionalParams: { username: "user@domain.com" },
  }),
  function (req, res) {
    res.redirect("/");
  },
);
```

In addition to passing the `additionalParams` option to `passport.authenticate`, you can also pass
`samlFallback`, either as "login-request" or "logout-request". By default, this is set to
"login-request". However, in the case of the `req.query` and the `req.body` not containing a
`SAMLRequest` or `SAMLResponse`, this can be used to dictate which request handler is used in cases
where it can not be determined by these standard properties.

### generateServiceProviderMetadata( decryptionCert, signingCert )

For details about this method, please see the
[documentation](https://github.com/node-saml/node-saml#generateserviceprovidermetadata-decryptioncert-signingcert-)
at `node-saml`.

The `generateServiceProviderMetadata` method is also available on the `MultiSamlStrategy`, but needs
an extra request and a callback argument
(`generateServiceProviderMetadata( req, decryptionCert, signingCert, next )`), which are passed to
the `getSamlOptions` to retrieve the correct configuration.

## Usage with Active Directory Federation Services

Here is a configuration that has been proven to work with ADFS:

```javascript
  {
    entryPoint: 'https://ad.example.net/adfs/ls/',
    issuer: 'https://your-app.example.net/login/callback',
    callbackUrl: 'https://your-app.example.net/login/callback',
    idpCert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==',
    authnContext: ['http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows'],
    identifierFormat: null
  }
```

Please note that ADFS needs to have a trust established to your service in order for this to work.

For more detailed instructions, see
[ADFS documentation](https://github.com/node-saml/passport-saml/wiki/How-to-use-with-ADFS).

## SLO (single logout)

Passport-SAML has built in support for SLO from Node-SAML.

Note: Fully functional IdP initiated SLO support is not provided out of the box. You have to inspect
your use cases / implementation / deployment scenarios (location of IdP in respect to SP) and
consider things / cases listed e.g. at issue(s)
[#221](https://github.com/node-saml/passport-saml/issues/221) and
[#419](https://github.com/node-saml/passport-saml/issues/419). This library provides you a mechanism
to veto "Success" result but it does not provide hooks/interfaces to implement support for IdP
initiated SLO which would work under all circumstances. You have to do it yourself.

## ChangeLog

See [Releases](https://github.com/node-saml/passport-saml/releases) to find the changes that go into
each release. Additionally, see the [CHANGELOG](./CHANGELOG.md).

## FAQ

### Is there an example I can look at?

Gerard Braad has provided an example app at <https://github.com/gbraad/passport-saml-example/>

## Node Support Policy

We only support [Long-Term Support](https://github.com/nodejs/Release) versions of Node.

We specifically limit our support to LTS versions of Node, not because this package won't work on
other versions, but because we have a limited amount of time, and supporting LTS offers the greatest
return on that investment.

It's possible this package will work correctly on newer versions of Node. It may even be possible to
use this package on older versions of Node, though that's more unlikely as we'll make every effort
to take advantage of features available in the oldest LTS version we support.

As each Node LTS version reaches its end-of-life we will remove that version from the `node`
`engines` property of our package's `package.json` file. Removing a Node version is considered a
breaking change and will entail the publishing of a new major version of this package. We will not
accept any requests to support an end-of-life version of Node. Any merge requests or issues
supporting an end-of-life version of Node will be closed.

We will accept code that allows this package to run on newer, non-LTS, versions of Node.

## Project History

The project was started by @bergie in 2012 based on Michael Bosworth's
[express-saml](https://github.com/bozzltron/express-saml) library. From 2014 - 2016, @ploer served
as primary maintainer. @markstos served the primary maintainer from 2017 till 2020 when he created
the node-saml organization. With a goal to create a team of maintainers, invitations were sent to
major contributors and fork authors to work together to maintain all the improvements in one place.

Since 2020, @cjbath emerged as the primary maintainer, with major contributions from @gugu and
@zoellner. Major updates from the team included rewriting the project in TypeScript and splitting
off a `node-saml` module which can be used without Passport. Almost 100 other developers have
contributed improvements to the project.

The project continues to be maintained by volunteers. Contributions small and large are welcome.

## Copyright Notices

“[OASIS](http://www.oasis-open.org/)”, “SAML”, and “Security Assertion Markup Language” are
trademarks of OASIS, the open standards consortium where the SAML specification is owned and
developed. SAML is a copyrighted © work of OASIS Open. All rights reserved.
