# Passport-SAML

[![Build Status](https://github.com/node-saml/passport-saml/actions/workflows/workflow.yml/badge.svg?branch=master)](https://github.com/node-saml/passport-saml/actions/workflows/workflow.yml)
[![CodeQL](https://github.com/node-saml/passport-saml/actions/workflows/codeql-analysis.yml/badge.svg?branch=master)](https://github.com/node-saml/passport-saml/actions/workflows/codeql-analysis.yml)
[![npm version](https://badge.fury.io/js/@node-saml%2Fpassport-saml.svg)](https://badge.fury.io/js/@node-saml%2Fpassport-saml)
[![Node.js version](https://img.shields.io/node/v/@node-saml/passport-saml)](#node-support-policy)
[![License: MIT](https://img.shields.io/npm/l/@node-saml/passport-saml)](LICENSE)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)
[![codecov](https://codecov.io/gh/node-saml/passport-saml/branch/master/graph/badge.svg?token=2JJrPZN29A)](https://codecov.io/gh/node-saml/passport-saml)
[![DeepScan grade](https://deepscan.io/api/teams/17569/projects/20922/branches/586238/badge/grade.svg)](https://deepscan.io/dashboard#view=project&tid=17569&pid=20922&bid=586238)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/cjbarth)](https://github.com/sponsors/cjbarth)

[![NPM](https://nodei.co/npm/@node-saml/passport-saml.png?downloads=true&downloadRank=true&stars=true)](https://www.npmjs.com/package/@node-saml/passport-saml)

This is a [SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0) authentication provider for
[Passport](https://www.passportjs.org/), the Node.js authentication library.

Passport-SAML has been tested to work with OneLogin, Okta, Shibboleth,
[SimpleSAMLphp](https://simplesamlphp.org/) based Identity Providers, and with
[Active Directory Federation Services](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Sponsors

![workos](https://github.com/workos.png?size=30) [workos](https://github.com/workos)

## Installation

```shell
npm install @node-saml/passport-saml
```

## Usage

Passport-SAML is the service provider (SP) side of a SAML login: it sends users to your identity
provider (IdP) to log in, and validates the response the IdP sends back. Register your site with
the IdP first; most IdPs accept the
[metadata](#generateserviceprovidermetadata-decryptioncert-signingcert-) that Passport-SAML
generates. From the IdP you need its single sign-on URL, for `entryPoint`, and its signing
certificate, for `idpCert`.

The examples use ES modules, which Node 18 supports; with CommonJS, `require()` the same names. They
use `https://sp.example.com` for your site and `https://idp.example.com` for the IdP.

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
- `name`: Optionally, provide a custom name. (default: `saml`). Useful if you want to instantiate
  the strategy multiple times with different configurations, allowing users to authenticate against
  multiple different SAML targets from the same site. You'll need to use a unique set of URLs for
  each target, and use this custom name when calling `passport.authenticate()` as well.

#### Examples

The IdP sends its response to `callbackUrl`;
[Provide the authentication callback](#provide-the-authentication-callback) adds the route for it.

```javascript
import { readFileSync } from "node:fs";
import passport from "passport";
import { Strategy as SamlStrategy } from "@node-saml/passport-saml";

const samlStrategy = new SamlStrategy(
  {
    callbackUrl: "https://sp.example.com/login/callback",
    entryPoint: "https://idp.example.com/sso",
    issuer: "https://sp.example.com/metadata",
    idpCert: readFileSync("./idp-signing-cert.pem", "utf-8"),
  },
  // Sign-on: return the user the IdP authenticated
  async (profile, done) => {
    try {
      done(null, await findUserByEmail(profile.email));
    } catch (err) {
      done(err);
    }
  },
  // Logout: return the user the IdP is logging out
  async (profile, done) => {
    try {
      done(null, await findUserByNameID(profile.nameID));
    } catch (err) {
      done(err);
    }
  },
);

passport.use(samlStrategy);
```

`findUserByEmail()` and `findUserByNameID()` stand in for your own user lookups. `profile` holds
the SAML assertion's `nameID` and attributes; `profile.email` comes from an `email` or `mail`
attribute, if the IdP sends one.

- **Sign-on:** call `done(null, user)` to log the user in. A missing user (`null`, `undefined` or
  `false`) fails the login, and `done(err)` reports an error.
- **Logout:** runs when the IdP sends a `LogoutRequest`. Passport-SAML compares the user you return
  with `req.user`, using `assert.deepStrictEqual`, and tells the IdP the logout succeeded only if
  they match. It logs out the current session either way.

### Configure strategy for multiple providers

To choose the SAML configuration per request, use `MultiSamlStrategy` and pass it a
`getSamlOptions` function:

```javascript
import passport from "passport";
import { MultiSamlStrategy } from "@node-saml/passport-saml";

passport.use(
  new MultiSamlStrategy(
    {
      passReqToCallback: true, // pass `req` to the sign-on and logout functions below
      getSamlOptions: async (req, done) => {
        try {
          const provider = await findProvider(req);
          done(null, provider.samlOptions);
        } catch (err) {
          done(err);
        }
      },
    },
    // Sign-on
    async (req, profile, done) => {
      try {
        done(null, await findUserByEmail(profile.email));
      } catch (err) {
        done(err);
      }
    },
    // Logout
    async (req, profile, done) => {
      try {
        done(null, await findUserByNameID(profile.nameID));
      } catch (err) {
        done(err);
      }
    },
  ),
);
```

`getSamlOptions` runs on every request that reaches the strategy. `findProvider()` stands in for
your own lookup. Call `done(null, options)` with that provider's configuration, or `done(err)`. The
options are merged over the ones passed to `MultiSamlStrategy`, so settings shared by every provider
can go in the constructor. `callbackUrl`, `issuer` and `idpCert` must be set after the merge.

`MultiSamlStrategy` builds a new `node-saml` `SAML` instance from the merged options for each
request. If those options have no `cacheProvider`, each instance starts with its own empty in-memory
cache, so with `validateInResponseTo` set to `"always"` or `"ifPresent"`, every response to a login
request is rejected: the cache that recorded the request is gone. Return a `cacheProvider` from
`getSamlOptions`, the same one for a provider on every call, so a response finds the cache its
request was recorded in. One `cacheProvider` passed to the `MultiSamlStrategy` constructor also
works, but all providers share it, so a response to one provider's request passes this check at
another provider's callback.

A `cacheProvider` is an object with `saveAsync(key, value)`, `getAsync(key)` and `removeAsync(key)`
methods, described by the `CacheProvider` TypeScript type. Back it with a store that every process
handling your logins can reach, such as Redis or your database. `node-saml` removes a request ID
only when a response to it arrives, so have the store expire entries after
`requestIdExpirationPeriodMs` (8 hours by default); otherwise the IDs of abandoned logins stay
forever.

### Provide the authentication callback

The IdP posts its response to `callbackUrl` as a form. Add a route for that path that parses the
form body before `passport.authenticate()`. `express.urlencoded()` is built into Express 4.16 and
later, including Express 5.

```javascript
app.post(
  "/login/callback",
  express.urlencoded({ extended: false }),
  passport.authenticate("saml", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/");
  },
);
```

### Authenticate requests

Use `passport.authenticate()`, specifying `saml` as the strategy, on the route that starts a login.
It sends the browser to the IdP's `entryPoint`:

```javascript
app.get("/login", passport.authenticate("saml"));
```

...or, if you wish to add or override query string parameters:

```javascript
app.get(
  "/login",
  passport.authenticate("saml", { additionalParams: { username: "user@example.com" } }),
);
```

These parameters go on the redirect URL, so a login with `authnRequestBinding: "HTTP-POST"` does not
send them.

In addition to passing the `additionalParams` option to `passport.authenticate`, you can also pass
`samlFallback`, either as "login-request" or "logout-request". By default, this is set to
"login-request". However, in the case of the `req.query` and the `req.body` not containing a
`SAMLRequest` or `SAMLResponse`, this can be used to dictate which request handler is used in cases
where it can not be determined by these standard properties.

### Return users to where they started with `RelayState`

`RelayState` is a short value that goes to the IdP with a SAML request and comes back, unchanged,
with the IdP's response. Use it to send users back to the page they asked for before they had to
log in.

To send one, put `RelayState` in the query string or form body of the request that starts the
login. Passport-SAML sends it to the IdP alongside the `AuthnRequest`: as a query parameter with the
HTTP-Redirect binding, or as a hidden form field with HTTP-POST. The `/login` route above needs no
changes:

```javascript
// When a page needs a logged-in user, send them to log in and remember where they were going
res.redirect(`/login?RelayState=${encodeURIComponent(req.originalUrl)}`);
```

The IdP posts it back to your callback URL along with the `SAMLResponse`, where it is available as
`req.body.RelayState`. Passport-SAML passes it through without acting on it.

`RelayState` is not part of the signed SAML response: the IdP posts it as a separate form field, so
anyone can change it on its way back to you. Treat it as untrusted input. Redirecting to it without
checking it turns your callback into an
[open redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
For example, follow it only when it is a path on your own site:

```javascript
app.post(
  "/login/callback",
  express.urlencoded({ extended: false }),
  passport.authenticate("saml", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect(localPathOr(req.body.RelayState, "/"));
  },
);

// Returns `value` if it is a path on this site; otherwise `fallback`.
function localPathOr(value, fallback) {
  if (typeof value !== "string") return fallback;
  const base = "https://sp.invalid"; // placeholder origin, used only to parse `value`
  try {
    const url = new URL(value, base);
    if (url.origin === base) return url.pathname + url.search + url.hash;
  } catch {
    // not a valid URL
  }
  return fallback;
}
```

The SAML 2.0 bindings specification
([sections 3.4.3 and 3.5.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf))
limits `RelayState` to 80 bytes, so an IdP may reject a longer value. It also recommends protecting
the value from tampering "by using a checksum, a pseudo-random value, or similar means". If your
paths can be longer than 80 bytes, or you want that protection, store the destination on the server
under a short random key and send the key as `RelayState` instead.

Logout works the same way. `RelayState` on the request that starts a logout, through
`strategy.logout(req, callback)` or `samlFallback: "logout-request"`, is sent with the
`LogoutRequest` and comes back with the IdP's `LogoutResponse`, in `req.query.RelayState` or
`req.body.RelayState` depending on the binding. When the IdP starts the logout, Passport-SAML
returns the IdP's `RelayState` in its `LogoutResponse`, as the specification requires.

`RelayState` only comes back if the IdP received your request. If `entryPoint` is a link that starts
an IdP-initiated login, rather than the IdP's single sign-on service URL (the `SingleSignOnService`
location in its metadata), the IdP ignores the `AuthnRequest` and the `RelayState` along with it. In
an IdP-initiated login, `req.body.RelayState` holds whatever the IdP is configured to send, if
anything.

### generateServiceProviderMetadata( decryptionCert, signingCert )

Generates your SP's metadata, which you can give to the IdP when you register your site. Serve it
from a route:

```javascript
app.get("/metadata", (req, res) => {
  res.type("application/xml").send(samlStrategy.generateServiceProviderMetadata(null));
});
```

Pass `decryptionCert` when you configure `decryptionPvk`, and `signingCert` when you configure
`privateKey`; otherwise pass `null` for `decryptionCert` and leave out `signingCert`. For details,
see [Service provider metadata](https://github.com/node-saml/node-saml#service-provider-metadata) in
the `node-saml` documentation.

The `generateServiceProviderMetadata` method is also available on the `MultiSamlStrategy`, but needs
an extra request and a callback argument
(`generateServiceProviderMetadata(req, decryptionCert, signingCert, callback)`). It passes `req` to
`getSamlOptions` to retrieve the correct configuration, then calls `callback(err, metadata)`.

## Usage with Active Directory Federation Services

Here is a configuration for ADFS:

```javascript
const adfsOptions = {
  entryPoint: "https://adfs.example.com/adfs/ls/",
  issuer: "https://sp.example.com/login/callback",
  callbackUrl: "https://sp.example.com/login/callback",
  idpCert: "MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==",
  authnContext: ["http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows"],
  identifierFormat: null,
};
```

ADFS needs a relying party trust for your service, with `issuer` as its identifier.

By default, ADFS signs only the assertion in its response, and Passport-SAML rejects a response
whose outer `Response` element is not signed. Have ADFS sign both:

```powershell
Set-AdfsRelyingPartyTrust -TargetName "<relying party name>" -SamlResponseSignature MessageAndAssertion
```

If you can't change the relying party trust, set `wantAuthnResponseSigned: false` instead. The
assertion's signature is still required.

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

Gerard Braad has provided an example app at <https://github.com/gbraad/passport-saml-example/>. It
was written for passport-saml 1.x, so some of its option names have changed since; for example,
`cert` is now `idpCert`. Use this README for the current options.

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

## Past sponsors

![stytchauth](https://github.com/stytchauth.png?size=30) [stytchauth](https://github.com/stytchauth)

## Copyright Notices

“[OASIS](http://www.oasis-open.org/)”, “SAML”, and “Security Assertion Markup Language” are
trademarks of OASIS, the open standards consortium where the SAML specification is owned and
developed. SAML is a copyrighted © work of OASIS Open. All rights reserved.
