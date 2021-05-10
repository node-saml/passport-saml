# Changelog

## v2.0.3 (2021-01-07)

- [**bug**] Reexport SamlConfig type to solve a regression in consumer packages [#516](https://github.com/node-saml/passport-saml/pull/516)
- [**bug**] fix: derive SamlConfig from SAMLOptions [#515](https://github.com/node-saml/passport-saml/pull/515)
- [**bug**] add ts-ignore to generated type definitions for multisaml strategy [#508](https://github.com/node-saml/passport-saml/pull/508)
- [**enhancement**] dev: add @types/xml-encryption [#517](https://github.com/node-saml/passport-saml/pull/517)
- [**dependencies**] upgrade deps to latest versions [#514](https://github.com/node-saml/passport-saml/pull/514)
- [**closed**] normalize signature line endings before loading signature block to xml-crypto [#512](https://github.com/node-saml/passport-saml/pull/512)
- [**closed**] fix(typing): Export Multi SAML types [#505](https://github.com/node-saml/passport-saml/pull/505)
- [**closed**] docs(scoping): fix for example [#504](https://github.com/node-saml/passport-saml/pull/504)
- [**dependencies**] Bump ini from 1.3.5 to 1.3.8 [#513](https://github.com/node-saml/passport-saml/pull/513)
- [**closed**] minor - fix typo in README [#506](https://github.com/node-saml/passport-saml/pull/506)
- [**semver-patch**] fix(typing): multi saml stratey export [#503](https://github.com/node-saml/passport-saml/pull/503)
- [**closed**] Prettier + ESLint + onchange = Happiness [#493](https://github.com/node-saml/passport-saml/pull/493)
- [**semver-patch**] support windows line breaks in keys [#500](https://github.com/node-saml/passport-saml/pull/500)

---

## v2.0.2 (2020-11-05)

- [**semver-patch**] normalize line endings before signature validation [#498](https://github.com/node-saml/passport-saml/pull/498)

---

## v2.0.1 (2020-11-03)

- [**closed**] Add deprecation notice for privateCert; fix bug [#492](https://github.com/node-saml/passport-saml/pull/492)

---

## v2.0.0 (2020-11-03)

- [**semver-minor**] Allow for use of privateKey instead of privateCert [#488](https://github.com/node-saml/passport-saml/pull/488)
- [**closed**] inlineSources option for better source maps [#487](https://github.com/node-saml/passport-saml/pull/487)
- [**2.0**][**breaking-change**] Always throw error objects instead of strings [#412](https://github.com/node-saml/passport-saml/pull/412)
- [**new-feature**][**pending-refinement**][**semver-minor**] feat(authorize-request): idp scoping provider [#428](https://github.com/node-saml/passport-saml/pull/428)
- [**semver-patch**] update version of xml2js to 0.4.23, fixes #479 [#486](https://github.com/node-saml/passport-saml/pull/486)
- [**closed**] fix: disable esmoduleInterop setting [#483](https://github.com/node-saml/passport-saml/pull/483)

---

## v1.5.0 (2020-10-30)

- [**closed**] validateSignature: Support XML docs that contain multiple signed node… [#481](https://github.com/node-saml/passport-saml/pull/481)
- [**needs-review**][**pending-refinement**] validateSignature: Support XML docs that contain multiple signed nodes [#455](https://github.com/node-saml/passport-saml/pull/455)
- [**closed**] Revert "validateSignature: Support XML docs that contain multiple signed nodes" [#480](https://github.com/node-saml/passport-saml/pull/480)
- [**closed**] outdated Q library was removed [#478](https://github.com/node-saml/passport-saml/pull/478)

---

## v1.4.2 (2020-10-29)

- [**closed**] Primary files use typescript [#477](https://github.com/node-saml/passport-saml/pull/477)

---

## v1.4.1 (2020-10-29)

- [**closed**] compatibility with @types/passport-saml, fixes #475 [#476](https://github.com/node-saml/passport-saml/pull/476)

---

## v1.4.0 (2020-10-28)

- [**closed**] try to use curl when wget is not available [#468](https://github.com/node-saml/passport-saml/pull/468)
- [**closed**] Ts secondary files [#474](https://github.com/node-saml/passport-saml/pull/474)
- [**closed**] bumped xml-crypto from 1.5.3 to 2.0.0 [#470](https://github.com/node-saml/passport-saml/pull/470)
- [**closed**] support typescript compilation [#469](https://github.com/node-saml/passport-saml/pull/469)
- [**closed**] Add PR template [#473](https://github.com/node-saml/passport-saml/pull/473)
- [**closed**] Drop support for Node 8 [#462](https://github.com/node-saml/passport-saml/pull/462)
- [**closed**] Fix typo [#434](https://github.com/node-saml/passport-saml/pull/434)
- [**closed**] Upgrade xml-crypto dependancy [#465](https://github.com/node-saml/passport-saml/pull/465)
- [**bug**] Only make an attribute an object if it has child elements [#464](https://github.com/node-saml/passport-saml/pull/464)
- [**closed**] Add GitHub Actions as Continuos Integration provider [#463](https://github.com/node-saml/passport-saml/pull/463)
- [**closed**] fix: add catch block to NameID decryption [#461](https://github.com/node-saml/passport-saml/pull/461)

---

## v1.3.5 (2020-09-16)

- [**dependencies**] Bump lodash from 4.17.15 to 4.17.20 [#449](https://github.com/node-saml/passport-saml/pull/449)
- [**dependencies**] Bump acorn from 7.1.0 to 7.4.0 [#448](https://github.com/node-saml/passport-saml/pull/448)
- [**closed**] Return object for XML-valued AttributeValues [#447](https://github.com/node-saml/passport-saml/pull/447)
- [**closed**] Revert "doc: announce site move." [#446](https://github.com/node-saml/passport-saml/pull/446)

---

## v1.3.4 (2020-07-21)

- [**closed**] Fix multi saml strategy race conditions [#426](https://github.com/node-saml/passport-saml/pull/426)

---

## v1.3.3 (2020-02-19)

- [**closed**] Singleline private keys [#423](https://github.com/node-saml/passport-saml/pull/423)

---

## v1.3.2 (2020-02-12)

- [**closed**] Revert "convert privateCert to PEM for signing" [#421](https://github.com/node-saml/passport-saml/pull/421)

---

## v1.3.1 (2020-02-11)

- [**closed**] Upgrade xml-encryption to 1.0.0 [#420](https://github.com/node-saml/passport-saml/pull/420)

---

## v1.3.0 (2020-02-06)

- [**pending-refinement**] Issue #206: Support signing AuthnRequests using the HTTP-POST Binding [#207](https://github.com/node-saml/passport-saml/pull/207)
- [**closed**] Add tests to check for correct logout [#418](https://github.com/node-saml/passport-saml/pull/418)
- [**closed**] added passReqToCallback to docs [#417](https://github.com/node-saml/passport-saml/pull/417)
- [**closed**] Fix an issue readme formatting [#416](https://github.com/node-saml/passport-saml/pull/416)
- [**closed**] attributeConsumingServiceIndex can be zero [#414](https://github.com/node-saml/passport-saml/pull/414)
- [**pending-refinement**] convert privateCert to PEM for signing [#390](https://github.com/node-saml/passport-saml/pull/390)
- [**pending-refinement**] add support for encrypted nameIDs in SLO request handling [#408](https://github.com/node-saml/passport-saml/pull/408)
- [**need-more-info**][**peer-review-welcome**] Bring-up xml-crypto to 1.4.0 [#400](https://github.com/node-saml/passport-saml/pull/400)
- [**closed**] fix #393 adding 'inResponseTo' in the profile [#404](https://github.com/node-saml/passport-saml/pull/404)
- [**closed**] Fix #355 missing parts: tests. [#402](https://github.com/node-saml/passport-saml/pull/402)
- [**closed**] Fix minimum version of Node.js in Travis [#399](https://github.com/node-saml/passport-saml/pull/399)
- [**closed**] Add .editorconfig as suggested in #373 [#398](https://github.com/node-saml/passport-saml/pull/398)

---

## v1.2.0 (2019-09-12)

- [**peer-review-welcome**] NameIDFormat fix [#375](https://github.com/node-saml/passport-saml/pull/375)
- [**peer-review-welcome**] Remove InResponseTo value if response validation fails [#341](https://github.com/node-saml/passport-saml/pull/341)

---

## v1.1.0 (2019-05-10)

- [**closed**] Fix broken tests [#367](https://github.com/node-saml/passport-saml/pull/367)
- [**peer-review-welcome**] Create a way to get provider metadata when using the MultiSamlStrategy [#323](https://github.com/node-saml/passport-saml/pull/323)
- [**pending-refinement**] feat: add RequestedAuthnContext Comparison Type parameter [#360](https://github.com/node-saml/passport-saml/pull/360)
- [**closed**] Update README.md [#363](https://github.com/node-saml/passport-saml/pull/363)
- [**peer-review-welcome**] InResponseTo support for logout [#356](https://github.com/node-saml/passport-saml/pull/356)

---

## v1.0.0 (2018-12-02)

- [**closed**] Handle case of missing InResponseTo when validation is on [#302](https://github.com/node-saml/passport-saml/pull/302)
- [**closed**] Extend and document the profile object [#301](https://github.com/node-saml/passport-saml/pull/301)

---

## v0.35.0 (2018-08-14)

_No changelog for this release._

---

## v0.34.0 (2018-08-14)

_No changelog for this release._

---

## v0.33.0 (2018-02-16)

_No changelog for this release._

---

## v0.32.1 (2018-01-03)

- [**closed**] README: fix typo `s/ADSF/ADFS/` [#251](https://github.com/node-saml/passport-saml/pull/251)

---

## v0.31.0 (2017-11-01)

_No changelog for this release._

---

## v0.30.0 (2017-10-12)

_No changelog for this release._

---

## v0.20.2 (2017-10-10)

_No changelog for this release._

---

## v0.20.1 (2017-10-10)

_No changelog for this release._

---

## v0.20.0 (2017-10-09)

_No changelog for this release._

---

## v0.16.2 (2017-10-07)

_No changelog for this release._

---

## v0.16.1 (2017-10-05)

_No changelog for this release._

---

## v0.16.0 (2017-10-04)

_No changelog for this release._

---

## v0.15.0 (2015-12-30)

_No changelog for this release._

---

## v0.14.0 (2015-11-02)

_No changelog for this release._

---

## v0.13.0 (2015-10-09)

_No changelog for this release._

---

## v0.12.0 (2015-08-19)

_No changelog for this release._

---

## v0.11.1 (2015-08-18)

_No changelog for this release._

---

## v0.11.0 (2015-08-10)

_No changelog for this release._

---

## v0.10.0 (2015-06-08)

_No changelog for this release._

---

## v0.9.2 (2015-04-26)

_No changelog for this release._

---

## v0.9.1 (2015-02-18)

_No changelog for this release._

---

## v0.9.0 (2015-02-05)

_No changelog for this release._

---

## v0.8.0 (2015-01-23)

_No changelog for this release._

---

## v0.7.0 (2015-01-13)

_No changelog for this release._

---

## v0.6.2 (2015-01-06)

_No changelog for this release._

---

## v0.6.1 (2014-12-18)

_No changelog for this release._

---

## v0.6.0 (2014-11-14)

_No changelog for this release._

---

## v0.5.3 (2014-09-11)

_No changelog for this release._

---

## v0.5.2 (2014-07-02)

_No changelog for this release._

---

## v0.5.1 (2014-07-02)

_No changelog for this release._

---

## v0.5.0 (2014-07-01)

_No changelog for this release._

---

## v0.4.0 (2014-06-20)

_No changelog for this release._

---

## v0.3.0 (2014-06-09)

_No changelog for this release._

---

## v0.2.1 (2014-06-05)

_No changelog for this release._

---

## v0.2.0 (2014-06-03)

_No changelog for this release._

---

## v0.1.0 (2014-05-31)

_No changelog for this release._
