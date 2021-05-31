# Changelog

## v3.0.0 (2021-05-14)

#### 💣 Major Changes:

- Node saml separation [#574](https://github.com/node-saml/passport-saml/pull/574)
- Remove support for deprecated `privateCert` [#569](https://github.com/node-saml/passport-saml/pull/569)
- Enforce more secure XML encryption [#584](https://github.com/node-saml/passport-saml/pull/584)
- Add Node 16 support; drop Node 10 [#589](https://github.com/node-saml/passport-saml/pull/589)
- Update all dependencies to latest [#590](https://github.com/node-saml/passport-saml/pull/590)
- Require cert for every strategy [#548](https://github.com/node-saml/passport-saml/pull/548)

#### 🚀 Minor Changes:

- Update xml-crypto to v2.1.1 [#558](https://github.com/node-saml/passport-saml/pull/558)
- Allow for authnRequestBinding in SAML options [#529](https://github.com/node-saml/passport-saml/pull/529)
- Add optional setting to set a ceiling on how old a SAML response is allowed to be [#577](https://github.com/node-saml/passport-saml/pull/577)
- Move XML functions to utility module [#571](https://github.com/node-saml/passport-saml/pull/571)
- Improve the typing of the Strategy class hierarchy. [#554](https://github.com/node-saml/passport-saml/pull/554)
- Resolve XML-encoded carriage returns during signature validation [#576](https://github.com/node-saml/passport-saml/pull/576)
- Make sure CI builds test latest versions of dependencies [#570](https://github.com/node-saml/passport-saml/pull/570)
- Add WantAssertionsSigned [#536](https://github.com/node-saml/passport-saml/pull/536)

#### 🔗 Dependencies:

- bump xmldom to 0.5.x since all lower versions have security issue [#551](https://github.com/node-saml/passport-saml/pull/551)
- Update xml-encryption to v1.2.3 [#560](https://github.com/node-saml/passport-saml/pull/560)
- Update xml-encryption to v1.2.3 [#567](https://github.com/node-saml/passport-saml/pull/567)
- Update all packages to latest semver-minor [#588](https://github.com/node-saml/passport-saml/pull/588)

#### 🐛 Bug Fixes:

- Fix incorrect import of compiled files in tests [#572](https://github.com/node-saml/passport-saml/pull/572)

#### 📚 Documentation:

- Remove deprecated field `privateCert` from README, tests [#591](https://github.com/node-saml/passport-saml/pull/591)
- Add support for more tags in the changelog [#592](https://github.com/node-saml/passport-saml/pull/592)
- Update readme on using multiSamlStrategy [#531](https://github.com/node-saml/passport-saml/pull/531)
- Create of Code of Conduct [#573](https://github.com/node-saml/passport-saml/pull/573)
- Changelog [#587](https://github.com/node-saml/passport-saml/pull/587)

#### ⚙️ Technical Tasks:

- remove old callback functions, tests use async/await [#545](https://github.com/node-saml/passport-saml/pull/545)
- async/await for saml.ts [#496](https://github.com/node-saml/passport-saml/pull/496)
- Format code and enforce code style on PR [#527](https://github.com/node-saml/passport-saml/pull/527)
- Tests use typescript [#534](https://github.com/node-saml/passport-saml/pull/534)
- async / await in cache interface [#532](https://github.com/node-saml/passport-saml/pull/532)
- Fix lint npm script to match all files including in src/ [#555](https://github.com/node-saml/passport-saml/pull/555)

#### 🙈 Other:

- Revert "Update xml-encryption to v1.2.3" [#564](https://github.com/node-saml/passport-saml/pull/564)

---

## v2.2.0 (2021-04-23)

#### 🚀 Minor Changes:

- Add deprecation notices for renamed variables [#568](https://github.com/node-saml/passport-saml/pull/568)

#### 🐛 Bug Fixes:

- Resolve XML-encoded carriage returns during signature validation (2.x) [#578](https://github.com/node-saml/passport-saml/pull/578)

---

## v2.1.0 (2021-03-19)

#### 🚀 Minor Changes:

- Update xml-crypto to v2.1.1 [#557](https://github.com/node-saml/passport-saml/pull/557)

#### 🔗 Dependencies:

- Update xml-encryption to v1.2.3 [#562](https://github.com/node-saml/passport-saml/pull/562)

#### 🙈 Other:

- Revert "Update xml-encryption to v1.2.3" [#565](https://github.com/node-saml/passport-saml/pull/565)
- Update xml-encryption to v1.2.3 (branch 2.x) [#566](https://github.com/node-saml/passport-saml/pull/566)

---

## v2.0.6 (2021-03-15)

#### 🔗 Dependencies:

- bump xmldom to 0.5.x since all lower versions have security issue (#551) [#553](https://github.com/node-saml/passport-saml/pull/553)

---

## v2.0.5 (2021-01-29)

#### ⚙️ Technical Tasks:

- Ignore `test` folder when building npm package [#526](https://github.com/node-saml/passport-saml/pull/526)

---

## v2.0.4 (2021-01-19)

#### ⚙️ Technical Tasks:

- Generating changelog using gren [#518](https://github.com/node-saml/passport-saml/pull/518)

---

## v2.0.3 (2020-12-21)

#### 🚀 Minor Changes:

- dev: add @types/xml-encryption [#517](https://github.com/node-saml/passport-saml/pull/517)

#### 🔗 Dependencies:

- upgrade deps to latest versions [#514](https://github.com/node-saml/passport-saml/pull/514)
- Bump ini from 1.3.5 to 1.3.8 [#513](https://github.com/node-saml/passport-saml/pull/513)

#### 🐛 Bug Fixes:

- support windows line breaks in keys [#500](https://github.com/node-saml/passport-saml/pull/500)
- add ts-ignore to generated type definitions for multisaml strategy [#508](https://github.com/node-saml/passport-saml/pull/508)
- fix: derive SamlConfig from SAMLOptions [#515](https://github.com/node-saml/passport-saml/pull/515)
- Reexport SamlConfig type to solve a regression in consumer packages [#516](https://github.com/node-saml/passport-saml/pull/516)
- fix(typing): multi saml stratey export [#503](https://github.com/node-saml/passport-saml/pull/503)
- normalize signature line endings before loading signature block to xml-crypto [#512](https://github.com/node-saml/passport-saml/pull/512)

#### 📚 Documentation:

- docs(scoping): fix for example [#504](https://github.com/node-saml/passport-saml/pull/504)
- minor - fix typo in README [#506](https://github.com/node-saml/passport-saml/pull/506)

#### 🙈 Other:

- fix(typing): Export Multi SAML types [#505](https://github.com/node-saml/passport-saml/pull/505)
- Prettier + ESLint + onchange = Happiness [#493](https://github.com/node-saml/passport-saml/pull/493)

---

## v2.0.2 (2020-11-05)

#### 🐛 Bug Fixes:

- normalize line endings before signature validation [#498](https://github.com/node-saml/passport-saml/pull/498)

---

## v2.0.1 (2020-11-03)

#### 🙈 Other:

- Add deprecation notice for privateCert; fix bug [#492](https://github.com/node-saml/passport-saml/pull/492)

---

## v2.0.0 (2020-11-03)

#### 💣 Major Changes:

- Always throw error objects instead of strings [#412](https://github.com/node-saml/passport-saml/pull/412)

#### 🚀 Minor Changes:

- Allow for use of privateKey instead of privateCert [#488](https://github.com/node-saml/passport-saml/pull/488)
- feat(authorize-request): idp scoping provider [#428](https://github.com/node-saml/passport-saml/pull/428)

#### 🐛 Bug Fixes:

- update version of xml2js to 0.4.23, fixes #479 [#486](https://github.com/node-saml/passport-saml/pull/486)

#### 🙈 Other:

- inlineSources option for better source maps [#487](https://github.com/node-saml/passport-saml/pull/487)
- fix: disable esmoduleInterop setting [#483](https://github.com/node-saml/passport-saml/pull/483)

---

## v1.5.0 (2020-10-29)

#### 🚀 Minor Changes:

- validateSignature: Support XML docs that contain multiple signed nodes [#455](https://github.com/node-saml/passport-saml/pull/455)

#### ⚙️ Technical Tasks:

- outdated Q library was removed [#478](https://github.com/node-saml/passport-saml/pull/478)

#### 🙈 Other:

- validateSignature: Support XML docs that contain multiple signed node… [#481](https://github.com/node-saml/passport-saml/pull/481)
- Revert "validateSignature: Support XML docs that contain multiple signed nodes" [#480](https://github.com/node-saml/passport-saml/pull/480)

---

## v1.4.2 (2020-10-29)

#### ⚙️ Technical Tasks:

- Primary files use typescript [#477](https://github.com/node-saml/passport-saml/pull/477)

---

## v1.4.1 (2020-10-29)

#### 🙈 Other:

- compatibility with @types/passport-saml, fixes #475 [#476](https://github.com/node-saml/passport-saml/pull/476)

---

## v1.4.0 (2020-10-28)

#### 🐛 Bug Fixes:

- Only make an attribute an object if it has child elements [#464](https://github.com/node-saml/passport-saml/pull/464)

#### ⚙️ Technical Tasks:

- support typescript compilation [#469](https://github.com/node-saml/passport-saml/pull/469)

#### 🙈 Other:

- try to use curl when wget is not available [#468](https://github.com/node-saml/passport-saml/pull/468)
- Ts secondary files [#474](https://github.com/node-saml/passport-saml/pull/474)
- bumped xml-crypto from 1.5.3 to 2.0.0 [#470](https://github.com/node-saml/passport-saml/pull/470)
- Add PR template [#473](https://github.com/node-saml/passport-saml/pull/473)
- Drop support for Node 8 [#462](https://github.com/node-saml/passport-saml/pull/462)
- Fix typo [#434](https://github.com/node-saml/passport-saml/pull/434)
- Upgrade xml-crypto dependancy [#465](https://github.com/node-saml/passport-saml/pull/465)
- Add GitHub Actions as Continuos Integration provider [#463](https://github.com/node-saml/passport-saml/pull/463)
- fix: add catch block to NameID decryption [#461](https://github.com/node-saml/passport-saml/pull/461)

---

## v1.3.5 (2020-09-16)

#### 🔗 Dependencies:

- Bump lodash from 4.17.15 to 4.17.20 [#449](https://github.com/node-saml/passport-saml/pull/449)
- Bump acorn from 7.1.0 to 7.4.0 [#448](https://github.com/node-saml/passport-saml/pull/448)

#### 🙈 Other:

- Return object for XML-valued AttributeValues [#447](https://github.com/node-saml/passport-saml/pull/447)
- Revert "doc: announce site move." [#446](https://github.com/node-saml/passport-saml/pull/446)

---

## v1.3.4 (2020-07-21)

#### 🙈 Other:

- Fix multi saml strategy race conditions [#426](https://github.com/node-saml/passport-saml/pull/426)

---

## v1.3.3 (2020-02-19)

#### 🙈 Other:

- Singleline private keys [#423](https://github.com/node-saml/passport-saml/pull/423)

---

## v1.3.2 (2020-02-12)

#### 🙈 Other:

- Revert "convert privateCert to PEM for signing" [#421](https://github.com/node-saml/passport-saml/pull/421)

---

## v1.3.1 (2020-02-11)

#### 🙈 Other:

- Upgrade xml-encryption to 1.0.0 [#420](https://github.com/node-saml/passport-saml/pull/420)

---

## v1.3.0 (2020-01-28)

#### 🚀 Minor Changes:

- add support for encrypted nameIDs in SLO request handling [#408](https://github.com/node-saml/passport-saml/pull/408)
- Issue #206: Support signing AuthnRequests using the HTTP-POST Binding [#207](https://github.com/node-saml/passport-saml/pull/207)
- convert privateCert to PEM for signing [#390](https://github.com/node-saml/passport-saml/pull/390)

#### 🙈 Other:

- Add tests to check for correct logout [#418](https://github.com/node-saml/passport-saml/pull/418)
- added passReqToCallback to docs [#417](https://github.com/node-saml/passport-saml/pull/417)
- Fix an issue readme formatting [#416](https://github.com/node-saml/passport-saml/pull/416)
- attributeConsumingServiceIndex can be zero [#414](https://github.com/node-saml/passport-saml/pull/414)
- fix #393 adding 'inResponseTo' in the profile [#404](https://github.com/node-saml/passport-saml/pull/404)
- Fix #355 missing parts: tests. [#402](https://github.com/node-saml/passport-saml/pull/402)
- Fix minimum version of Node.js in Travis [#399](https://github.com/node-saml/passport-saml/pull/399)
- Add .editorconfig as suggested in #373 [#398](https://github.com/node-saml/passport-saml/pull/398)
- Bring-up xml-crypto to 1.4.0 [#400](https://github.com/node-saml/passport-saml/pull/400)

---

## v1.2.0 (2019-07-26)

#### 🙈 Other:

- Remove InResponseTo value if response validation fails [#341](https://github.com/node-saml/passport-saml/pull/341)
- NameIDFormat fix [#375](https://github.com/node-saml/passport-saml/pull/375)

---

## v1.1.0 (2019-05-10)

#### 🚀 Minor Changes:

- feat: add RequestedAuthnContext Comparison Type parameter [#360](https://github.com/node-saml/passport-saml/pull/360)
- Add option to disable SAML spec AuthnRequest optional value Assertion… [#315](https://github.com/node-saml/passport-saml/pull/315)

#### 🙈 Other:

- Fix broken tests [#367](https://github.com/node-saml/passport-saml/pull/367)
- Update README.md [#363](https://github.com/node-saml/passport-saml/pull/363)
- Set explicitChar: true to make XML parsing consistent. Fixes issue #283 and #187 [#361](https://github.com/node-saml/passport-saml/pull/361)
- update xml crypto to 1.1.4 [#352](https://github.com/node-saml/passport-saml/pull/352)
- Upgrade xml-crypto to 1.1.2 [#344](https://github.com/node-saml/passport-saml/pull/344)
- Add SamlResponseXML method to profile object [#330](https://github.com/node-saml/passport-saml/pull/330)
- Fix Node Buffer deprecation warning: update 'new Buffer' to 'Buffer.from()' [#342](https://github.com/node-saml/passport-saml/pull/342)
- Fix #128 documentation for body-parser dependancy [#326](https://github.com/node-saml/passport-saml/pull/326)
- Update Node version in package.json to >=6 [#340](https://github.com/node-saml/passport-saml/pull/340)
- Fix for failing test [#347](https://github.com/node-saml/passport-saml/pull/347)
- Support InResponseTo validations in MultiSaml [#350](https://github.com/node-saml/passport-saml/pull/350)
- InResponseTo support for logout [#356](https://github.com/node-saml/passport-saml/pull/356)
- Create a way to get provider metadata when using the MultiSamlStrategy [#323](https://github.com/node-saml/passport-saml/pull/323)

---

## v1.0.0 (2018-12-02)

#### 💣 Major Changes:

- Adds signing key in the metadata service provider generation. [#306](https://github.com/node-saml/passport-saml/pull/306)

#### 🚀 Minor Changes:

- Support dynamic SAML configuration lookup [#276](https://github.com/node-saml/passport-saml/pull/276)
- Support redirect for Logout flows [#277](https://github.com/node-saml/passport-saml/pull/277)

#### 🙈 Other:

- Include support for run-time params to be included in the generated URLs [#136](https://github.com/node-saml/passport-saml/pull/136)
- support multiple authnContext [#298](https://github.com/node-saml/passport-saml/pull/298)
- Handle case of missing InResponseTo when validation is on [#302](https://github.com/node-saml/passport-saml/pull/302)
- Extend and document the profile object [#301](https://github.com/node-saml/passport-saml/pull/301)
- Update xml-crypto to 1.0.2 [#321](https://github.com/node-saml/passport-saml/pull/321)
- Validate issuer on logout requests/responses if configured [#314](https://github.com/node-saml/passport-saml/pull/314)
- feat(logout): handle null and undefined on nameQualifier [#311](https://github.com/node-saml/passport-saml/pull/311)
- entryPoint is compulsory for signed requests [#299](https://github.com/node-saml/passport-saml/pull/299)

---

## v0.35.0 (2018-08-14)

_No changelog for this release._

---

## v0.34.0 (2018-08-14)

_No changelog for this release._

---

## v0.33.0 (2018-02-16)

#### 🙈 Other:

- New Feature: allow customizing the name of the strategy. [#262](https://github.com/node-saml/passport-saml/pull/262)

---

## v0.32.1 (2018-01-03)

#### 🙈 Other:

- Audience validation [#253](https://github.com/node-saml/passport-saml/pull/253)
- README: fix typo `s/ADSF/ADFS/` [#251](https://github.com/node-saml/passport-saml/pull/251)

---

## v0.31.0 (2017-11-01)

#### 🚀 Minor Changes:

- Support multiple and dynamic signing certificates [#218](https://github.com/node-saml/passport-saml/pull/218)

#### 🙈 Other:

- Upd: Mention ADFS 2016 with NameIDFormatError. [#242](https://github.com/node-saml/passport-saml/pull/242)

---

## v0.30.0 (2017-10-12)

#### 🐛 Bug Fixes:

- [**security**] Use crypto.randomBytes for ID generation [#235](https://github.com/node-saml/passport-saml/pull/235)
- Fix: "TypeError: Cannot read property 'documentElement' of null" [#239](https://github.com/node-saml/passport-saml/pull/239)

---

## v0.20.2 (2017-10-10)

_No changelog for this release._

---

## v0.20.1 (2017-10-10)

#### 🙈 Other:

- handle bad privateCert [#231](https://github.com/node-saml/passport-saml/pull/231)
- Add support for ProviderName attribute [#216](https://github.com/node-saml/passport-saml/pull/216)

---

## v0.20.0 (2017-10-09)

#### 🙈 Other:

- Add badges to readme [#202](https://github.com/node-saml/passport-saml/pull/202)
- Update README to clarify that saml.cert requires a PEM-encoded x509 c… [#133](https://github.com/node-saml/passport-saml/pull/133)

---

## v0.16.2 (2017-10-05)

_No changelog for this release._

---

## v0.16.1 (2017-10-05)

_No changelog for this release._

---

## v0.16.0 (2017-04-01)

#### 🙈 Other:

- Remove unused ejs package from devDeps [#195](https://github.com/node-saml/passport-saml/pull/195)
- Fixes #170: Clarify that the certificate are looking for is: [#171](https://github.com/node-saml/passport-saml/pull/171)
- Add the ability to sign with SHA-512 [#173](https://github.com/node-saml/passport-saml/pull/173)
- Support detached encrypted key [#166](https://github.com/node-saml/passport-saml/pull/166)

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

## v0.2.0 (2014-06-02)

_No changelog for this release._

---

## v0.1.0 (2014-05-31)

_No changelog for this release._
