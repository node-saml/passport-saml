# Changelog

## v2.2.0 (2021-04-23)

#### 💣 Major Changes:

- Node saml separation [#574](https://github.com/node-saml/passport-saml/pull/574)
- Remove support for deprecated `privateCert` [#569](https://github.com/node-saml/passport-saml/pull/569)

#### 🚀 Minor Changes:

- Add deprecation notices for renamed variables [#568](https://github.com/node-saml/passport-saml/pull/568)
- Move XML functions to utility module [#571](https://github.com/node-saml/passport-saml/pull/571)
- Improve the typing of the Strategy class hierarchy. [#554](https://github.com/node-saml/passport-saml/pull/554)
- Resolve XML-encoded carriage returns during signature validation [#576](https://github.com/node-saml/passport-saml/pull/576)
- Make sure CI builds test latest versions of dependencies [#570](https://github.com/node-saml/passport-saml/pull/570)
- Add WantAssertionsSigned [#536](https://github.com/node-saml/passport-saml/pull/536)

#### 🐛 Bug Fixes:

- Resolve XML-encoded carriage returns during signature validation (2.x) [#578](https://github.com/node-saml/passport-saml/pull/578)
- Fix incorrect import of compiled files in tests [#572](https://github.com/node-saml/passport-saml/pull/572)

#### 📚 Documentation:

- Create of Code of Conduct [#573](https://github.com/node-saml/passport-saml/pull/573)

---

## v2.1.0 (2021-03-19)

#### 💣 Major Changes:

- Require cert for every strategy [#548](https://github.com/node-saml/passport-saml/pull/548)

#### 🚀 Minor Changes:

- Update xml-crypto to v2.1.1 [#557](https://github.com/node-saml/passport-saml/pull/557)
- Update xml-crypto to v2.1.1 [#558](https://github.com/node-saml/passport-saml/pull/558)

#### 🔗 Dependencies:

- Update xml-encryption to v1.2.3 [#560](https://github.com/node-saml/passport-saml/pull/560)
- Update xml-encryption to v1.2.3 [#562](https://github.com/node-saml/passport-saml/pull/562)
- Update xml-encryption to v1.2.3 [#567](https://github.com/node-saml/passport-saml/pull/567)

#### ⚙️ Technical Tasks:

- Fix lint npm script to match all files including in src/ [#555](https://github.com/node-saml/passport-saml/pull/555)

#### 🙈 Other:

- Revert "Update xml-encryption to v1.2.3" [#564](https://github.com/node-saml/passport-saml/pull/564)
- Revert "Update xml-encryption to v1.2.3" [#565](https://github.com/node-saml/passport-saml/pull/565)
- Update xml-encryption to v1.2.3 (branch 2.x) [#566](https://github.com/node-saml/passport-saml/pull/566)

---

## v2.0.6 (2021-03-15)

#### 🚀 Minor Changes:

- Allow for authnRequestBinding in SAML options [#529](https://github.com/node-saml/passport-saml/pull/529)

#### 🔗 Dependencies:

- bump xmldom to 0.5.x since all lower versions have security issue [#551](https://github.com/node-saml/passport-saml/pull/551)
- bump xmldom to 0.5.x since all lower versions have security issue (#551) [#553](https://github.com/node-saml/passport-saml/pull/553)

#### 📚 Documentation:

- Update readme on using multiSamlStrategy [#531](https://github.com/node-saml/passport-saml/pull/531)

#### ⚙️ Technical Tasks:

- remove old callback functions, tests use async/await [#545](https://github.com/node-saml/passport-saml/pull/545)
- async/await for saml.ts [#496](https://github.com/node-saml/passport-saml/pull/496)
- Format code and enforce code style on PR [#527](https://github.com/node-saml/passport-saml/pull/527)
- Tests use typescript [#534](https://github.com/node-saml/passport-saml/pull/534)
- async / await in cache interface [#532](https://github.com/node-saml/passport-saml/pull/532)

---

## v2.0.5 (2021-01-29)

#### ⚙️ Technical Tasks:

- Ignore `test` folder when building npm package [#526](https://github.com/node-saml/passport-saml/pull/526)

---

## v2.0.4 (2021-01-19)

#### ⚙️ Technical Tasks:

- Generating changelog using gren [#518](https://github.com/node-saml/passport-saml/pull/518)

---

## v2.0.3 (2021-01-07)

#### 🐛 Bug Fixes:

- normalize signature line endings before loading signature block to xml-crypto [#512](https://github.com/node-saml/passport-saml/pull/512)
- support windows line breaks in keys [#500](https://github.com/node-saml/passport-saml/pull/500)
- add ts-ignore to generated type definitions for multisaml strategy [#508](https://github.com/node-saml/passport-saml/pull/508)

#### 📚 Documentation:

- docs(scoping): fix for example [#504](https://github.com/node-saml/passport-saml/pull/504)
- minor - fix typo in README [#506](https://github.com/node-saml/passport-saml/pull/506)

---

## v2.0.2 (2020-11-05)

_No changelog for this release._

---

## v2.0.1 (2020-11-03)

_No changelog for this release._

---

## v2.0.0 (2020-11-03)

#### 🚀 Minor Changes:

- feat(authorize-request): idp scoping provider [#428](https://github.com/node-saml/passport-saml/pull/428)

#### 🐛 Bug Fixes:

- update version of xml2js to 0.4.23, fixes #479 [#486](https://github.com/node-saml/passport-saml/pull/486)

---

## v1.5.0 (2020-10-30)

#### 🚀 Minor Changes:

- validateSignature: Support XML docs that contain multiple signed nodes [#455](https://github.com/node-saml/passport-saml/pull/455)

#### ⚙️ Technical Tasks:

- outdated Q library was removed [#478](https://github.com/node-saml/passport-saml/pull/478)

---

## v1.4.2 (2020-10-29)

#### ⚙️ Technical Tasks:

- Primary files use typescript [#477](https://github.com/node-saml/passport-saml/pull/477)

---

## v1.4.1 (2020-10-29)

_No changelog for this release._

---

## v1.4.0 (2020-10-28)

#### ⚙️ Technical Tasks:

- support typescript compilation [#469](https://github.com/node-saml/passport-saml/pull/469)

---

## v1.3.5 (2020-09-16)

_No changelog for this release._

---

## v1.3.4 (2020-07-21)

_No changelog for this release._

---

## v1.3.3 (2020-02-19)

_No changelog for this release._

---

## v1.3.2 (2020-02-12)

_No changelog for this release._

---

## v1.3.1 (2020-02-11)

_No changelog for this release._

---

## v1.3.0 (2020-02-06)

#### 🚀 Minor Changes:

- add support for encrypted nameIDs in SLO request handling [#408](https://github.com/node-saml/passport-saml/pull/408)
- Issue #206: Support signing AuthnRequests using the HTTP-POST Binding [#207](https://github.com/node-saml/passport-saml/pull/207)
- convert privateCert to PEM for signing [#390](https://github.com/node-saml/passport-saml/pull/390)

---

## v1.2.0 (2019-09-12)

_No changelog for this release._

---

## v1.1.0 (2019-05-10)

#### 🚀 Minor Changes:

- feat: add RequestedAuthnContext Comparison Type parameter [#360](https://github.com/node-saml/passport-saml/pull/360)
- Add option to disable SAML spec AuthnRequest optional value Assertion… [#315](https://github.com/node-saml/passport-saml/pull/315)

---

## v1.0.0 (2018-12-02)

#### 💣 Major Changes:

- Adds signing key in the metadata service provider generation. [#306](https://github.com/node-saml/passport-saml/pull/306)

#### 🚀 Minor Changes:

- Support dynamic SAML configuration lookup [#276](https://github.com/node-saml/passport-saml/pull/276)
- Support redirect for Logout flows [#277](https://github.com/node-saml/passport-saml/pull/277)

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

_No changelog for this release._

---

## v0.31.0 (2017-11-01)

#### 🚀 Minor Changes:

- Support multiple and dynamic signing certificates [#218](https://github.com/node-saml/passport-saml/pull/218)

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

## v0.14.0 (2015-11-01)

_No changelog for this release._

---

## v0.13.0 (2015-10-09)

_No changelog for this release._

---

## v0.12.0 (2015-08-18)

_No changelog for this release._

---

## v0.11.1 (2015-08-18)

_No changelog for this release._

---

## v0.11.0 (2015-08-10)

_No changelog for this release._

---

## v0.10.0 (2015-06-07)

_No changelog for this release._

---

## v0.9.2 (2015-04-25)

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

## v0.7.0 (2015-01-12)

_No changelog for this release._

---

## v0.6.2 (2015-01-05)

_No changelog for this release._

---

## v0.6.1 (2014-12-18)

_No changelog for this release._

---

## v0.6.0 (2014-11-13)

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

## v0.2.1 (2014-06-04)

_No changelog for this release._

---

## v0.2.0 (2014-06-02)

_No changelog for this release._

---

## v0.1.0 (2014-05-30)

_No changelog for this release._
