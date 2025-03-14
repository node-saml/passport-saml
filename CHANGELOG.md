# Changelog

## 5.0.1 (2025-03-14)

#### 🔗 Dependencies

- [**github_actions**] Bump github/codeql-action from 2 to 3 [#902](https://github.com/node-saml/passport-saml/pull/902)

#### 🐛 Bug Fixes

- [**security**] Update node-saml/xml-crypto to address CVE [#953](https://github.com/node-saml/passport-saml/pull/953)

#### 📚 Documentation

- Update README.md to reflect updated node-saml [#945](https://github.com/node-saml/passport-saml/pull/945)

---

## v5.0.0 (2024-03-27)

#### 💣 Major Changes

- Update major versions of dependencies [#896](https://github.com/node-saml/passport-saml/pull/896)
- Update to @node-saml/node-saml v5 [#894](https://github.com/node-saml/passport-saml/pull/894)
- Update to Node 18 [#893](https://github.com/node-saml/passport-saml/pull/893)
- Clean up types [#813](https://github.com/node-saml/passport-saml/pull/813)

#### 🚀 Minor Changes

- Update minor dependencies [#895](https://github.com/node-saml/passport-saml/pull/895)

#### 🔗 Dependencies

- Update nested dependencies [#898](https://github.com/node-saml/passport-saml/pull/898)
- Update prettier [#897](https://github.com/node-saml/passport-saml/pull/897)

#### 🐛 Bug Fixes

- Fix circular references #879 [#880](https://github.com/node-saml/passport-saml/pull/880)
- [**needs-review**] StrategyOptionsCallback shouldn't have to pass all SAML options [#838](https://github.com/node-saml/passport-saml/pull/838)

#### 📚 Documentation

- Fix README to require correct module name [#884](https://github.com/node-saml/passport-saml/pull/884)
- Update README to point to `node-saml` documentation [#886](https://github.com/node-saml/passport-saml/pull/886)
- Clarify SLO support in `passport-saml` [#862](https://github.com/node-saml/passport-saml/pull/862)
- Roll-up changelog entries for beta releases [#867](https://github.com/node-saml/passport-saml/pull/867)

#### ⚙️ Technical Tasks

- Adjust type enforcement to remove warnings [#889](https://github.com/node-saml/passport-saml/pull/889)
- Update `package.json` script to mirror `node-saml` [#888](https://github.com/node-saml/passport-saml/pull/888)
- Remove unused `AuthorizeOptions` type [#887](https://github.com/node-saml/passport-saml/pull/887)
- Add bot to close stale issues [#864](https://github.com/node-saml/passport-saml/pull/864)

---

## v4.0.4 (2023-05-30)

#### 🐛 Bug Fixes

- Revised AbstractStrategy for authenticate method to match PassportStrategy expectation [#861](https://github.com/node-saml/passport-saml/pull/861)

#### 📚 Documentation

- Update docs/adfs/README.md and move to wiki [#840](https://github.com/node-saml/passport-saml/pull/840)

---

## v4.0.3 (2023-04-11)

#### 🔗 Dependencies

- [**security**] Use secure version of node-saml [#855](https://github.com/node-saml/passport-saml/pull/855)

#### 📚 Documentation

- Fix minor typos [#853](https://github.com/node-saml/passport-saml/pull/853)

---

## v4.0.2 (2022-12-13)

#### 🔗 Dependencies

- [**javascript**] Bump eslint from 8.26.0 to 8.29.0 [#827](https://github.com/node-saml/passport-saml/pull/827)
- [**javascript**] Bump @typescript-eslint/parser from 5.41.0 to 5.46.1 [#826](https://github.com/node-saml/passport-saml/pull/826)
- [**javascript**] Bump @xmldom/xmldom from 0.8.3 to 0.8.6 [#825](https://github.com/node-saml/passport-saml/pull/825)
- [**javascript**] Bump prettier from 2.7.1 to 2.8.0 [#821](https://github.com/node-saml/passport-saml/pull/821)
- [**javascript**] Bump @types/node from 14.18.33 to 14.18.34 [#819](https://github.com/node-saml/passport-saml/pull/819)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.41.0 to 5.45.0 [#818](https://github.com/node-saml/passport-saml/pull/818)

#### 📚 Documentation

- Reference `node-saml` documentation from README [#815](https://github.com/node-saml/passport-saml/pull/815)
- Update README formatting and to provide clearer explanation of examples [#812](https://github.com/node-saml/passport-saml/pull/812)
- Update README.md [#810](https://github.com/node-saml/passport-saml/pull/810)

---

## v4.0.1 (2022-10-28)

#### 📚 Documentation

- Update changelog [#797](https://github.com/node-saml/passport-saml/pull/797)

---

## v4.0.0 (2022-10-28)

#### 💣 Major Changes

- deps: use node-saml v4.  See node-saml changelog for breaking changes: https://github.com/node-saml/node-saml/blob/master/CHANGELOG.md#v400-2022-10-28 [#796](https://github.com/node-saml/passport-saml/pull/796)
- Update node-saml to beta 5 -- See node-saml changelog for breaking changes [#783](https://github.com/node-saml/passport-saml/pull/783)
- Update node-saml dependency [#770](https://github.com/node-saml/passport-saml/pull/770)
- Update to support node-saml@4.0.0-beta.3 [#707](https://github.com/node-saml/passport-saml/pull/707)
- Update passport to 0.6.x -- See passport changelog for breaking changes [#698](https://github.com/node-saml/passport-saml/pull/698)
- Update packages; set minimum Node to 14 [#685](https://github.com/node-saml/passport-saml/pull/685)
- [**security**] Check user matches logout request before reporting logout success [#619](https://github.com/node-saml/passport-saml/pull/619)
- Remove `node-saml` code and use an import instead [#612](https://github.com/node-saml/passport-saml/pull/612)

#### 🚀 Minor Changes

- Add support for multiple signing certs in metadata [#655](https://github.com/node-saml/passport-saml/pull/655)

#### 🔗 Dependencies

- [**javascript**] Bump @xmldom/xmldom from 0.7.5 to 0.7.6 [#794](https://github.com/node-saml/passport-saml/pull/794)
- [**javascript**] Bump @types/mocha from 9.1.1 to 10.0.0 [#781](https://github.com/node-saml/passport-saml/pull/781)
- [**javascript**] Bump @types/express from 4.17.13 to 4.17.14 [#785](https://github.com/node-saml/passport-saml/pull/785)
- [**javascript**] Bump @types/chai from 4.3.1 to 4.3.3 [#787](https://github.com/node-saml/passport-saml/pull/787)
- [**javascript**] Bump @typescript-eslint/parser from 5.36.2 to 5.40.0 [#786](https://github.com/node-saml/passport-saml/pull/786)
- [**javascript**] Bump eslint from 8.23.0 to 8.25.0 [#784](https://github.com/node-saml/passport-saml/pull/784)
- [**github_actions**] Bump codecov/codecov-action from 3.1.0 to 3.1.1 [#782](https://github.com/node-saml/passport-saml/pull/782)
- [**javascript**] Bump @types/passport from 1.0.10 to 1.0.11 [#778](https://github.com/node-saml/passport-saml/pull/778)
- [**javascript**] Bump vm2 from 3.9.9 to 3.9.11 [#777](https://github.com/node-saml/passport-saml/pull/777)
- [**javascript**] Bump concurrently from 7.3.0 to 7.4.0 [#773](https://github.com/node-saml/passport-saml/pull/773)
- [**javascript**] Bump @types/node from 14.18.22 to 14.18.28 [#772](https://github.com/node-saml/passport-saml/pull/772)
- [**javascript**] Bump @types/passport from 1.0.9 to 1.0.10 [#771](https://github.com/node-saml/passport-saml/pull/771)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.7 to 5.36.2 [#766](https://github.com/node-saml/passport-saml/pull/766)
- [**javascript**] Bump eslint from 8.20.0 to 8.23.0 [#759](https://github.com/node-saml/passport-saml/pull/759)
- [**javascript**] Bump @typescript-eslint/parser from 5.30.7 to 5.36.2 [#767](https://github.com/node-saml/passport-saml/pull/767)
- [**javascript**] Bump concurrently from 7.2.2 to 7.3.0 [#741](https://github.com/node-saml/passport-saml/pull/741)
- [**javascript**] Bump @types/node from 14.18.21 to 14.18.22 [#740](https://github.com/node-saml/passport-saml/pull/740)
- [**javascript**] Bump @typescript-eslint/parser from 5.30.5 to 5.30.7 [#737](https://github.com/node-saml/passport-saml/pull/737)
- [**javascript**] Bump eslint from 8.19.0 to 8.20.0 [#736](https://github.com/node-saml/passport-saml/pull/736)
- [**javascript**] Bump @types/sinon from 10.0.12 to 10.0.13 [#738](https://github.com/node-saml/passport-saml/pull/738)
- [**javascript**] Bump ts-node from 10.8.2 to 10.9.1 [#732](https://github.com/node-saml/passport-saml/pull/732)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.5 to 5.30.7 [#739](https://github.com/node-saml/passport-saml/pull/739)
- [**javascript**] Bump parse-url from 6.0.0 to 6.0.2 [#730](https://github.com/node-saml/passport-saml/pull/730)
- [**javascript**] Bump @typescript-eslint/parser from 5.30.3 to 5.30.5 [#726](https://github.com/node-saml/passport-saml/pull/726)
- [**javascript**] Bump eslint-plugin-prettier from 4.0.0 to 4.2.1 [#722](https://github.com/node-saml/passport-saml/pull/722)
- [**javascript**] Bump eslint from 8.18.0 to 8.19.0 [#719](https://github.com/node-saml/passport-saml/pull/719)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.3 to 5.30.5 [#725](https://github.com/node-saml/passport-saml/pull/725)
- [**javascript**] Bump ts-node from 10.8.0 to 10.8.2 [#723](https://github.com/node-saml/passport-saml/pull/723)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.29.0 to 5.30.3 [#716](https://github.com/node-saml/passport-saml/pull/716)
- [**javascript**] Bump @types/sinon from 10.0.11 to 10.0.12 [#717](https://github.com/node-saml/passport-saml/pull/717)
- [**javascript**] Bump @typescript-eslint/parser from 5.29.0 to 5.30.3 [#718](https://github.com/node-saml/passport-saml/pull/718)
- [**github_actions**] Bump actions/checkout from 2 to 3 [#713](https://github.com/node-saml/passport-saml/pull/713)
- [**github_actions**] Bump github/codeql-action from 1 to 2 [#712](https://github.com/node-saml/passport-saml/pull/712)
- Update dependencies [#696](https://github.com/node-saml/passport-saml/pull/696)
- Bump follow-redirects from 1.14.4 to 1.15.1 [#695](https://github.com/node-saml/passport-saml/pull/695)
- Bump npm from 8.6.0 to 8.12.0 [#694](https://github.com/node-saml/passport-saml/pull/694)
- [**security**] Bump ansi-regex from 4.1.0 to 4.1.1 [#688](https://github.com/node-saml/passport-saml/pull/688)
- Move TypeScript-required types to dependencies from devDependencies [#686](https://github.com/node-saml/passport-saml/pull/686)
- Code cleanup in preparation for logout validation [#658](https://github.com/node-saml/passport-saml/pull/658)
- Update packages [#641](https://github.com/node-saml/passport-saml/pull/641)

#### 🐛 Bug Fixes

- add MultiStrategyConfig type export [#675](https://github.com/node-saml/passport-saml/pull/675)

#### 📚 Documentation

- Update changelog and changelog building tools [#774](https://github.com/node-saml/passport-saml/pull/774)
- Update badges for scoped package [#710](https://github.com/node-saml/passport-saml/pull/710)
- Update badges for scoped package [#709](https://github.com/node-saml/passport-saml/pull/709)
- docs: move history note to the bottom and expand it. [#708](https://github.com/node-saml/passport-saml/pull/708)
- Update README to remove an insecure suggestion [#704](https://github.com/node-saml/passport-saml/pull/704)
- Document passive option [#660](https://github.com/node-saml/passport-saml/pull/660)
- Read me update for authnContext example for ADFS [#647](https://github.com/node-saml/passport-saml/pull/647)

#### ⚙️ Technical Tasks

- Clean working folder before doing a release build [#793](https://github.com/node-saml/passport-saml/pull/793)
- Update changelog build tools [#792](https://github.com/node-saml/passport-saml/pull/792)
- Add prerelease script [#775](https://github.com/node-saml/passport-saml/pull/775)
- Reduce dependabot update frequency [#765](https://github.com/node-saml/passport-saml/pull/765)
- Have dependabot update package.json too [#764](https://github.com/node-saml/passport-saml/pull/764)
- Have dependabot update package.json too [#724](https://github.com/node-saml/passport-saml/pull/724)
- Add dependabot config file [#711](https://github.com/node-saml/passport-saml/pull/711)
- Move to NPM organization [#705](https://github.com/node-saml/passport-saml/pull/705)
- Add code coverage workflow [#706](https://github.com/node-saml/passport-saml/pull/706)
- Replace integration tests with unit tests [#702](https://github.com/node-saml/passport-saml/pull/702)
- Add code coverage [#701](https://github.com/node-saml/passport-saml/pull/701)
- Adjust .mochars.json [#699](https://github.com/node-saml/passport-saml/pull/699)
- Migrate from "should" to "chai" [#687](https://github.com/node-saml/passport-saml/pull/687)
- Update issue templates [#652](https://github.com/node-saml/passport-saml/pull/652)
- Fix main path in package.json [#623](https://github.com/node-saml/passport-saml/pull/623)

---

## v3.1.0 (2021-06-17)

#### 🐛 Bug Fixes

- [**security**] Limit transforms for signed nodes [#595](https://github.com/node-saml/passport-saml/pull/595)
- Fix: Conflicting profile properties between profile and attributes [#593](https://github.com/node-saml/passport-saml/pull/593)
- Fix validateInResponseTo null check [#596](https://github.com/node-saml/passport-saml/pull/596)

#### 📚 Documentation

- Rebuild changelog for 3.0.0 [#605](https://github.com/node-saml/passport-saml/pull/605)
- Fix typo OnBefore -> NotBefore [#611](https://github.com/node-saml/passport-saml/pull/611)
- Update README with new Cache Provider interface [#608](https://github.com/node-saml/passport-saml/pull/608)

---

## v3.0.0 (2021-05-14)

#### 💣 Major Changes

- Update all dependencies to latest [#590](https://github.com/node-saml/passport-saml/pull/590)
- Add Node 16 support; drop Node 10 [#589](https://github.com/node-saml/passport-saml/pull/589)
- Enforce more secure XML encryption [#584](https://github.com/node-saml/passport-saml/pull/584)
- Node saml separation [#574](https://github.com/node-saml/passport-saml/pull/574)
- Remove support for deprecated `privateCert` [#569](https://github.com/node-saml/passport-saml/pull/569)
- Require cert for every strategy [#548](https://github.com/node-saml/passport-saml/pull/548)

#### 🚀 Minor Changes

- Add optional setting to set a ceiling on how old a SAML response is allowed to be [#577](https://github.com/node-saml/passport-saml/pull/577)
- Move XML functions to utility module [#571](https://github.com/node-saml/passport-saml/pull/571)
- Improve the typing of the Strategy class hierarchy. [#554](https://github.com/node-saml/passport-saml/pull/554)
- Resolve XML-encoded carriage returns during signature validation [#576](https://github.com/node-saml/passport-saml/pull/576)
- Make sure CI builds test latest versions of dependencies [#570](https://github.com/node-saml/passport-saml/pull/570)
- Add WantAssertionsSigned [#536](https://github.com/node-saml/passport-saml/pull/536)
- Update xml-crypto to v2.1.1 [#558](https://github.com/node-saml/passport-saml/pull/558)
- Allow for authnRequestBinding in SAML options [#529](https://github.com/node-saml/passport-saml/pull/529)

#### 🔗 Dependencies

- Update all packages to latest semver-minor [#588](https://github.com/node-saml/passport-saml/pull/588)
- Update xml-encryption to v1.2.3 [#567](https://github.com/node-saml/passport-saml/pull/567)
- Revert "Update xml-encryption to v1.2.3" [#564](https://github.com/node-saml/passport-saml/pull/564)
- Update xml-encryption to v1.2.3 [#560](https://github.com/node-saml/passport-saml/pull/560)
- bump xmldom to 0.5.x since all lower versions have security issue [#551](https://github.com/node-saml/passport-saml/pull/551)

#### 🐛 Bug Fixes

- Fix incorrect import of compiled files in tests [#572](https://github.com/node-saml/passport-saml/pull/572)

#### 📚 Documentation

- Remove deprecated field `privateCert` from README, tests [#591](https://github.com/node-saml/passport-saml/pull/591)
- Add support for more tags in the changelog [#592](https://github.com/node-saml/passport-saml/pull/592)
- Changelog [#587](https://github.com/node-saml/passport-saml/pull/587)
- Create of Code of Conduct [#573](https://github.com/node-saml/passport-saml/pull/573)
- Update readme on using multiSamlStrategy [#531](https://github.com/node-saml/passport-saml/pull/531)

#### ⚙️ Technical Tasks

- Fix lint npm script to match all files including in src/ [#555](https://github.com/node-saml/passport-saml/pull/555)
- remove old callback functions, tests use async/await [#545](https://github.com/node-saml/passport-saml/pull/545)
- Tests use typescript [#534](https://github.com/node-saml/passport-saml/pull/534)
- async / await in cache interface [#532](https://github.com/node-saml/passport-saml/pull/532)
- Format code and enforce code style on PR [#527](https://github.com/node-saml/passport-saml/pull/527)
- async/await for saml.ts [#496](https://github.com/node-saml/passport-saml/pull/496)

---

## v2.0.5 (2021-01-29)

#### ⚙️ Technical Tasks

- Ignore `test` folder when building npm package [#526](https://github.com/node-saml/passport-saml/pull/526)

---

## v2.0.4 (2021-01-19)

#### ⚙️ Technical Tasks

- Generating changelog using gren [#518](https://github.com/node-saml/passport-saml/pull/518)

---

## v2.0.3 (2020-12-21)

#### 🚀 Minor Changes

- dev: add @types/xml-encryption [#517](https://github.com/node-saml/passport-saml/pull/517)

#### 🔗 Dependencies

- upgrade deps to latest versions [#514](https://github.com/node-saml/passport-saml/pull/514)
- Bump ini from 1.3.5 to 1.3.8 [#513](https://github.com/node-saml/passport-saml/pull/513)

#### 🐛 Bug Fixes

- Reexport SamlConfig type to solve a regression in consumer packages [#516](https://github.com/node-saml/passport-saml/pull/516)
- normalize signature line endings before loading signature block to xml-crypto [#512](https://github.com/node-saml/passport-saml/pull/512)
- fix: derive SamlConfig from SAMLOptions [#515](https://github.com/node-saml/passport-saml/pull/515)
- fix(typing): Export Multi SAML types [#505](https://github.com/node-saml/passport-saml/pull/505)
- add ts-ignore to generated type definitions for multisaml strategy [#508](https://github.com/node-saml/passport-saml/pull/508)
- fix(typing): multi saml strategy export [#503](https://github.com/node-saml/passport-saml/pull/503)
- support windows line breaks in keys [#500](https://github.com/node-saml/passport-saml/pull/500)

#### 📚 Documentation

- docs(scoping): fix for example [#504](https://github.com/node-saml/passport-saml/pull/504)
- minor - fix typo in README [#506](https://github.com/node-saml/passport-saml/pull/506)

#### ⚙️ Technical Tasks

- Prettier + ESLint + onchange = Happiness [#493](https://github.com/node-saml/passport-saml/pull/493)

---

## v2.0.2 (2020-11-05)

#### 🐛 Bug Fixes

- normalize line endings before signature validation [#498](https://github.com/node-saml/passport-saml/pull/498)

---

## v2.0.1 (2020-11-03)

#### 🐛 Bug Fixes

- Add deprecation notice for privateCert; fix bug [#492](https://github.com/node-saml/passport-saml/pull/492)

---

## v2.0.0 (2020-11-03)

#### 💣 Major Changes

- Always throw error objects instead of strings [#412](https://github.com/node-saml/passport-saml/pull/412)

#### 🚀 Minor Changes

- Allow for use of privateKey instead of privateCert [#488](https://github.com/node-saml/passport-saml/pull/488)
- feat(authorize-request): idp scoping provider [#428](https://github.com/node-saml/passport-saml/pull/428)

#### 🐛 Bug Fixes

- update version of xml2js to 0.4.23, fixes #479 [#486](https://github.com/node-saml/passport-saml/pull/486)
- fix: disable esmoduleInterop setting [#483](https://github.com/node-saml/passport-saml/pull/483)

#### ⚙️ Technical Tasks

- inlineSources option for better source maps [#487](https://github.com/node-saml/passport-saml/pull/487)

---

## v1.5.0 (2020-10-29)

#### 🚀 Minor Changes

- validateSignature: Support XML docs that contain multiple signed node… [#481](https://github.com/node-saml/passport-saml/pull/481)
- validateSignature: Support XML docs that contain multiple signed nodes [#455](https://github.com/node-saml/passport-saml/pull/455)

#### 🐛 Bug Fixes

- Revert "validateSignature: Support XML docs that contain multiple signed nodes" [#480](https://github.com/node-saml/passport-saml/pull/480)

#### ⚙️ Technical Tasks

- outdated Q library was removed [#478](https://github.com/node-saml/passport-saml/pull/478)

---

## v1.4.2 (2020-10-29)

#### ⚙️ Technical Tasks

- Primary files use typescript [#477](https://github.com/node-saml/passport-saml/pull/477)

---

## v1.4.1 (2020-10-29)

#### ⚙️ Technical Tasks

- compatibility with @types/passport-saml, fixes #475 [#476](https://github.com/node-saml/passport-saml/pull/476)

---

## v1.4.0 (2020-10-28)

#### 💣 Major Changes

- Drop support for Node 8 [#462](https://github.com/node-saml/passport-saml/pull/462)

#### 🚀 Minor Changes

- try to use curl when wget is not available [#468](https://github.com/node-saml/passport-saml/pull/468)

#### 🔗 Dependencies

- bumped xml-crypto from 1.5.3 to 2.0.0 [#470](https://github.com/node-saml/passport-saml/pull/470)
- Upgrade xml-crypto dependency [#465](https://github.com/node-saml/passport-saml/pull/465)

#### 🐛 Bug Fixes

- Only make an attribute an object if it has child elements [#464](https://github.com/node-saml/passport-saml/pull/464)
- fix: add catch block to NameID decryption [#461](https://github.com/node-saml/passport-saml/pull/461)

#### 📚 Documentation

- Add PR template [#473](https://github.com/node-saml/passport-saml/pull/473)
- Fix typo [#434](https://github.com/node-saml/passport-saml/pull/434)

#### ⚙️ Technical Tasks

- Ts secondary files [#474](https://github.com/node-saml/passport-saml/pull/474)
- support typescript compilation [#469](https://github.com/node-saml/passport-saml/pull/469)
- Add GitHub Actions as Continuos Integration provider [#463](https://github.com/node-saml/passport-saml/pull/463)

---

## v1.3.5 (2020-09-16)

#### 🚀 Minor Changes

- Return object for XML-valued AttributeValues [#447](https://github.com/node-saml/passport-saml/pull/447)

#### 🔗 Dependencies

- Bump lodash from 4.17.15 to 4.17.20 [#449](https://github.com/node-saml/passport-saml/pull/449)
- Bump acorn from 7.1.0 to 7.4.0 [#448](https://github.com/node-saml/passport-saml/pull/448)

#### 📚 Documentation

- Revert "doc: announce site move." [#446](https://github.com/node-saml/passport-saml/pull/446)

---

## v1.3.4 (2020-07-21)

#### 🐛 Bug Fixes

- Fix multi saml strategy race conditions [#426](https://github.com/node-saml/passport-saml/pull/426)

---

## v1.3.3 (2020-02-19)

#### 🙈 Other

- Singleline private keys [#423](https://github.com/node-saml/passport-saml/pull/423)

---

## v1.3.2 (2020-02-12)

#### 🙈 Other

- Revert "convert privateCert to PEM for signing" [#421](https://github.com/node-saml/passport-saml/pull/421)

---

## v1.3.1 (2020-02-11)

#### 🙈 Other

- Upgrade xml-encryption to 1.0.0 [#420](https://github.com/node-saml/passport-saml/pull/420)

---

## v1.3.0 (2020-01-28)

#### 🚀 Minor Changes

- convert privateCert to PEM for signing [#390](https://github.com/node-saml/passport-saml/pull/390)
- add support for encrypted nameIDs in SLO request handling [#408](https://github.com/node-saml/passport-saml/pull/408)
- Issue #206: Support signing AuthnRequests using the HTTP-POST Binding [#207](https://github.com/node-saml/passport-saml/pull/207)

#### 🙈 Other

- Add tests to check for correct logout [#418](https://github.com/node-saml/passport-saml/pull/418)
- added passReqToCallback to docs [#417](https://github.com/node-saml/passport-saml/pull/417)
- Fix an issue readme formatting [#416](https://github.com/node-saml/passport-saml/pull/416)
- attributeConsumingServiceIndex can be zero [#414](https://github.com/node-saml/passport-saml/pull/414)
- Bring-up xml-crypto to 1.4.0 [#400](https://github.com/node-saml/passport-saml/pull/400)
- fix #393 adding 'inResponseTo' in the profile [#404](https://github.com/node-saml/passport-saml/pull/404)
- Fix #355 missing parts: tests. [#402](https://github.com/node-saml/passport-saml/pull/402)
- Fix minimum version of Node.js in Travis [#399](https://github.com/node-saml/passport-saml/pull/399)
- Add .editorconfig as suggested in #373 [#398](https://github.com/node-saml/passport-saml/pull/398)

---

## v1.2.0 (2019-07-26)

#### 🙈 Other

- NameIDFormat fix [#375](https://github.com/node-saml/passport-saml/pull/375)
- Remove InResponseTo value if response validation fails [#341](https://github.com/node-saml/passport-saml/pull/341)

---

## v1.1.0 (2019-05-10)

#### 🚀 Minor Changes

- feat: add RequestedAuthnContext Comparison Type parameter [#360](https://github.com/node-saml/passport-saml/pull/360)
- Add option to disable SAML spec AuthnRequest optional value Assertion… [#315](https://github.com/node-saml/passport-saml/pull/315)

#### 🙈 Other

- Fix broken tests [#367](https://github.com/node-saml/passport-saml/pull/367)
- Update README.md [#363](https://github.com/node-saml/passport-saml/pull/363)
- InResponseTo support for logout [#356](https://github.com/node-saml/passport-saml/pull/356)
- Set explicitChar: true to make XML parsing consistent. Fixes issue #283 and #187 [#361](https://github.com/node-saml/passport-saml/pull/361)
- update xml crypto to 1.1.4 [#352](https://github.com/node-saml/passport-saml/pull/352)
- Create a way to get provider metadata when using the MultiSamlStrategy [#323](https://github.com/node-saml/passport-saml/pull/323)
- Fix Node Buffer deprecation warning: update 'new Buffer' to 'Buffer.from()' [#342](https://github.com/node-saml/passport-saml/pull/342)
- Fix #128 documentation for body-parser dependency [#326](https://github.com/node-saml/passport-saml/pull/326)
- Update Node version in package.json to >=6 [#340](https://github.com/node-saml/passport-saml/pull/340)
- Upgrade xml-crypto to 1.1.2 [#344](https://github.com/node-saml/passport-saml/pull/344)
- Fix for failing test [#347](https://github.com/node-saml/passport-saml/pull/347)
- Support InResponseTo validations in MultiSaml [#350](https://github.com/node-saml/passport-saml/pull/350)
- Add SamlResponseXML method to profile object [#330](https://github.com/node-saml/passport-saml/pull/330)

---

## v1.0.0 (2018-12-02)

#### 💣 Major Changes

- Adds signing key in the metadata service provider generation. [#306](https://github.com/node-saml/passport-saml/pull/306)

#### 🚀 Minor Changes

- Support redirect for Logout flows [#277](https://github.com/node-saml/passport-saml/pull/277)
- Support dynamic SAML configuration lookup [#276](https://github.com/node-saml/passport-saml/pull/276)

#### 🙈 Other

- Update xml-crypto to 1.0.2 [#321](https://github.com/node-saml/passport-saml/pull/321)
- Validate issuer on logout requests/responses if configured [#314](https://github.com/node-saml/passport-saml/pull/314)
- feat(logout): handle null and undefined on nameQualifier [#311](https://github.com/node-saml/passport-saml/pull/311)
- Extend and document the profile object [#301](https://github.com/node-saml/passport-saml/pull/301)
- Handle case of missing InResponseTo when validation is on [#302](https://github.com/node-saml/passport-saml/pull/302)
- entryPoint is compulsory for signed requests [#299](https://github.com/node-saml/passport-saml/pull/299)
- Include support for run-time params to be included in the generated URLs [#136](https://github.com/node-saml/passport-saml/pull/136)
- support multiple authnContext [#298](https://github.com/node-saml/passport-saml/pull/298)

---

## v0.35.0 (2018-08-14)

_No changelog for this release._

---

## v0.34.0 (2018-08-14)

_No changelog for this release._

---

## v0.33.0 (2018-02-16)

#### 🙈 Other

- New Feature: allow customizing the name of the strategy. [#262](https://github.com/node-saml/passport-saml/pull/262)

---

## v0.32.1 (2018-01-03)

_No changelog for this release._

---

## v0.32.0 (2018-01-03)

#### 🙈 Other

- Audience validation [#253](https://github.com/node-saml/passport-saml/pull/253)
- README: fix typo `s/ADSF/ADFS/` [#251](https://github.com/node-saml/passport-saml/pull/251)

---

## v0.31.0 (2017-11-01)

#### 🚀 Minor Changes

- Support multiple and dynamic signing certificates [#218](https://github.com/node-saml/passport-saml/pull/218)

#### 🙈 Other

- Upd: Mention ADFS 2016 with NameIDFormatError. [#242](https://github.com/node-saml/passport-saml/pull/242)

---

## v0.30.0 (2017-10-12)

#### 🐛 Bug Fixes

- [**security**] Use crypto.randomBytes for ID generation [#235](https://github.com/node-saml/passport-saml/pull/235)
- Fix: "TypeError: Cannot read property 'documentElement' of null" [#239](https://github.com/node-saml/passport-saml/pull/239)

---

## v0.20.2 (2017-10-10)

_No changelog for this release._

---

## v0.20.1 (2017-10-10)

#### 🙈 Other

- handle bad privateCert [#231](https://github.com/node-saml/passport-saml/pull/231)
- Add support for ProviderName attribute [#216](https://github.com/node-saml/passport-saml/pull/216)

---

## v0.20.0 (2017-10-09)

#### 🙈 Other

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

#### 🙈 Other

- Remove unused ejs package from devDeps [#195](https://github.com/node-saml/passport-saml/pull/195)
- Add the ability to sign with SHA-512 [#173](https://github.com/node-saml/passport-saml/pull/173)
- Support detached encrypted key [#166](https://github.com/node-saml/passport-saml/pull/166)
- Fixes #170: Clarify that the certificate are looking for is: [#171](https://github.com/node-saml/passport-saml/pull/171)

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
