# Changelog

## v2.0.3 (07/01/2021)
- [Generating changelog using gren](https://github.com/node-saml/passport-saml/commit/9bc09b97063b10be3e323e18523e8de453332d6d) - @gugu
- [Reexport SamlConfig type to solve a regression in consumer packages (#516)](https://github.com/node-saml/passport-saml/commit/c61cbad96c742ebde36f2b4fff2408675e6f30b6) - @carboneater
- [dev: add @types/xml-encryption](https://github.com/node-saml/passport-saml/commit/51a154cd142fff7c932352ffcbf0825f38343cf8) - @midgleyc
- [normalize signature line endings before loading signature block to xml-crypto (#512)](https://github.com/node-saml/passport-saml/commit/915b31da2a2785835065bf9e8db3c7dadcfcd3fc) - @mhassan1
- [fix: derive SamlConfig from SAMLOptions (#515)](https://github.com/node-saml/passport-saml/commit/29d997f48700b0b56e9f270e35a85f792afaeaad) - @midgleyc
- [fix(typing): Export Multi SAML types (#505)](https://github.com/node-saml/passport-saml/commit/cfd08b6c0e74dbb2208a50b131cd76fc219ee85a) - @echojoshchen
- [docs(scoping): fix for example (#504)](https://github.com/node-saml/passport-saml/commit/f6329ea505a6e6d07eb682270565ab6395832a59) - @rob-gijsens
- [upgrade deps to latest versions](https://github.com/node-saml/passport-saml/commit/28e481cc1ef86a16bdbddb2f074b475e051c910f) - @gugu
- [Bump ini from 1.3.5 to 1.3.8](https://github.com/node-saml/passport-saml/commit/f004897d641fb76c25cb8459a4e7677373a5b58c) - @dependabot[bot]
- [run tsc when package is installed as github dependency](https://github.com/node-saml/passport-saml/commit/f515f5ed0972a3c3e46ed0236ce048f0f703f83f) - @gugu
- [add ts-ignore to generated type definitions for multisaml strategy](https://github.com/node-saml/passport-saml/commit/4dcef6b161d8627f4334193e14867972fc6f8432) - @gugu
- [Fix typo in README (#506)](https://github.com/node-saml/passport-saml/commit/9c9c53d9d3f93caeb3721031860aea9f7cba3108) - @oakmac
- [fix(typing): multi saml stratey export (#503)](https://github.com/node-saml/passport-saml/commit/c5ceaca215591a7ce1009661ef48cdc64beba624) - @rob-gijsens
- [Add support for prettier + eslint + watcher (#493)](https://github.com/node-saml/passport-saml/commit/33385164c3c0c19daf6397651db958243df7d7b5) - @cjbarth

---

## v2.0.2 (05/11/2020)
- [Release 2.0.2](https://github.com/node-saml/passport-saml/commit/711956c717d7f843638b35431026adc6d365f010) - @markstos
- [chore: release-it Github Release support.](https://github.com/node-saml/passport-saml/commit/02f3e0996fba1a645c4ea4ea295c1e5da8595f22) - @markstos
- [chore: bump version in package-lock.json](https://github.com/node-saml/passport-saml/commit/0da87a2aef524152f00148459fe9ad25fd260ee0) - @markstos
- [deps: add release-it dev dep](https://github.com/node-saml/passport-saml/commit/dc1f2f04f80c1cb8bbfc107b6bde7c3e10f071d7) - @markstos

---

## v2.0.1 (03/11/2020)
- [v2.0.1](https://github.com/node-saml/passport-saml/commit/b349e4b3c5136c478b4183d617a698300fef9681) - @markstos

---

## v2.0.0 (03/11/2020)
- [v2.0.0](https://github.com/node-saml/passport-saml/commit/be111f3a231fe917bfe42104e42a952bfc843ebe) - @markstos
- [add multiSamlStrategy.d.ts to the package](https://github.com/node-saml/passport-saml/commit/13b491cdeb97a284d47ae997e50a1cd845b9e65b) - @gugu
- [add multiSamlStrategy.d.ts to exclude for typescript](https://github.com/node-saml/passport-saml/commit/b2d5b0ba2bb9c7ffa2d6d524993e8b1a995c3a46) - @gugu
- [code style](https://github.com/node-saml/passport-saml/commit/bfcff604b7ed43db42d024a1eb8e5ce642776c09) - @gugu
- [as Node[] => as Attr[] in xpath response](https://github.com/node-saml/passport-saml/commit/4382bea7d30f1904f579a5d6a45319852939d714) - @gugu
- [strict TS types, Strategy and MultiSamlStrategy use native classes](https://github.com/node-saml/passport-saml/commit/0a9255f13d61142d314d03b8ec194ea86669785c) - @gugu
- [v1.5.0](https://github.com/node-saml/passport-saml/commit/29abcb8c2b2c035b2af30f23030f5edc7d5ebb46) - @markstos
- [Allow for use of privateKey instead of privateCert (#488)](https://github.com/node-saml/passport-saml/commit/8046db027e8172be63ba488d1d42b1b48ade67a5) - @alon85
- [inlineSources option for better source maps (#487)](https://github.com/node-saml/passport-saml/commit/0f1a414eac62c0d7b4db1b9e14a95ba1d0bee741) - @gugu
- [Always throw error objects instead of strings (#412)](https://github.com/node-saml/passport-saml/commit/86781395c9c38dd75cbc98aaa562de8a95c225b5) - @Gekkio
- [feat(authorize-request): idp scoping provider (#428)](https://github.com/node-saml/passport-saml/commit/a11ad61841f3cf7d5f3c2195e225329598dc11b5) - @rob-gijsens
- [update version of xml2js to 0.4.23, fixes #479](https://github.com/node-saml/passport-saml/commit/881208bbcd4d34ca4dc26aad3dd9be919cf9f2f2) - @gugu

---

## v1.5.0 (30/10/2020)
- [validateSignature: Support XML docs that contain multiple signed nodes. Only select the signatures which reference the currentNode. (#481)](https://github.com/node-saml/passport-saml/commit/7b71596d099302cd84313b229e4d6fc01e768527) - @vandernorth
- [Revert "validateSignature: Support XML docs that contain multiple signed nodes (#455)" (#480)](https://github.com/node-saml/passport-saml/commit/aa4fa868251bbc687e176e17254f9d37cf5056ba) - @cjbarth
- [validateSignature: Support XML docs that contain multiple signed nodes (#455)](https://github.com/node-saml/passport-saml/commit/43df9ad3bd38ddf759d240e580ba0f490cc1d166) - @vandernorth

---

## v1.4.2 (29/10/2020)
- [v1.4.2](https://github.com/node-saml/passport-saml/commit/4c14bea49d0aa87f6afd548be695fb3db1f453f8) - @markstos
- [primary files use typescript](https://github.com/node-saml/passport-saml/commit/decc5d64be8bd916981fc06d7dfe397444b21969) - @gugu

---

## v1.4.1 (29/10/2020)
- [v1.4.1](https://github.com/node-saml/passport-saml/commit/c226896cad3c5b00020beeae52ecd55564321846) - @markstos

---

## v1.4.0 (28/10/2020)
- [chore: version bump to 1.4.0](https://github.com/node-saml/passport-saml/commit/cc24d78d21c0a0d8d1d3ecf3c272e2618bb5509a) - @markstos
- [chore: Allow mocha globals in tests.](https://github.com/node-saml/passport-saml/commit/4e93c900fa04fa889ba332ba99ad08794f877fc3) - @markstos
- [fix returning value for signer](https://github.com/node-saml/passport-saml/commit/33caa06abbb60175aa2b6abec26bb2ffb7cc3d45) - @gugu
- [types for return values for algorithms](https://github.com/node-saml/passport-saml/commit/733e865404ab2bb142ffe527ba901d2d1ecafacc) - @gugu
- [add types to cache provider](https://github.com/node-saml/passport-saml/commit/7da6e8078a71b7a989abb72a0ede50d25f2c1652) - @gugu
- [migrated secondary files to typescript, add .d.ts and sourcemaps](https://github.com/node-saml/passport-saml/commit/19afcb24b0360d2f303742305fb750db548c08c5) - @gugu
- [chore: update package-lock.json, remove yarn.lock.](https://github.com/node-saml/passport-saml/commit/dc9eb8deb098b60b1e2a6cdb5a3b2af08c0eaad4) - @markstos
- [bumped xml-crypto from 1.5.3 to 2.0.0](https://github.com/node-saml/passport-saml/commit/104788ed40b7a9474335789eb6c82ccebed9c3a1) - @KeiferC
- [don't package src folder](https://github.com/node-saml/passport-saml/commit/c81a47cb61c065888887bc5f39a39b698ac60426) - @gugu
- [typescript: fix test running](https://github.com/node-saml/passport-saml/commit/8c0226c9140ff6c8c3487611108882c91a03b6b0) - @gugu
- [temporary make eslint return true after linting](https://github.com/node-saml/passport-saml/commit/e835f03c7be34a751c596e13ef60ffc39a5c3dcf) - @gugu
- [use src directory instead](https://github.com/node-saml/passport-saml/commit/1a57f472bc67c5c8b618520687a241252f689bd6) - @gugu
- [prepublish hook](https://github.com/node-saml/passport-saml/commit/2545286d1c1c2a15b3b09c08b2e0266d1d55cb9a) - @gugu
- [support typescript compilation](https://github.com/node-saml/passport-saml/commit/aa7636bb785c50565ad52b39db566bcaba55a042) - @gugu
- [Add PR template (#473)](https://github.com/node-saml/passport-saml/commit/dca255639c00670278bcd8aea185662ebe1036c5) - @cjbarth
- [Drop support for Node 8](https://github.com/node-saml/passport-saml/commit/08482ad2d0ee1ca4b6b5b4f4788f6d97304109ca) - @walokra
- [try to use curl when wget is not available (#468)](https://github.com/node-saml/passport-saml/commit/026edf2a422f70ee8f483c902594bf29a27def3c) - @rod-stuchi
- [Include package-lock.json in repo](https://github.com/node-saml/passport-saml/commit/b4b7fcc6de7c0436bfabe6a85383ab7cf8621c06) - @mans0954
- [Bump xml-crypto from 1.4.0 to 1.5.3](https://github.com/node-saml/passport-saml/commit/cbf7483c92ef3659ed19874b754f36e0c9f9277d) - @mans0954
- [Only make an attribute an object if it has child elements](https://github.com/node-saml/passport-saml/commit/384b28d672bd473d048009de8f1a9fe052a78b7c) - @mans0954
- [Add GitHub Actions as Continuos Integration provider (#463)](https://github.com/node-saml/passport-saml/commit/df8eb78a3d01e5decb18fb755b2a353bd7d680bc) - @walokra
- [Add test for issue 459](https://github.com/node-saml/passport-saml/commit/7995eeffd5267e0f468dd518c103aea70a8d31a3) - @mans0954

---

## v1.3.5 (16/09/2020)
- [docs: remove badges broken by project rename.](https://github.com/node-saml/passport-saml/commit/e0480e13dba1c6635763cf31d2bb942a930bcc70) - @markstos
- [bump version to 1.3.5](https://github.com/node-saml/passport-saml/commit/9115a02b518d808335b7e88b63c82f71d05974d3) - @markstos
- [deps: really bump xml-encryption for node-forge sub-dep upgrade to address vuln.](https://github.com/node-saml/passport-saml/commit/b696e5895b8a7aa530280671d40ad487201a0564) - @markstos
- [docs: Update package.json / README to reflect site move.](https://github.com/node-saml/passport-saml/commit/af98f3677fc6bc3250e74f476be63551c09f5c33) - @markstos
- [deps: bump xml-encryption to address node-forge sub-dep vuln.](https://github.com/node-saml/passport-saml/commit/1e6ec3987000a1e7a4145ecd7ff40fe699e977d8) - @markstos
- [Update issue templates](https://github.com/node-saml/passport-saml/commit/bfcdb78f683937c51afe68d29269bac9fd87e24e) - @markstos
- [Update issue templates](https://github.com/node-saml/passport-saml/commit/85ffa052265795ab1894fe7339d5f561c698d6ce) - @markstos
- [Bump lodash from 4.17.15 to 4.17.20 (#449)](https://github.com/node-saml/passport-saml/commit/5abba17e10ccb404e5575e0ba94940a233528286) - @dependabot[bot]
- [Bump acorn from 7.1.0 to 7.4.0 (#448)](https://github.com/node-saml/passport-saml/commit/8a8d82bdd34df037768d751aec4088ed392f7d3e) - @dependabot[bot]
- [Return object for XML-valued AttributeValues (#447)](https://github.com/node-saml/passport-saml/commit/aed4a3d26ee3daba14fd08ede1465997b3a15468) - @mans0954
- [Revert "doc: announce site move." (#446)](https://github.com/node-saml/passport-saml/commit/bb025e645ecc7d9b78963e7f807ee90544be5f9a) - @mans0954
- [doc: announce site move.](https://github.com/node-saml/passport-saml/commit/f64cc7a30a916adb81e4451842b58b759651a7ca) - @markstos
- [add yarn-error.log to .gitignore](https://github.com/node-saml/passport-saml/commit/8fdd087ae9ef627f49f9addc5ab44f100de1b92d) - @markstos

---

## v1.3.4 (21/07/2020)
- [Fix multi saml strategy race conditions (#426)](https://github.com/node-saml/passport-saml/commit/ffbd2f61e05e8c6e932422fb4f54523b15c106df) - @stavros-wb

---

## v1.3.3 (19/02/2020)
- [v1.3.3](https://github.com/node-saml/passport-saml/commit/74fa6307652d3c7d785725655ce63a755938b270) - @markstos

---

## v1.3.2 (12/02/2020)
- [v1.3.2](https://github.com/node-saml/passport-saml/commit/e70b6db8be2134620fa31345ec3fc12ab7017033) - @markstos

---

## v1.3.1 (11/02/2020)
- [Upgrade xml-encryption to 1.0.0 (#420)](https://github.com/node-saml/passport-saml/commit/707211ccd722b0cbb12a5b96a6ba3296228201e9) - @brandon-leapyear

---

## v1.3.0 (06/02/2020)
- [deps: bump yarn.lock to match package.json](https://github.com/node-saml/passport-saml/commit/1869d272f53263abd259d39ac59f87457ba99e8d) - @markstos
- [Add tests to check for correct logout (#418)](https://github.com/node-saml/passport-saml/commit/ac7939fc1f74c3a350cee99d68268de7391db41e) - @cjbarth
- [added passReqToCallback to docs](https://github.com/node-saml/passport-saml/commit/dc4603a2c2027c5d289f3cec5a8ba5ea6c754cf7) - undefined
- [Fix an issue readme formatting](https://github.com/node-saml/passport-saml/commit/9a2c26ec2398a2b56316aac2a6c996f34b425a9c) - @cjbarth
- [BugFix: Quit deleting 'name' option passed.](https://github.com/node-saml/passport-saml/commit/21ff020e694801a77d52cd53ad6077d59eb0792c) - @markstos
- [attributeConsumingServiceIndex can be zero](https://github.com/node-saml/passport-saml/commit/d10fb931f51e2a0cdeb30df71e20a6dda8c90da3) - @gunzip
- [add documentation on privateCert options](https://github.com/node-saml/passport-saml/commit/3c69c7c0a5212b639c5ad9b2d9949fe641907de7) - undefined
- [convert private cert to pem for signing](https://github.com/node-saml/passport-saml/commit/7e2de2d4e22d1562eccd5d487ac24071226e9492) - undefined
- [add support for encrypted nameIDs in SLO request handling](https://github.com/node-saml/passport-saml/commit/2277f2620e923a64ff7300d8f42e0fbb4a2aba4c) - @eero3
- [Issue #206: Support signing AuthnRequests using the HTTP-POST Binding (#207)](https://github.com/node-saml/passport-saml/commit/370ee9f03366f50cb4e346db95b9cb29834dea24) - @richardTowers
- [Bring-up xml-crypto to 1.4.0 (#400)](https://github.com/node-saml/passport-saml/commit/c82149d2f8b5d3f90f973ab69812efb11e85569a) - @LoneRifle
- [fix #393 adding 'inResponseTo' in the profile (#404)](https://github.com/node-saml/passport-saml/commit/7bffa5c3e518aeacfe7291fa424d21726d568116) - @nishch
- [add Node support policy to README](https://github.com/node-saml/passport-saml/commit/4ebfae0da47968f4c3d4459d4d174506ddcfa0e5) - @markstos
- [refactor: replace 'self = this' with arrow functions](https://github.com/node-saml/passport-saml/commit/53e7363567123f9099ecc6163f148df3a79b1314) - @markstos
- [Fix minimum version of Node.js in Travis (#399)](https://github.com/node-saml/passport-saml/commit/75ad459ba57a1e974b9ad8278ddfbc964c19705b) - @walokra
- [Fix #355 missing parts: tests.](https://github.com/node-saml/passport-saml/commit/571bf42d3191a0b0f4003785f85e13e61a74e4c5) - @walokra
- [Add .editorconfig as suggested in #373](https://github.com/node-saml/passport-saml/commit/da64d889a9d5af780297ed5f4c0aeaac8607f925) - undefined
- [Fix #392 Switching from jshint to eslint](https://github.com/node-saml/passport-saml/commit/7d71fe21e84fd6becb63d93e0dad1906d39495fa) - @walokra

---

## v1.2.0 (12/09/2019)
- [bump version to 1.2.0](https://github.com/node-saml/passport-saml/commit/3ba244d2859dd80da9f4cfcfba656f00400ce6c1) - @markstos
- [Use exact match to check for a compatible crypto algorithm.](https://github.com/node-saml/passport-saml/commit/403a18998c573b545a3baac4cb37d4bd5bb41111) - @stavros-wb
- [Validate signatures on original query string](https://github.com/node-saml/passport-saml/commit/91bac34977dec9a0ff3e9af3dda9dd2c8402b969) - @stavros-wb
- [NameIDFormat fix (#375)](https://github.com/node-saml/passport-saml/commit/6f0876ed77815235d7d846ea145da733c3fa6b04) - @ahavriluk

---

## v1.1.0 (10/05/2019)
- [v1.1.0: bump for release](https://github.com/node-saml/passport-saml/commit/16fb6599061de8106bed3fb76b5f77c6ba56bb94) - @markstos
- [Improve code consistency; fix error handling bugs](https://github.com/node-saml/passport-saml/commit/ce5351d59f07569534c15dfe8b0d29e3eda0461f) - @cjbarth
- [Fix broken tests](https://github.com/node-saml/passport-saml/commit/3592f07f08f648349951231c2da69560aa760c74) - @cjbarth
- [rename comparisonType to RACComparison](https://github.com/node-saml/passport-saml/commit/48ac6558ef57edba8ed90fae53833e17b4b0d0ed) - @markstos
- [:star: feat: add RequestedAuthnContext Comparison Type parameter](https://github.com/node-saml/passport-saml/commit/a4661393f4628910160842c3f928a2f2fe2dccd2) - @osan15
- [Update README.md](https://github.com/node-saml/passport-saml/commit/663c127c000c542aa8226df6e22beb17f9c9d62a) - @josecolella
- [InResponseTo support for logout](https://github.com/node-saml/passport-saml/commit/b99deb1b83e62187ec06dc3384c46c9f8dda5092) - @VilleMiekkoja
- [deps: bump deps](https://github.com/node-saml/passport-saml/commit/98f1be76baadf2ee05ff377d68f76c1158baaf12) - @markstos
- [Set explicitChar to true when parsing xml. Now character content of a element should be accessed only through ._](https://github.com/node-saml/passport-saml/commit/53bfd7dbb5849f5a8dd214f8d286f3a3c9039fc0) - @andkrist
- [update gitignore](https://github.com/node-saml/passport-saml/commit/5ae1fa30424e27a8ea773f93d2dd2cc3e5532cd7) - @andkrist
- [update xml crypto to 1.1.4](https://github.com/node-saml/passport-saml/commit/47d011884d312db10f20de25d73edd642d2ea1ec) - @lpamlie
- [Create a way to get provider metadata when using the MultiSamlStrategy](https://github.com/node-saml/passport-saml/commit/b384277361bdda2003152b4a1801e3d8dd3696c9) - @mlunoe
- [Fix Node Buffer deprecation warning: update 'new Buffer' to 'Buffer.from()'](https://github.com/node-saml/passport-saml/commit/a60fda016862ba9fcffd2e558b8ac35ede37fab3) - @Archinowsk
- [Fix #128 documentation for body-parser dependancy](https://github.com/node-saml/passport-saml/commit/0ab4639ddfee4156c5043ff50f6ff4dcaf49b9d1) - undefined
- [Update Node version in package.json to >=6](https://github.com/node-saml/passport-saml/commit/e60ec9ece9bb17d23e12a97c6378aa9dc019e2d8) - @Archinowsk
- [Upgrade xml-crypto to 1.1.2](https://github.com/node-saml/passport-saml/commit/f54a43c8cb655087987cc6f92d426de875f7b6e1) - @LoneRifle
- [fix for failing test](https://github.com/node-saml/passport-saml/commit/c40ccb5e2912393a741f54011beb8afc20c19549) - @siren
- [Support InResponseTo validations in MultiSaml](https://github.com/node-saml/passport-saml/commit/2afa1bace21005c86969b6f054b8adbe1f7fb8dc) - @stavros-wb
- [Add SamlResponseXML method to profile object](https://github.com/node-saml/passport-saml/commit/0544376c51d9061a7d901c76ce19d0412b8765a1) - @josecolella
- [Add option to disable SAML spec AuthnRequest optional value AssertionConsumerServiceURL.](https://github.com/node-saml/passport-saml/commit/e2154f28b9311b3975c95145cf636d198eead959) - undefined
- [Drop support for Node 4. It is EOLed.](https://github.com/node-saml/passport-saml/commit/d2c89947fca1fa79365f5819a0e7326ebc94728a) - @markstos

---

## v1.0.0 (02/12/2018)
- [bump version to v1.0.0.](https://github.com/node-saml/passport-saml/commit/677424cf2f594344e4e70bec0be2d7591a60e089) - @markstos
- [Update xml-crypto to 1.0.2](https://github.com/node-saml/passport-saml/commit/b5fd79db749c1dbcdc8a7920fe131e49b504b1a1) - @elahti
- [Fixes #180: Signature validation will error if empty signature is provided](https://github.com/node-saml/passport-saml/commit/f6b1c885c0717f1083c664345556b535f217c102) - @andrsnn
- [Validate issuer on logout requests/responses if configured](https://github.com/node-saml/passport-saml/commit/09f0a4e5c58bdc723c86fe32bfbb3e4ad360c503) - @stavros-wb
- [feat(logout): handle null and undefined on nameQualifier](https://github.com/node-saml/passport-saml/commit/a4998ea4e6ab85d11e0eb34f5c15d2109a070c1e) - @sibelius
- [Support redirect flows](https://github.com/node-saml/passport-saml/commit/7674e18e2cc674132a9655936c2fca5dfc72af70) - @stavros-wb
- [Adds signing key in the metadata service provider generation.](https://github.com/node-saml/passport-saml/commit/4b02e16a6d7cb7534c585c3e015b5a5f0d2aa9ac) - undefined
- [Correct typo in README. Fixes #303.](https://github.com/node-saml/passport-saml/commit/25ac94e37d17b371eaa90f344a5f0d17a162d5ad) - @markstos
- [Extend and document the profile object](https://github.com/node-saml/passport-saml/commit/4943e28e16d9196214d1d3ced5b4ce6677436148) - @cjbarth
- [Handle case of missing InResponseTo when validation is on](https://github.com/node-saml/passport-saml/commit/e483496e257cfed75a43638e983836025ceaab56) - @cjbarth
- [entryPoint is compulsory for signed requests](https://github.com/node-saml/passport-saml/commit/f7aab5c0e071827956484b094e59b72b22dd8309) - @cjbarth
- [Include support for run-time params to be included in the generated URLs](https://github.com/node-saml/passport-saml/commit/f82d14190e44dee2eb40585e220dbab3234ccaf8) - @cjbarth
- [support multiple authnContext](https://github.com/node-saml/passport-saml/commit/45af79e44f8b4d82ab82ebe6fce8694f416c9cc7) - @cjbarth

---

## v0.35.0 (14/08/2018)
- [start to use the debug module.](https://github.com/node-saml/passport-saml/commit/f8140aa6bca4e645119b45b83dd5eef45627aacf) - @markstos

---

## v0.34.0 (14/08/2018)
- [v0.34.0: release](https://github.com/node-saml/passport-saml/commit/32f1a21c7cb07783d55c898b949d0e39f307d4ae) - @markstos

---

## v0.33.0 (16/02/2018)
- [package.json: bump version to 0.33.0](https://github.com/node-saml/passport-saml/commit/2de3528f308f2103625b191c5b32432636f1592e) - @markstos
- [docs: mention that disableRequestAuthnContext helps with AD FS](https://github.com/node-saml/passport-saml/commit/8f1fe3269b5e4497d97a5534f5236a07140c0560) - @markstos

---

## v0.32.1 (03/01/2018)
- [bump version to v0.32.1](https://github.com/node-saml/passport-saml/commit/3165135d75e96550e2cd9d4edd6e310cb8261972) - @markstos
- [README: link to where our Changes are documented.](https://github.com/node-saml/passport-saml/commit/be55ed383a61eb3805786e6d045e44cc16d69615) - @markstos
- [Audience validation](https://github.com/node-saml/passport-saml/commit/c2ce79d51d93b68e34911e74bb06cf915d8a754b) - @beneidel
- [README: fix typo `s/ADSF/ADFS/`](https://github.com/node-saml/passport-saml/commit/b54e0f23e8d460da88e21843a6df145f935833e8) - @teppeis

---

## v0.31.0 (01/11/2017)
- [v0.31.0 release](https://github.com/node-saml/passport-saml/commit/2ba2565a778aa59d6540b02892a1329b6046cf20) - @markstos
- [README: update link description for ADFS docs.](https://github.com/node-saml/passport-saml/commit/086607434ab734fee00341c31022dd1c7c22fdc4) - @markstos
- [Upd: Mention ADFS 2016 with NameIDFormatError. (#242)](https://github.com/node-saml/passport-saml/commit/a94fbfa730dd0aca0e0fa2cedcbabbea1765aee6) - @cadesalaberry

---

## v0.30.0 (12/10/2017)
- [v0.30.0](https://github.com/node-saml/passport-saml/commit/073b9db03be871652e260d14624ec05451591221) - @markstos
- [Ignore .tern-port files](https://github.com/node-saml/passport-saml/commit/aa4a6e2870e86ba69d9fe0cf8d06188f1babe792) - @markstos
- [Use crypto.randomBytes for ID generation (#235)](https://github.com/node-saml/passport-saml/commit/da829fc0216ed961ea7cb8a6234df65a60f51114) - @autopulated
- [BugFix: Fail gracefully when SAML Response is invalid. Fixes #238](https://github.com/node-saml/passport-saml/commit/305afbd31978a1b171a8abe0f1c79ff57dcff846) - @markstos
- [docs: Improve docs for privateKey format. Ref #230](https://github.com/node-saml/passport-saml/commit/a780d0707caff89ed9b0564d3657efdbea411336) - @markstos

---

## v0.20.2 (10/10/2017)
- [v0.20.2](https://github.com/node-saml/passport-saml/commit/8980d25729c39da163fcb422da4da4ff8aeb6791) - @markstos
- [Update dependencies to be current.](https://github.com/node-saml/passport-saml/commit/83a26d6ae3895ce632ecf361c5b42edac6edeabd) - @markstos

---

## v0.20.1 (10/10/2017)
- [v0.20.1](https://github.com/node-saml/passport-saml/commit/663db184b834c2fc45fdd4c25b16a50f6c9f0384) - @markstos
- [handle bad privateCert](https://github.com/node-saml/passport-saml/commit/3e08bfb2f333f3dc6ae094f3253f11c66b481b40) - undefined

---

## v0.20.0 (09/10/2017)
- [v.0.20.0](https://github.com/node-saml/passport-saml/commit/011d0758c5a05343cdfd46564bf5a89cd9af455f) - @markstos
- [deps: bump xml-encryption version from 0.10 to 0.11.0](https://github.com/node-saml/passport-saml/commit/691122e02d4dfed5292e465d3ea758ef6d4df62f) - @markstos
- [test: refactor: re-use certificate variable instead of copy/pasting whole cert.](https://github.com/node-saml/passport-saml/commit/a84a722aafe10b8f04181081f7a096e9cc2d4612) - @markstos
- [test: refactor: Better organize validatePostResponse tests](https://github.com/node-saml/passport-saml/commit/648926972e616e3af8a5044894ca96e62de85744) - @markstos

---

## v0.16.2 (07/10/2017)
- [bump version to v0.16.2](https://github.com/node-saml/passport-saml/commit/67029ae6aeb7d81724db2ac0d1bfbed930f2d5f2) - @markstos

---

## v0.16.1 (05/10/2017)
- [README: link to related sections and clarify decryptionCert docs](https://github.com/node-saml/passport-saml/commit/4d97ffcb7918526cfc6101207fe04d14a0abd23e) - @markstos

---

## v0.16.0 (04/10/2017)
- [Fix travis for older versions of node](https://github.com/node-saml/passport-saml/commit/1f7a0d8203d9e137c6d7feee6b52d9c6d62f2574) - @alvinward
- [Fix jshint error](https://github.com/node-saml/passport-saml/commit/ed522eee5170176ca1b0ca3b7629c8ef716a92a2) - @alvinward
- [Add support for ProviderName attribute](https://github.com/node-saml/passport-saml/commit/99cc3013e39cd2e3b2b6953cf36556286bffaee8) - @alvinward
- [Add badges to readme](https://github.com/node-saml/passport-saml/commit/2f2e91aa5434445f0e864b40cd720cda055ada06) - undefined
- [Update deps to latest](https://github.com/node-saml/passport-saml/commit/6d1215bf96e9e352c25e92d282cba513ed8e876c) - @pdspicer
- [Updated README to include sha512 as a listed option](https://github.com/node-saml/passport-saml/commit/9d7f676e590bd3d81af2518c89838610cd9c2672) - @pdspicer
- [Remove unused ejs package from devDeps](https://github.com/node-saml/passport-saml/commit/010874d587f48688038fbb273fcb672b03426979) - @akselinurmio
- [Use latest version of xml-encryption](https://github.com/node-saml/passport-saml/commit/62604435febd0aa1d26ae0652e545c721e8ca11d) - @xdmnl
- [Fixes #170: Clarify that the certificate are looking for is:](https://github.com/node-saml/passport-saml/commit/01611572d1b71300a66034ea603d739c8b26b95b) - @markstos
- [Add the ability to sign with SHA-512](https://github.com/node-saml/passport-saml/commit/411e4f7fe3b3bc14dd39d1ba6ad72d51c34b5fb5) - undefined
- [Fix tests on Node.js:stable](https://github.com/node-saml/passport-saml/commit/6501c235cf9821c33750ca12caf5e1557154039e) - @xdmnl
- [Add test for an encrypted Okta response](https://github.com/node-saml/passport-saml/commit/c0eac66d3bc53bde8b8fe67f5f4e627a006bc930) - @xdmnl
- [Send EncryptedAssertion node when trying to decrypt the assertion](https://github.com/node-saml/passport-saml/commit/25b6dd01c782461e0677b64d6dda67693bfc879c) - @xdmnl
- [Updagrade to xml-encryption 0.9](https://github.com/node-saml/passport-saml/commit/785ed3b05206ce88c06cc2961c7a1c45d3bf7689) - @xdmnl
- [Fix tests with latest version of shouldjs](https://github.com/node-saml/passport-saml/commit/ade5f0ed8b1f95d39f6b553f3c05671c1f77442f) - @xdmnl
- [Clarify that `cert` value should a single line. Fixes #134](https://github.com/node-saml/passport-saml/commit/0f0fc47ec42587af5b4c20d25deaf48dcc30d3a6) - @markstos

---

## v0.15.0 (30/12/2015)
- [v0.15.0](https://github.com/node-saml/passport-saml/commit/525748647c8a8c6e79073bf8965c639c36f262b5) - @ploer
- [Fix scope issues in PR #131.](https://github.com/node-saml/passport-saml/commit/094c660a0560625ccd29dbbffff4b7168844b4ef) - @ploer
- [Refactor HTTP-Post tests to be a branch in existing authnRequest tests, rather than largely duplicated separate test.](https://github.com/node-saml/passport-saml/commit/f8b6837bd81ddba91d5c654a8cebd33f555e6c0f) - @ploer
- [Remove a comment left behind in the wrong place (and content now covered in documentation)](https://github.com/node-saml/passport-saml/commit/85cab613453cea9487263a1f7555f743fe130969) - @ploer
- [Minor documentation clarification.](https://github.com/node-saml/passport-saml/commit/77407f73c6ba5f66c57cd731a7db2730b8779454) - @ploer
- [Changing HTTP-Post AuthnRequest binding option to be part of SAML object options, named authnRequestBinding, and adding to documentation.](https://github.com/node-saml/passport-saml/commit/dd32a45b5d4e3984784276dbea67f5a9e9d86db3) - @ploer
- [Add a basic test for HTTP-Post authn binding support (PR #129)](https://github.com/node-saml/passport-saml/commit/2879451cccf24f2dbcbabdf5bc0df1cb780fb31f) - @ploer
- [Fix Subject dereference bug](https://github.com/node-saml/passport-saml/commit/2b5abbaafe630f84926afb4750f6aa1208198e2c) - @timoruppell
- [Update package.json](https://github.com/node-saml/passport-saml/commit/ee5e92158f1583dcfc850b0afb75bda50c3bec65) - @cheton
- [Update package.json](https://github.com/node-saml/passport-saml/commit/d069ae6f1777cae9516788ff4fb05183aaa6eee4) - @cheton
- [Added missing semicolon](https://github.com/node-saml/passport-saml/commit/5a236a25fce9e645a255545fd60387434bf6fded) - undefined
- [Adds HTTP-POST binding support for the SAML <AuthnRequest>](https://github.com/node-saml/passport-saml/commit/e0056923656733b83ca81d68bc2f907f94e26797) - undefined
- [Add test for new nameid attributes](https://github.com/node-saml/passport-saml/commit/fadd3e4a2812ff719aa1dec694191aeca33577e6) - @ashimaathri
- [Do not sign custom query string parameters](https://github.com/node-saml/passport-saml/commit/f33edd934243855e85f33fb5cb91374439e2c172) - @cjbarth

---

## v0.14.0 (02/11/2015)
- [v0.14.0](https://github.com/node-saml/passport-saml/commit/b6a882a54732a47d423ba02665e87e8643c1ef40) - @ploer
- [Specify SingleLogoutService callback url](https://github.com/node-saml/passport-saml/commit/e7c77bb22e8bf2ec0323cd75d13bf778a300dfc6) - @cjbarth
- [Only add to logout xml if present in authn response](https://github.com/node-saml/passport-saml/commit/80da2879c9b2791cc6e79562ee1bc25e1cff87e1) - @ashimaathri
- [Add NameQualifier and SPNameQualifier to nameID](https://github.com/node-saml/passport-saml/commit/90973fffd417664a6ae5d8ef070a71760a96545e) - @ashimaathri

---

## v0.13.0 (09/10/2015)
- [v0.13.0](https://github.com/node-saml/passport-saml/commit/8064dda414a461ac621ca8b9c2b9a114efac2bc8) - @ploer
- [xml-crypto: update to 0.8](https://github.com/node-saml/passport-saml/commit/503cfc26a7e33626aac9bbea050a450ffe92ef0f) - @gnawhleinad
- [Remove duplicate should clause](https://github.com/node-saml/passport-saml/commit/2fddad618324fa7f09f0ade4ab61967444dc373b) - @adalinesimonian
- [travis: remove node-0.8 and add node-4.0](https://github.com/node-saml/passport-saml/commit/bf016c63e18c8fb0b54abcac753f6e536dbe4ea2) - @gnawhleinad
- [Add tests for parsing multiple AttributeStatements](https://github.com/node-saml/passport-saml/commit/6003165f3d6aaf3a341248dcf2e5ebc97ad0f608) - @adalinesimonian
- [Process all attributes in all attribute statements](https://github.com/node-saml/passport-saml/commit/b13b7babccbf15e5c7d9a9b8edcce4fb5e69d50c) - @adalinesimonian
- [adds a test case for PR #111 - attributes without attributeValue should be ignored](https://github.com/node-saml/passport-saml/commit/1aa4690f23f2275b0267ec22fbae7132a99b5c31) - undefined
- [Replace passport dependency with passport-saml dependency (as suggested in PR #110)](https://github.com/node-saml/passport-saml/commit/010f2d4373719cf34b6dc241d51e76d8e4b1c2f2) - @ploer

---

## v0.12.0 (19/08/2015)
- [version 0.12.0](https://github.com/node-saml/passport-saml/commit/a1567585c0c4a8d1e28bac3c85b7bb11dca3f4a7) - @ploer
- [Update README.md to add reference to docs/adfs/README.md.](https://github.com/node-saml/passport-saml/commit/2c20a73ee4af8e6d6c7d53c538cdd6da4a08cfce) - @ploer
- [Move ADFS folder into docs subfolder.](https://github.com/node-saml/passport-saml/commit/b48a069822ee77f3237b4aa1b269b8151eb31065) - @ploer

---

## v0.11.1 (18/08/2015)
- [version 0.11.1](https://github.com/node-saml/passport-saml/commit/9d7df826f632510d2807e226d39699527d2d88c7) - @ploer

---

## v0.11.0 (10/08/2015)
- [version 0.11.0](https://github.com/node-saml/passport-saml/commit/c4ef5982d96fb99ba6cc5c6841d67ffa7b119b1d) - @ploer
- [generateServiceProviderMetadata: remove callbackUrl dependency](https://github.com/node-saml/passport-saml/commit/321d6bd3df3637309ec4a7a34ce015b8f4f72d60) - @gnawhleinad
- [Revising logic from PR #102 to just conditionally put the keyDescriptor in if needed, rather than deleting it if unneeded.](https://github.com/node-saml/passport-saml/commit/cc652563cf9fd314889d5a07c0eba9da3d38c25f) - undefined
- [Fixed an obscure bug in which certificates may not be found.](https://github.com/node-saml/passport-saml/commit/24295ecf2961da40fdb0a7c69c6213ed7bf29f2b) - @ethanmick

---

## v0.10.0 (08/06/2015)
- [version 0.10.0](https://github.com/node-saml/passport-saml/commit/f143ada7d631151952e3333791c3a92fafb85344) - @ploer
- [Add test for SessionIndex](https://github.com/node-saml/passport-saml/commit/b9472d8e9d5713869ad3cd62c1a6cee9683aa327) - undefined
- [SessionIndex works when added to current request](https://github.com/node-saml/passport-saml/commit/3311afd9bcaf56d7e28890b97b297df5e51158d3) - undefined
- [Generate logout request that should work with WSO2, but it doesn't](https://github.com/node-saml/passport-saml/commit/46d8ad99ac83945ac56c26f81c1f188b2d56bd0c) - undefined
- [Update README.md](https://github.com/node-saml/passport-saml/commit/28b4fe0540975622edd6b90a2fa0816b958d2fb1) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/8b48f659b2ba1a5ce8ef037624ebcf3f1c91b65c) - @ploer

---

## v0.9.2 (26/04/2015)
- [version 0.9.2](https://github.com/node-saml/passport-saml/commit/5fd2e997dc841ae1e106acc2b8124db72bee8847) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/467fe0188ce5277dfcf3e949d7f830f7f8103f55) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/3252f9410c5452d718d1e00871d2bd7f2294d46f) - @ploer
- [Added Destination attribute to LogoutResponse assertions](https://github.com/node-saml/passport-saml/commit/dd08c26a37e0ed6b4d377c6ac4f07aef5ceb1ec2) - @cmordue
- [Remove node 0.11 from travis testing.](https://github.com/node-saml/passport-saml/commit/2623f786bbfa77db8f9734fa1e6c826351466674) - @ploer
- [Add iojs to travis tests.](https://github.com/node-saml/passport-saml/commit/08360ba7e9a674ec5b0a28fd0583036f24e18d9d) - @ploer
- [Re-adding travis checking on 0.11.](https://github.com/node-saml/passport-saml/commit/f7af949416b229a8f691c46befcfc97438b408e8) - @ploer

---

## v0.9.1 (18/02/2015)
- [version 0.9.1](https://github.com/node-saml/passport-saml/commit/c5e7305fb32386e37e278e19ce37afe0d9de9ca8) - @ploer

---

## v0.9.0 (05/02/2015)
- [version 0.9.0](https://github.com/node-saml/passport-saml/commit/4298ed9e85106885be4c21f08a6042523892d083) - @ploer
- [@ForceAuthn parameter is only emitted, if it is set true. Add forceAuthn description in README.md](https://github.com/node-saml/passport-saml/commit/5115b58f7f440cca4799ea7f81268dd698f5a35e) - undefined

---

## v0.8.0 (23/01/2015)
- [version 0.8.0](https://github.com/node-saml/passport-saml/commit/3441a6729fba876c8454ac3a3581c85bfbdce54c) - @ploer
- [Fix typo in readme.](https://github.com/node-saml/passport-saml/commit/98cc66848308092c118207d61b3ea627505e845b) - @ploer
- [Slight readme clarification](https://github.com/node-saml/passport-saml/commit/757116bd3c2d0bf5f9b170261ac1095cfc697a4d) - @ploer
- [Fix typo in readme.](https://github.com/node-saml/passport-saml/commit/9304705163e073ec616144e7309fc736b525f38b) - @ploer
- [Organize list of config options into sections](https://github.com/node-saml/passport-saml/commit/1e82f23bd5b0e0429edd31fb5ef1135a899f483b) - @ploer
- [document new logoutUrl option](https://github.com/node-saml/passport-saml/commit/c8bbed34cab9da0468b5581339c1dc3e4e74959d) - @ploer
- [Adding default for options.logoutUrl](https://github.com/node-saml/passport-saml/commit/42457e210ef6bde91fbe342925a556732b2f5148) - undefined

---

## v0.7.0 (13/01/2015)
- [version 0.7.0](https://github.com/node-saml/passport-saml/commit/33df15ee4e3732ccc614648267dea8fedcf7791d) - @ploer

---

## v0.6.2 (06/01/2015)
- [version 0.6.2](https://github.com/node-saml/passport-saml/commit/e130ac5ad42f2bda9aa108dcbab62abc1763babb) - @ploer

---

## v0.6.1 (18/12/2014)
- [version 0.6.1](https://github.com/node-saml/passport-saml/commit/de8438aa5f47ada133ac70f99979da02eb995fe2) - @ploer
- [Disable expirationTimer.unref() change under node 0.10.34 due to https://github.com/joyent/node/issues/8900](https://github.com/node-saml/passport-saml/commit/6422bb1aeae1bbf8ea8a75a5db4924ec630507ba) - @ploer
- [Unref our inmemory-cache expiration timer so that it doesn't hold the process open (issue #68).](https://github.com/node-saml/passport-saml/commit/4daf10e3f7f8d5ad6a829edbddbae122f6adf6f9) - @ploer

---

## v0.6.0 (14/11/2014)
- [version 0.6.0](https://github.com/node-saml/passport-saml/commit/aa3dfaa681e449bc88477b27c36ba5b7e417f3a6) - @ploer
- [Updating some dependency versions.](https://github.com/node-saml/passport-saml/commit/de26b9ad8df5cba3263b4223e2d03330f7e98bbe) - @ploer
- [Added 'getAdditionalParams' unit tests.](https://github.com/node-saml/passport-saml/commit/80068a8a3bf61d7e16d2682776d08f38ebd89472) - @tkopczuk
- [Fixed all the linter warnings.](https://github.com/node-saml/passport-saml/commit/c3389a7359593b787a8af8aaf5e5e48707982456) - @tkopczuk
- [Fixed variable name.](https://github.com/node-saml/passport-saml/commit/63adf4cb36ce43187b79e05d41cd2c5b7620739c) - @tkopczuk
- [Simple documentation for the new options:](https://github.com/node-saml/passport-saml/commit/b99409d5f7216620edeffed44d93487a9e95a7f1) - @tkopczuk
- [Support for new options:](https://github.com/node-saml/passport-saml/commit/abc5ffd9863199af567cbc407680285aad80f44d) - @tkopczuk
- [Delete example directory since we're not currently maintaining it.](https://github.com/node-saml/passport-saml/commit/7919eb3417ba1c1bd4c915327374ae926d45b85d) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/dd6f8861fd371d472ee790f37bfa819b40efecdb) - @ploer
- [Updated SamlStrategy example in README.md](https://github.com/node-saml/passport-saml/commit/e1b8a7bbc14bf702e49c9f01259cfd300020a3bb) - @gbraad

---

## v0.5.3 (11/09/2014)
- [0.5.3](https://github.com/node-saml/passport-saml/commit/8595f68f16cf0f2a48d9c9569480ece04aa93f68) - @lcalvy
- [Fix body ascii encoding to support accented characters in xml response](https://github.com/node-saml/passport-saml/commit/f4ecac057f7f29fcb28ccf15a5c6bfc36cff0eaf) - @lcalvy
- [Update README.md](https://github.com/node-saml/passport-saml/commit/91f34462fd3d14dcc739063956e7d8ad4caf6f8a) - @ploer
- [Accept responses with encrypted assertions that are signed only at the response level.  (was requiring signature at assertion level in this case)](https://github.com/node-saml/passport-saml/commit/217b77049f641dbc97f9b3930b88cedbb65554f6) - @ploer
- [Add a disableRequestedAuthnContext option.](https://github.com/node-saml/passport-saml/commit/d6950e68a7bb2e2fd91dd89f613aa78bc3a4a33a) - @ploer

---

## v0.5.2 (02/07/2014)
- [Bump version to 0.5.2.](https://github.com/node-saml/passport-saml/commit/b5ee209af948d505706f86ea0712124610fd32ff) - @ploer
- [Slight change to PR #51.](https://github.com/node-saml/passport-saml/commit/175c0bb8162026dbf5cdf4636c16b789aa433cb7) - @ploer

---

## v0.5.1 (02/07/2014)
- [Bump version to 0.5.1](https://github.com/node-saml/passport-saml/commit/c2b31ba9401121fddd79de9d2ea94179096a9957) - @ploer
- [Better error messages when the server returns a status code or message.](https://github.com/node-saml/passport-saml/commit/ab1e8b5f0318839bff0a0a0c259abaa64b9dd274) - @ploer

---

## v0.5.0 (01/07/2014)
- [Bump version to 0.5.0.](https://github.com/node-saml/passport-saml/commit/7c0e2e15dcda47c9a454b605c1f2a3a096b1a21b) - @ploer
- [Fixing a couple of mistakes in the new promises code.](https://github.com/node-saml/passport-saml/commit/4fa83ed949c270e4c89ca2e3b3e49bcc1e4e0ea6) - @ploer
- [Jshint clean.](https://github.com/node-saml/passport-saml/commit/97f644196c3e82ef8bd43bbeb73155695b8062f2) - @ploer
- [Specify 'body-parser' version in devDependency.](https://github.com/node-saml/passport-saml/commit/77f53c317fc8bc1d6e3828a42cfb6e75b6d52f09) - @ploer
- [Fix capitalization for 'q' include.](https://github.com/node-saml/passport-saml/commit/a6fa25083f236644a1daf76f303d6f050936e303) - @ploer
- [Add 'Q' dependency to packages.json.](https://github.com/node-saml/passport-saml/commit/9ee4baf3577baa121b9b20fab5518e541074f2e5) - @ploer
- [Rewrite some of pull request #46 to use 'Q' promises library and try to make sure we are handling asynchronous control-flow correctly.](https://github.com/node-saml/passport-saml/commit/da912ea9e78d1268286bc0e93dfcea648aecb06c) - @ploer
- [Add .SAML export (see issue #50)](https://github.com/node-saml/passport-saml/commit/873f3616db5fbe27cece9e1b5f93561e926c2a52) - @ploer
- [Changing ID check from PR #49 to not depend on idAttributes in SignedXml.](https://github.com/node-saml/passport-saml/commit/631557e5371cbcfc0a54a6547a7baf7266005392) - @ploer
- [Support for node id attribute variations (e.g. "ID", "Id", etc.)](https://github.com/node-saml/passport-saml/commit/1d1695572fb36490c7dcf6146acd2f8d42f4256a) - @lukehorvat
- [Make generateAuthRequest callback friendly](https://github.com/node-saml/passport-saml/commit/94c12cd9a46a2fa7c2ba91e97d05e8594528c780) - undefined
- [Update README.md](https://github.com/node-saml/passport-saml/commit/3e88246e33655d6263c4743fc3e9ba65aad3b456) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/e12be0a14686e6b4126d9a72ac258351399350c3) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/f7a392e8c1831d713e00ef3a6de2a7b50ce4b6d0) - @ploer
- [slight cleanup of pr #48](https://github.com/node-saml/passport-saml/commit/0e1640bd7655ee32ac8f9a359a056bd66de5b01b) - @ploer
- [Add documentation for attributeConsumingServiceIndex option](https://github.com/node-saml/passport-saml/commit/c43fb25cb20929b639b5315ac6b401030eb16ba3) - @heikkihakkalasc
- [test for "don't add begin, end certificate"](https://github.com/node-saml/passport-saml/commit/eb109c199ccf6d2b4b17dd604ff3538b9403d1cf) - @dnbard
- [don't add begin, end certificate to document that allready have this strings](https://github.com/node-saml/passport-saml/commit/4b4f7d7e1f3703ac26b94d348bc85e39466b6d8c) - @dnbard
- [Make CacheProvider async with callback argument](https://github.com/node-saml/passport-saml/commit/7b42a9be6b83600b84f18a51b0248f7d8e3d26b4) - @mradamlacey
- [Support NameID without Format attribute](https://github.com/node-saml/passport-saml/commit/5658f4a48c7961ab24ce92ae88d52c3bc73ea41d) - @heikkihakkalasc

---

## v0.4.0 (20/06/2014)
- [Bump version to 0.4.0.](https://github.com/node-saml/passport-saml/commit/050ed13c09abe8cb0835ae8d35bca107f8d9df22) - @ploer
- [Add the ability for consumers to capture the source assertion associated with a profile object for debugging purposes.](https://github.com/node-saml/passport-saml/commit/f11368f477a96116a6085b6a6cba447574e5cfcf) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/52e9287c5f91b43386ca544188a5b37c53c2240c) - @ploer
- [Fix last checkin (wrong options).](https://github.com/node-saml/passport-saml/commit/ad95a219fd52b6c1cdba13958b39c403234ab18a) - @ploer
- [#41, By default initiate a login-request](https://github.com/node-saml/passport-saml/commit/15a567be0e19040acc79bddaeda65d76c80dd535) - @ploer
- [#40, bug in tolerating missing subject name format field](https://github.com/node-saml/passport-saml/commit/24652330bd528b0fa344a84a5dd0af1d70a9b7be) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/f199e8c0c40794629bfcbe6be8c1e502bfac6cb1) - @ploer
- [Detect protocol if not provided](https://github.com/node-saml/passport-saml/commit/a3a9c3a0f939c1448bd4783b92b8938c72fc4191) - @rubenstolk
- [Add test to make sure passport.serializeUser is being called.](https://github.com/node-saml/passport-saml/commit/afc4d2813154718e496f88bc50090206159c77ad) - @ploer
- [Fix some broken tests.](https://github.com/node-saml/passport-saml/commit/171b73c67e425e2edd293d541885b17412a58140) - @ploer

---

## v0.3.0 (09/06/2014)
- [Bump version to 0.3.0.](https://github.com/node-saml/passport-saml/commit/4891d2d7081380c3f34e11e5b6342182b4f09d13) - @ploer
- [Use latest xml-crypto, which means we no longer need to monkey patch the enveloped signature canonicalization.](https://github.com/node-saml/passport-saml/commit/f1ed7a89f455ba628f3dbe3d80e6dc1d1b9a4262) - @ploer
- [Update README.md, address #39, incorrect string for samlFallback](https://github.com/node-saml/passport-saml/commit/0c1c2df6e9bb1ebf11a356ea7bace94f1a15e6d5) - @ploer
- [Clean up the cache provider interface a little, and make sure the saml code also checks the expiration time so that if a cache provider doesn't flush expired tokens promptly, they'll still be invalid once the expiration interval elapses.](https://github.com/node-saml/passport-saml/commit/c1fb6c6f9d272f78f7ad11423d0b119a7d61ccdb) - @ploer
- [Cleanup of merge of PR #38.](https://github.com/node-saml/passport-saml/commit/9bef922f086ef76ccca4efdb6fcbf9d5b317205f) - @ploer
- [Additional support to check NotBefore and NotOnOrAfter as part of SubjectConfirmation element](https://github.com/node-saml/passport-saml/commit/a827156311e61040e525e04d2b97e693f67e0721) - undefined
- [Fix JSHint failures, implement CacheProvider the SAML object uses, provide in-memory default implementation](https://github.com/node-saml/passport-saml/commit/a22e1617739cf2bc082a03b7eea017f7b63cfb73) - undefined
- [Merging changes from pull request #35 (mradamlacey:master).](https://github.com/node-saml/passport-saml/commit/6e9571a843f711f3616e3b9e0b8e38f594488dc5) - @ploer
- [Support -1 for acceptedClockSkew to disable timestamp validity checks, use default of 0 for acceptedClockSkew](https://github.com/node-saml/passport-saml/commit/012eca58c9d772d018f44378340452711742207f) - undefined
- [InResponseTo SubjectConfirmation validation support](https://github.com/node-saml/passport-saml/commit/1f920c386c6a2196aacd592a90b5fa1de4478115) - undefined

---

## v0.2.1 (05/06/2014)
- [Bump version to 0.2.1.](https://github.com/node-saml/passport-saml/commit/f22595a850aca74f5ecd8aede9f4aeae3c902b7b) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/71f457c4455e5566a66583a32a03d748f35eff53) - @ploer
- [Jshint fix.](https://github.com/node-saml/passport-saml/commit/f06fc3993e17687b4e5a78267cef5181a93bfb34) - @ploer
- [Expose generateServiceProviderMetadata through Strategy object.](https://github.com/node-saml/passport-saml/commit/ec6a68cf50bd0285e52d66702cf64540ca53540d) - @ploer

---

## v0.2.0 (03/06/2014)
- [Bump version to 0.2.0.](https://github.com/node-saml/passport-saml/commit/7a76e10bb74dd25a2643b9e9da4db9eb7cd2d4be) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/d5c51fea61beef27ec45e3a6f6928bf846ab814a) - @ploer
- [Fix package.json.](https://github.com/node-saml/passport-saml/commit/1a2f7cf34ca39bd4b735acfeb213a6fed7a1a79a) - @ploer
- [Add support for EncryptedAssertions in saml responses.  (& test)](https://github.com/node-saml/passport-saml/commit/e027994107daebd2a73431c0bb68c3f13f2dee26) - @ploer
- [Update README.md](https://github.com/node-saml/passport-saml/commit/ed2ef110cf301778ad550a3d7eccc636cc4dd09e) - @ploer

---

## v0.1.0 (31/05/2014)
- [Bumping version number to 0.1 -- definitely enough changes in this release to bump the second tuple.](https://github.com/node-saml/passport-saml/commit/b58237877f17845ef3de8732932ca819badecafe) - @ploer
- [Jshint clean.](https://github.com/node-saml/passport-saml/commit/a82af61bb480682ab1e371b011da21681a342c14) - @ploer
- [Issue #19, stricter signature verification, with tests for cases that were passing but shouldn't.](https://github.com/node-saml/passport-saml/commit/9ce59924ab849bb605ff7e406f1b5fcce09486bb) - @ploer
- [Add repository tag to package.json.](https://github.com/node-saml/passport-saml/commit/8817db5a9e67985e025d6f70bc4654d9b6964bda) - @ploer
- [Remove redirect support from passport-saml-too branch, since it doesn't validate signatures.](https://github.com/node-saml/passport-saml/commit/6f2087e2aa8f14953ec454e82e9882e28ba90da3) - @ploer
- [Updating license link & contributors list.](https://github.com/node-saml/passport-saml/commit/6da8caae2f23a140841f26f15cad7d97d889ab5c) - @ploer
- [Reverting npm name to 'passport-saml' & bumping version.](https://github.com/node-saml/passport-saml/commit/aa674b33f9b180c8418bb084a2d9776859d7b639) - @ploer
- [More travis build fixing.](https://github.com/node-saml/passport-saml/commit/0f2eb7af0d421996fc3e41a19e5bd301e98b5a3e) - @ploer
- [Including mocha as devDependency, and rolling back express to 3.x to see if that helps 0.8 build.](https://github.com/node-saml/passport-saml/commit/73712f6519d626d4bb1371aed5714efb4589334e) - @ploer
- [Travis config: drop 0.6 engine; run mocha.](https://github.com/node-saml/passport-saml/commit/c331df8cff8800ed3e29229d2b44f701956db640) - @ploer
- [Jshint cleaning.](https://github.com/node-saml/passport-saml/commit/5b90b1dba4d19635dfd3fdb1f7ecbb01821fc4e2) - @ploer
- [Remove some commented out code that got missed.](https://github.com/node-saml/passport-saml/commit/7c9d197d93df38feed3706175b929d2aecb7f2cf) - @ploer
- [Updating minimum engine version to 0.8, and updating travis CI engine versions.](https://github.com/node-saml/passport-saml/commit/67df1baf2885e10a59dde5ba32fe269f8077221b) - @ploer
- [Use xmlbuilder to construct xml documents.](https://github.com/node-saml/passport-saml/commit/a11d76ac5c24b55dc669464a01a8c90f59cf17d0) - @ploer
- [Add some tests for generateLogoutRequest and generateLogoutResponse functions.](https://github.com/node-saml/passport-saml/commit/4f4beddef4e4cbc3d922615c1b0de4eaf4c72185) - @ploer
- [Expand tests to cover requests.](https://github.com/node-saml/passport-saml/commit/f96ce0d308afef685aff13b2de9179b6e19eba74) - @ploer
- [Take advantage of xml2js tagNameProcessors to simplify code.](https://github.com/node-saml/passport-saml/commit/1e0bd33ba89543e7037df3596c2fb0048447aacf) - @ploer
- [Cleaning up jshint warning.](https://github.com/node-saml/passport-saml/commit/8cd061a24b021477ca61d6254149cbd0a504cc3f) - @ploer
- [Updating xml2js to latest.](https://github.com/node-saml/passport-saml/commit/d7d284246bebbe69bd09201358adc5a58135c6e5) - @ploer
- [Update dependency versions.](https://github.com/node-saml/passport-saml/commit/b4c0261266bd247a2b9ceb581b477d8e0447021c) - @ploer
- [Adding some basic tests.](https://github.com/node-saml/passport-saml/commit/3a9a8cb57fe88de16c991ec0e8b59617172d1904) - @ploer
- [Check some extra namespaces needed to handle Okta assertions.  (see https://github.com/qingdou/passport-saml/commit/390bbf188d2ff329251ebc13f43b8047e1d5de91)](https://github.com/node-saml/passport-saml/commit/7086e3f0b7c1202a0d2206927b8fef22f026abe3) - @ploer
- [Treat a missing 'AttributeStatement' as just a lack of attributes instead of an error.](https://github.com/node-saml/passport-saml/commit/a293dc65d88867887e1bda3e277a005040eab419) - @ploer
- [bump version 0.0.6](https://github.com/node-saml/passport-saml/commit/38d869244c185eb2fe919681a8f8c7900a81a0b8) - undefined
- [Passing RelayState in all SAML operations.](https://github.com/node-saml/passport-saml/commit/7dbd833b6e6f2acb43941da4b272371341148291) - undefined
- [Forking the name to upload it to npm.](https://github.com/node-saml/passport-saml/commit/79f2f98cb91cdf51a32761ff5d399a59ca5783a1) - undefined
- [throwing if unknown operation](https://github.com/node-saml/passport-saml/commit/4b810ab1760b773d5a906aabaf0ed6b24f50929f) - undefined
- [Accepting NoPassive SAML Response](https://github.com/node-saml/passport-saml/commit/958f5d8934acc4e593579454481cfca57c07f622) - undefined
- [Generating passive AuthnRequest if options say so](https://github.com/node-saml/passport-saml/commit/230db7cbb9961ee9d1ca756bdf048dda7efcc5f7) - undefined
- [using RelayState](https://github.com/node-saml/passport-saml/commit/10bcee137c421132bc354d0461588c5437df6109) - undefined
- [generating LogoutResponse](https://github.com/node-saml/passport-saml/commit/941003397ffa90cf868db68a71febe68ca46b6ec) - undefined
- [requestToUrl additionalParameters, req/res](https://github.com/node-saml/passport-saml/commit/011622a1dd4c3b01722beff5b93d9840eb100ab2) - undefined
- [strategy prepared to have logout response functionality](https://github.com/node-saml/passport-saml/commit/6cc19a7cd75cd076c2a24fd02ac8897d5beeab6a) - undefined
- [SAML accepting LogoutRequest, not responding correctly yet](https://github.com/node-saml/passport-saml/commit/bc619a3f517c8bd53b70d132f7953ff911f79b91) - undefined
- [validation part of xml contents extracted to parameter](https://github.com/node-saml/passport-saml/commit/c540661f6e895829feb7d84189ea372dd86c2739) - undefined
- [Option to tell authenticate what to do without SAMLRe... fields.](https://github.com/node-saml/passport-saml/commit/56e72bcd800b0c769efb7d232b10b70b408f798c) - undefined
- [profile was global because var was missing](https://github.com/node-saml/passport-saml/commit/67632610e71719ce022d9adf07860dea38f80ece) - undefined
- [After successful logout, clear user and continue](https://github.com/node-saml/passport-saml/commit/320b25258460d050b3340837af284d4604382705) - undefined
- [attribute with multiple calues are put as array in profile](https://github.com/node-saml/passport-saml/commit/543edbe505c284b1b2d279d8de9cadd768b29f01) - undefined
- [accepting redirect as well as post; redirect not verified](https://github.com/node-saml/passport-saml/commit/638ce6e4e257d99bf1f5b59c2b76f0890744ded9) - undefined
- [correct method called; validateRedirectResponse impl'd](https://github.com/node-saml/passport-saml/commit/060ce03c62486b368064cd489b91703b2b7b6df0) - undefined
- [use 'container' parameter, redirect uses req.query not .body](https://github.com/node-saml/passport-saml/commit/fb401bf5d6f256f0a8ce39354d0a8e3a58a0c8eb) - undefined
- [Forking to have validate{Post,Redirect}Response](https://github.com/node-saml/passport-saml/commit/db6a5ad07f92d1f06bf78c175846434289ded84b) - undefined
- [XML parsing error is not ignored](https://github.com/node-saml/passport-saml/commit/4cee70bee85a3e92ff9bf3f27c1f0ba7e0b00418) - undefined
- [fixes redirect initiation for targets that already have ...](https://github.com/node-saml/passport-saml/commit/74f964787932b783497410c835704b24866438d4) - undefined
- [fix xpath lookup](https://github.com/node-saml/passport-saml/commit/88ec27c285a1e5f6c66c2abbd51ec2acea1f9946) - @torra
- [Removed zlib](https://github.com/node-saml/passport-saml/commit/84b9ba525520eba51ced4a1e0cfaa85e2de091e0) - undefined
- [fix the hour of the message timestamp](https://github.com/node-saml/passport-saml/commit/40c6b9486da3b1a20d3a8d9cc46b872d4262cbd6) - @dongliu
- [Add jshint on commits](https://github.com/node-saml/passport-saml/commit/78bc1f16d924cbb340cfa9cef1360ca56a3cb187) - @bergie
- [Version bump](https://github.com/node-saml/passport-saml/commit/8b3c4c3ca597ff7a56ff9c3accefbb9b7297e802) - @bergie
- [migrate to xml2js 0.2.0](https://github.com/node-saml/passport-saml/commit/6e74231da9747ec14428a541d7691ca234852da4) - @jess-sheneberger
- [revert accidental change to README.md, package.json](https://github.com/node-saml/passport-saml/commit/81ad226f6b1db6f46505cec8c5377a60add24481) - @jess-sheneberger
- [if the SAML response includes a NameID, put it in the profile](https://github.com/node-saml/passport-saml/commit/61f7558b9f8b271088cd9234872f15eed6be11ff) - @jess-sheneberger
- [remap xml-crypto to pulsehub copy](https://github.com/node-saml/passport-saml/commit/5c6c01692a769cadfb1941c8ea5b7aa8e251a4d4) - @jess-sheneberger
- [initial merge from github jess-sheneberger/passport-saml to](https://github.com/node-saml/passport-saml/commit/ec6b6b60b422b44b191e089e6f5a2ba09b6d6f85) - @jess-sheneberger
- [Initial commit](https://github.com/node-saml/passport-saml/commit/43588760434ae3ea82d5b119016f39eca112480c) - @jess-sheneberger
- [look for Signature element anywhere in the document instead of just two levels down -- ADFS generates SAML that is signed three levels down](https://github.com/node-saml/passport-saml/commit/f7a6913c5a3a550a3bde3f6d655dd79e9eb8de57) - @jess-sheneberger
- [ADFS config notes](https://github.com/node-saml/passport-saml/commit/f6c9b52b54fb1d7e21ae1ce72aa155ab398008c2) - @bergie
- [Some documentation on signatures, plus bump to 0.0.3](https://github.com/node-saml/passport-saml/commit/ad9200052a0e921f7cb1d5fd151961eb7e7cd738) - @bergie
- [Some work to be ADFS compatible](https://github.com/node-saml/passport-saml/commit/6f54068efc794ddaaab1425973d48e234ee25e60) - @bergie
- [Abort login if there is no assertion in the message](https://github.com/node-saml/passport-saml/commit/ebe211c9b6d922d0e2d28c460cdade157f8b65c9) - @bergie
- [Use querystring](https://github.com/node-saml/passport-saml/commit/9b3ee23f0401758f46aeb801b2c8da143c04e935) - @bergie
- [With HTTP Redirect binding the signature has to be outside of XML](https://github.com/node-saml/passport-saml/commit/825619f4bc34a5eb660b8772086656e54f420b3c) - @bergie
- [Validate responses with cert](https://github.com/node-saml/passport-saml/commit/d317547de9f58721ac232f563f11eb327d6924df) - @bergie
- [Use correct element for signing](https://github.com/node-saml/passport-saml/commit/0e8ad6e7af40ff68227e4458774556427213042e) - @bergie
- [Support for signing requests](https://github.com/node-saml/passport-saml/commit/86f45b9d60c07fa6c25505e610dd0e22485a16e7) - @bergie
- [Support for verifying XML signatures](https://github.com/node-saml/passport-saml/commit/6294f9952092bfae51af5834ba4fdd1b6d9a6ca3) - @bergie
- [Make protocol configurable](https://github.com/node-saml/passport-saml/commit/11f20d480f93b1c40c74fdc7e21303c51bc26c49) - @bergie
- [README](https://github.com/node-saml/passport-saml/commit/2e07afba22556572e3b0d38671bda73273c2d4fb) - @bergie
- [MIT license](https://github.com/node-saml/passport-saml/commit/2514a70fbbdfffbf8ca49ff8184c4d45f043b0b8) - @bergie
- [Example with https://openidp.feide.no/](https://github.com/node-saml/passport-saml/commit/0b72cec954536d983c38c73bddd0d7d553eb1e72) - @bergie
- [Initial SAML implementation](https://github.com/node-saml/passport-saml/commit/8baa54c785c7c9343f4df16ba88f3ccd4e5689e5) - @bergie

---

## v0.32.0 (01/01/1970)
- [Generating changelog using gren](https://github.com/node-saml/passport-saml/commit/9bc09b97063b10be3e323e18523e8de453332d6d) - @gugu
- [Reexport SamlConfig type to solve a regression in consumer packages (#516)](https://github.com/node-saml/passport-saml/commit/c61cbad96c742ebde36f2b4fff2408675e6f30b6) - @carboneater
- [dev: add @types/xml-encryption](https://github.com/node-saml/passport-saml/commit/51a154cd142fff7c932352ffcbf0825f38343cf8) - @midgleyc
- [normalize signature line endings before loading signature block to xml-crypto (#512)](https://github.com/node-saml/passport-saml/commit/915b31da2a2785835065bf9e8db3c7dadcfcd3fc) - @mhassan1
- [fix: derive SamlConfig from SAMLOptions (#515)](https://github.com/node-saml/passport-saml/commit/29d997f48700b0b56e9f270e35a85f792afaeaad) - @midgleyc
- [fix(typing): Export Multi SAML types (#505)](https://github.com/node-saml/passport-saml/commit/cfd08b6c0e74dbb2208a50b131cd76fc219ee85a) - @echojoshchen
- [docs(scoping): fix for example (#504)](https://github.com/node-saml/passport-saml/commit/f6329ea505a6e6d07eb682270565ab6395832a59) - @rob-gijsens
- [upgrade deps to latest versions](https://github.com/node-saml/passport-saml/commit/28e481cc1ef86a16bdbddb2f074b475e051c910f) - @gugu
- [Bump ini from 1.3.5 to 1.3.8](https://github.com/node-saml/passport-saml/commit/f004897d641fb76c25cb8459a4e7677373a5b58c) - @dependabot[bot]
- [run tsc when package is installed as github dependency](https://github.com/node-saml/passport-saml/commit/f515f5ed0972a3c3e46ed0236ce048f0f703f83f) - @gugu
- [add ts-ignore to generated type definitions for multisaml strategy](https://github.com/node-saml/passport-saml/commit/4dcef6b161d8627f4334193e14867972fc6f8432) - @gugu
- [Fix typo in README (#506)](https://github.com/node-saml/passport-saml/commit/9c9c53d9d3f93caeb3721031860aea9f7cba3108) - @oakmac
- [fix(typing): multi saml stratey export (#503)](https://github.com/node-saml/passport-saml/commit/c5ceaca215591a7ce1009661ef48cdc64beba624) - @rob-gijsens
- [Add support for prettier + eslint + watcher (#493)](https://github.com/node-saml/passport-saml/commit/33385164c3c0c19daf6397651db958243df7d7b5) - @cjbarth
- [support windows line breaks in keys](https://github.com/node-saml/passport-saml/commit/d97d7e316f8c086309201dc594053b99fb6de40b) - @gugu
- [Release 2.0.2](https://github.com/node-saml/passport-saml/commit/711956c717d7f843638b35431026adc6d365f010) - @markstos
- [chore: release-it Github Release support.](https://github.com/node-saml/passport-saml/commit/02f3e0996fba1a645c4ea4ea295c1e5da8595f22) - @markstos
- [chore: bump version in package-lock.json](https://github.com/node-saml/passport-saml/commit/0da87a2aef524152f00148459fe9ad25fd260ee0) - @markstos
- [deps: add release-it dev dep](https://github.com/node-saml/passport-saml/commit/dc1f2f04f80c1cb8bbfc107b6bde7c3e10f071d7) - @markstos
- [normalize line endings before signature validation](https://github.com/node-saml/passport-saml/commit/02c6c5aa700c2aa32f414d590926e5f5ee3af2df) - @mhassan1
- [v2.0.1](https://github.com/node-saml/passport-saml/commit/b349e4b3c5136c478b4183d617a698300fef9681) - @markstos
- [Add deprecation notice for privateCert; fix bug (#492)](https://github.com/node-saml/passport-saml/commit/c2f32c6de20d0ee5e25be80c95fb57f921572472) - @cjbarth
- [v2.0.0](https://github.com/node-saml/passport-saml/commit/be111f3a231fe917bfe42104e42a952bfc843ebe) - @markstos
- [add multiSamlStrategy.d.ts to the package](https://github.com/node-saml/passport-saml/commit/13b491cdeb97a284d47ae997e50a1cd845b9e65b) - @gugu
- [add multiSamlStrategy.d.ts to exclude for typescript](https://github.com/node-saml/passport-saml/commit/b2d5b0ba2bb9c7ffa2d6d524993e8b1a995c3a46) - @gugu
- [code style](https://github.com/node-saml/passport-saml/commit/bfcff604b7ed43db42d024a1eb8e5ce642776c09) - @gugu
- [as Node[] => as Attr[] in xpath response](https://github.com/node-saml/passport-saml/commit/4382bea7d30f1904f579a5d6a45319852939d714) - @gugu
- [strict TS types, Strategy and MultiSamlStrategy use native classes](https://github.com/node-saml/passport-saml/commit/0a9255f13d61142d314d03b8ec194ea86669785c) - @gugu
- [v1.5.0](https://github.com/node-saml/passport-saml/commit/29abcb8c2b2c035b2af30f23030f5edc7d5ebb46) - @markstos
- [Allow for use of privateKey instead of privateCert (#488)](https://github.com/node-saml/passport-saml/commit/8046db027e8172be63ba488d1d42b1b48ade67a5) - @alon85
- [inlineSources option for better source maps (#487)](https://github.com/node-saml/passport-saml/commit/0f1a414eac62c0d7b4db1b9e14a95ba1d0bee741) - @gugu
- [Always throw error objects instead of strings (#412)](https://github.com/node-saml/passport-saml/commit/86781395c9c38dd75cbc98aaa562de8a95c225b5) - @Gekkio
- [feat(authorize-request): idp scoping provider (#428)](https://github.com/node-saml/passport-saml/commit/a11ad61841f3cf7d5f3c2195e225329598dc11b5) - @rob-gijsens
- [update version of xml2js to 0.4.23, fixes #479](https://github.com/node-saml/passport-saml/commit/881208bbcd4d34ca4dc26aad3dd9be919cf9f2f2) - @gugu
- [fix: disable esmoduleInterop setting](https://github.com/node-saml/passport-saml/commit/91b6d72a3326aa38f3c22326579cd92553c22a36) - @robcresswell
- [validateSignature: Support XML docs that contain multiple signed nodes. Only select the signatures which reference the currentNode. (#481)](https://github.com/node-saml/passport-saml/commit/7b71596d099302cd84313b229e4d6fc01e768527) - @vandernorth
- [Revert "validateSignature: Support XML docs that contain multiple signed nodes (#455)" (#480)](https://github.com/node-saml/passport-saml/commit/aa4fa868251bbc687e176e17254f9d37cf5056ba) - @cjbarth
- [validateSignature: Support XML docs that contain multiple signed nodes (#455)](https://github.com/node-saml/passport-saml/commit/43df9ad3bd38ddf759d240e580ba0f490cc1d166) - @vandernorth
- [outdated Q library was removed](https://github.com/node-saml/passport-saml/commit/056e6dd0878a911078aace2d2cee5ff5629bccc5) - @gugu
- [v1.4.2](https://github.com/node-saml/passport-saml/commit/4c14bea49d0aa87f6afd548be695fb3db1f453f8) - @markstos
- [primary files use typescript](https://github.com/node-saml/passport-saml/commit/decc5d64be8bd916981fc06d7dfe397444b21969) - @gugu
- [saml.ts switched to typescript](https://github.com/node-saml/passport-saml/commit/b5aab0690cae1a91c0c0ef0830b371c399e6e480) - @gugu
- [v1.4.1](https://github.com/node-saml/passport-saml/commit/c226896cad3c5b00020beeae52ecd55564321846) - @markstos
- [compatibility with @types/passport-saml](https://github.com/node-saml/passport-saml/commit/756ed75daf7b7162cd5ca57ee76f91197e6a5a54) - @gugu
- [chore: version bump to 1.4.0](https://github.com/node-saml/passport-saml/commit/cc24d78d21c0a0d8d1d3ecf3c272e2618bb5509a) - @markstos
- [chore: Allow mocha globals in tests.](https://github.com/node-saml/passport-saml/commit/4e93c900fa04fa889ba332ba99ad08794f877fc3) - @markstos
- [fix returning value for signer](https://github.com/node-saml/passport-saml/commit/33caa06abbb60175aa2b6abec26bb2ffb7cc3d45) - @gugu
- [types for return values for algorithms](https://github.com/node-saml/passport-saml/commit/733e865404ab2bb142ffe527ba901d2d1ecafacc) - @gugu
- [add types to cache provider](https://github.com/node-saml/passport-saml/commit/7da6e8078a71b7a989abb72a0ede50d25f2c1652) - @gugu
- [migrated secondary files to typescript, add .d.ts and sourcemaps](https://github.com/node-saml/passport-saml/commit/19afcb24b0360d2f303742305fb750db548c08c5) - @gugu
- [chore: update package-lock.json, remove yarn.lock.](https://github.com/node-saml/passport-saml/commit/dc9eb8deb098b60b1e2a6cdb5a3b2af08c0eaad4) - @markstos
- [bumped xml-crypto from 1.5.3 to 2.0.0](https://github.com/node-saml/passport-saml/commit/104788ed40b7a9474335789eb6c82ccebed9c3a1) - @KeiferC
- [don't package src folder](https://github.com/node-saml/passport-saml/commit/c81a47cb61c065888887bc5f39a39b698ac60426) - @gugu
- [typescript: fix test running](https://github.com/node-saml/passport-saml/commit/8c0226c9140ff6c8c3487611108882c91a03b6b0) - @gugu
- [temporary make eslint return true after linting](https://github.com/node-saml/passport-saml/commit/e835f03c7be34a751c596e13ef60ffc39a5c3dcf) - @gugu
- [use src directory instead](https://github.com/node-saml/passport-saml/commit/1a57f472bc67c5c8b618520687a241252f689bd6) - @gugu
- [prepublish hook](https://github.com/node-saml/passport-saml/commit/2545286d1c1c2a15b3b09c08b2e0266d1d55cb9a) - @gugu
- [support typescript compilation](https://github.com/node-saml/passport-saml/commit/aa7636bb785c50565ad52b39db566bcaba55a042) - @gugu
- [Add PR template (#473)](https://github.com/node-saml/passport-saml/commit/dca255639c00670278bcd8aea185662ebe1036c5) - @cjbarth
- [Drop support for Node 8](https://github.com/node-saml/passport-saml/commit/08482ad2d0ee1ca4b6b5b4f4788f6d97304109ca) - @walokra
- [try to use curl when wget is not available (#468)](https://github.com/node-saml/passport-saml/commit/026edf2a422f70ee8f483c902594bf29a27def3c) - @rod-stuchi
- [Include package-lock.json in repo](https://github.com/node-saml/passport-saml/commit/b4b7fcc6de7c0436bfabe6a85383ab7cf8621c06) - @mans0954
- [Bump xml-crypto from 1.4.0 to 1.5.3](https://github.com/node-saml/passport-saml/commit/cbf7483c92ef3659ed19874b754f36e0c9f9277d) - @mans0954
- [Only make an attribute an object if it has child elements](https://github.com/node-saml/passport-saml/commit/384b28d672bd473d048009de8f1a9fe052a78b7c) - @mans0954
- [Add GitHub Actions as Continuos Integration provider (#463)](https://github.com/node-saml/passport-saml/commit/df8eb78a3d01e5decb18fb755b2a353bd7d680bc) - @walokra
- [Add test for issue 459](https://github.com/node-saml/passport-saml/commit/7995eeffd5267e0f468dd518c103aea70a8d31a3) - @mans0954
- [add catch block to NameID decryption (#461)](https://github.com/node-saml/passport-saml/commit/43465d6b4957218b05ca040dd5c8d853a1208cbd) - @bryan-lockhart
- [docs: remove badges broken by project rename.](https://github.com/node-saml/passport-saml/commit/e0480e13dba1c6635763cf31d2bb942a930bcc70) - @markstos
- [bump version to 1.3.5](https://github.com/node-saml/passport-saml/commit/9115a02b518d808335b7e88b63c82f71d05974d3) - @markstos
- [deps: really bump xml-encryption for node-forge sub-dep upgrade to address vuln.](https://github.com/node-saml/passport-saml/commit/b696e5895b8a7aa530280671d40ad487201a0564) - @markstos
- [docs: Update package.json / README to reflect site move.](https://github.com/node-saml/passport-saml/commit/af98f3677fc6bc3250e74f476be63551c09f5c33) - @markstos
- [deps: bump xml-encryption to address node-forge sub-dep vuln.](https://github.com/node-saml/passport-saml/commit/1e6ec3987000a1e7a4145ecd7ff40fe699e977d8) - @markstos
- [Update issue templates](https://github.com/node-saml/passport-saml/commit/bfcdb78f683937c51afe68d29269bac9fd87e24e) - @markstos
- [Update issue templates](https://github.com/node-saml/passport-saml/commit/85ffa052265795ab1894fe7339d5f561c698d6ce) - @markstos
- [Bump lodash from 4.17.15 to 4.17.20 (#449)](https://github.com/node-saml/passport-saml/commit/5abba17e10ccb404e5575e0ba94940a233528286) - @dependabot[bot]
- [Bump acorn from 7.1.0 to 7.4.0 (#448)](https://github.com/node-saml/passport-saml/commit/8a8d82bdd34df037768d751aec4088ed392f7d3e) - @dependabot[bot]
- [Return object for XML-valued AttributeValues (#447)](https://github.com/node-saml/passport-saml/commit/aed4a3d26ee3daba14fd08ede1465997b3a15468) - @mans0954
- [Revert "doc: announce site move." (#446)](https://github.com/node-saml/passport-saml/commit/bb025e645ecc7d9b78963e7f807ee90544be5f9a) - @mans0954
- [doc: announce site move.](https://github.com/node-saml/passport-saml/commit/f64cc7a30a916adb81e4451842b58b759651a7ca) - @markstos
- [add yarn-error.log to .gitignore](https://github.com/node-saml/passport-saml/commit/8fdd087ae9ef627f49f9addc5ab44f100de1b92d) - @markstos
- [bump version.](https://github.com/node-saml/passport-saml/commit/66bf7d611a9d7ab9e7ce5293ef437f23609c29f2) - @markstos
- [Fix multi saml strategy race conditions (#426)](https://github.com/node-saml/passport-saml/commit/ffbd2f61e05e8c6e932422fb4f54523b15c106df) - @stavros-wb
- [Fix typo](https://github.com/node-saml/passport-saml/commit/bf83d238f7edc75df5f0777e0362f3f7e38f7de0) - @willemli
- [v1.3.3](https://github.com/node-saml/passport-saml/commit/74fa6307652d3c7d785725655ce63a755938b270) - @markstos
- [Singleline private keys (#423)](https://github.com/node-saml/passport-saml/commit/fb1bda0d19e5b206e772562bf0ab6d1a1ce96ae4) - @big-kahuna-burger
- [v1.3.2](https://github.com/node-saml/passport-saml/commit/e70b6db8be2134620fa31345ec3fc12ab7017033) - @markstos
- [Revert "convert privateCert to PEM for signing" (#421)](https://github.com/node-saml/passport-saml/commit/a224a31fc7e711c73a81138e0bfc6e60ccf19344) - @markstos
- [Upgrade xml-encryption to 1.0.0 (#420)](https://github.com/node-saml/passport-saml/commit/707211ccd722b0cbb12a5b96a6ba3296228201e9) - @brandon-leapyear
- [deps: bump yarn.lock to match package.json](https://github.com/node-saml/passport-saml/commit/1869d272f53263abd259d39ac59f87457ba99e8d) - @markstos

---

## 0.0.3 (01/01/1970)
- [Generating changelog using gren](https://github.com/node-saml/passport-saml/commit/9bc09b97063b10be3e323e18523e8de453332d6d) - @gugu
- [Reexport SamlConfig type to solve a regression in consumer packages (#516)](https://github.com/node-saml/passport-saml/commit/c61cbad96c742ebde36f2b4fff2408675e6f30b6) - @carboneater
- [dev: add @types/xml-encryption](https://github.com/node-saml/passport-saml/commit/51a154cd142fff7c932352ffcbf0825f38343cf8) - @midgleyc
- [normalize signature line endings before loading signature block to xml-crypto (#512)](https://github.com/node-saml/passport-saml/commit/915b31da2a2785835065bf9e8db3c7dadcfcd3fc) - @mhassan1
- [fix: derive SamlConfig from SAMLOptions (#515)](https://github.com/node-saml/passport-saml/commit/29d997f48700b0b56e9f270e35a85f792afaeaad) - @midgleyc
- [fix(typing): Export Multi SAML types (#505)](https://github.com/node-saml/passport-saml/commit/cfd08b6c0e74dbb2208a50b131cd76fc219ee85a) - @echojoshchen
- [docs(scoping): fix for example (#504)](https://github.com/node-saml/passport-saml/commit/f6329ea505a6e6d07eb682270565ab6395832a59) - @rob-gijsens
- [upgrade deps to latest versions](https://github.com/node-saml/passport-saml/commit/28e481cc1ef86a16bdbddb2f074b475e051c910f) - @gugu
- [Bump ini from 1.3.5 to 1.3.8](https://github.com/node-saml/passport-saml/commit/f004897d641fb76c25cb8459a4e7677373a5b58c) - @dependabot[bot]
- [run tsc when package is installed as github dependency](https://github.com/node-saml/passport-saml/commit/f515f5ed0972a3c3e46ed0236ce048f0f703f83f) - @gugu
- [add ts-ignore to generated type definitions for multisaml strategy](https://github.com/node-saml/passport-saml/commit/4dcef6b161d8627f4334193e14867972fc6f8432) - @gugu
- [Fix typo in README (#506)](https://github.com/node-saml/passport-saml/commit/9c9c53d9d3f93caeb3721031860aea9f7cba3108) - @oakmac
- [fix(typing): multi saml stratey export (#503)](https://github.com/node-saml/passport-saml/commit/c5ceaca215591a7ce1009661ef48cdc64beba624) - @rob-gijsens
- [Add support for prettier + eslint + watcher (#493)](https://github.com/node-saml/passport-saml/commit/33385164c3c0c19daf6397651db958243df7d7b5) - @cjbarth
- [support windows line breaks in keys](https://github.com/node-saml/passport-saml/commit/d97d7e316f8c086309201dc594053b99fb6de40b) - @gugu
- [Release 2.0.2](https://github.com/node-saml/passport-saml/commit/711956c717d7f843638b35431026adc6d365f010) - @markstos
- [chore: release-it Github Release support.](https://github.com/node-saml/passport-saml/commit/02f3e0996fba1a645c4ea4ea295c1e5da8595f22) - @markstos
- [chore: bump version in package-lock.json](https://github.com/node-saml/passport-saml/commit/0da87a2aef524152f00148459fe9ad25fd260ee0) - @markstos
- [deps: add release-it dev dep](https://github.com/node-saml/passport-saml/commit/dc1f2f04f80c1cb8bbfc107b6bde7c3e10f071d7) - @markstos
- [normalize line endings before signature validation](https://github.com/node-saml/passport-saml/commit/02c6c5aa700c2aa32f414d590926e5f5ee3af2df) - @mhassan1
- [v2.0.1](https://github.com/node-saml/passport-saml/commit/b349e4b3c5136c478b4183d617a698300fef9681) - @markstos
- [Add deprecation notice for privateCert; fix bug (#492)](https://github.com/node-saml/passport-saml/commit/c2f32c6de20d0ee5e25be80c95fb57f921572472) - @cjbarth
- [v2.0.0](https://github.com/node-saml/passport-saml/commit/be111f3a231fe917bfe42104e42a952bfc843ebe) - @markstos
- [add multiSamlStrategy.d.ts to the package](https://github.com/node-saml/passport-saml/commit/13b491cdeb97a284d47ae997e50a1cd845b9e65b) - @gugu
- [add multiSamlStrategy.d.ts to exclude for typescript](https://github.com/node-saml/passport-saml/commit/b2d5b0ba2bb9c7ffa2d6d524993e8b1a995c3a46) - @gugu
- [code style](https://github.com/node-saml/passport-saml/commit/bfcff604b7ed43db42d024a1eb8e5ce642776c09) - @gugu
- [as Node[] => as Attr[] in xpath response](https://github.com/node-saml/passport-saml/commit/4382bea7d30f1904f579a5d6a45319852939d714) - @gugu
- [strict TS types, Strategy and MultiSamlStrategy use native classes](https://github.com/node-saml/passport-saml/commit/0a9255f13d61142d314d03b8ec194ea86669785c) - @gugu
- [v1.5.0](https://github.com/node-saml/passport-saml/commit/29abcb8c2b2c035b2af30f23030f5edc7d5ebb46) - @markstos
- [Allow for use of privateKey instead of privateCert (#488)](https://github.com/node-saml/passport-saml/commit/8046db027e8172be63ba488d1d42b1b48ade67a5) - @alon85
- [inlineSources option for better source maps (#487)](https://github.com/node-saml/passport-saml/commit/0f1a414eac62c0d7b4db1b9e14a95ba1d0bee741) - @gugu
- [Always throw error objects instead of strings (#412)](https://github.com/node-saml/passport-saml/commit/86781395c9c38dd75cbc98aaa562de8a95c225b5) - @Gekkio
- [feat(authorize-request): idp scoping provider (#428)](https://github.com/node-saml/passport-saml/commit/a11ad61841f3cf7d5f3c2195e225329598dc11b5) - @rob-gijsens
- [update version of xml2js to 0.4.23, fixes #479](https://github.com/node-saml/passport-saml/commit/881208bbcd4d34ca4dc26aad3dd9be919cf9f2f2) - @gugu
- [fix: disable esmoduleInterop setting](https://github.com/node-saml/passport-saml/commit/91b6d72a3326aa38f3c22326579cd92553c22a36) - @robcresswell
- [validateSignature: Support XML docs that contain multiple signed nodes. Only select the signatures which reference the currentNode. (#481)](https://github.com/node-saml/passport-saml/commit/7b71596d099302cd84313b229e4d6fc01e768527) - @vandernorth
- [Revert "validateSignature: Support XML docs that contain multiple signed nodes (#455)" (#480)](https://github.com/node-saml/passport-saml/commit/aa4fa868251bbc687e176e17254f9d37cf5056ba) - @cjbarth
- [validateSignature: Support XML docs that contain multiple signed nodes (#455)](https://github.com/node-saml/passport-saml/commit/43df9ad3bd38ddf759d240e580ba0f490cc1d166) - @vandernorth
- [outdated Q library was removed](https://github.com/node-saml/passport-saml/commit/056e6dd0878a911078aace2d2cee5ff5629bccc5) - @gugu
- [v1.4.2](https://github.com/node-saml/passport-saml/commit/4c14bea49d0aa87f6afd548be695fb3db1f453f8) - @markstos
- [primary files use typescript](https://github.com/node-saml/passport-saml/commit/decc5d64be8bd916981fc06d7dfe397444b21969) - @gugu
- [saml.ts switched to typescript](https://github.com/node-saml/passport-saml/commit/b5aab0690cae1a91c0c0ef0830b371c399e6e480) - @gugu
- [v1.4.1](https://github.com/node-saml/passport-saml/commit/c226896cad3c5b00020beeae52ecd55564321846) - @markstos
- [compatibility with @types/passport-saml](https://github.com/node-saml/passport-saml/commit/756ed75daf7b7162cd5ca57ee76f91197e6a5a54) - @gugu
- [chore: version bump to 1.4.0](https://github.com/node-saml/passport-saml/commit/cc24d78d21c0a0d8d1d3ecf3c272e2618bb5509a) - @markstos
- [chore: Allow mocha globals in tests.](https://github.com/node-saml/passport-saml/commit/4e93c900fa04fa889ba332ba99ad08794f877fc3) - @markstos
- [fix returning value for signer](https://github.com/node-saml/passport-saml/commit/33caa06abbb60175aa2b6abec26bb2ffb7cc3d45) - @gugu
- [types for return values for algorithms](https://github.com/node-saml/passport-saml/commit/733e865404ab2bb142ffe527ba901d2d1ecafacc) - @gugu
- [add types to cache provider](https://github.com/node-saml/passport-saml/commit/7da6e8078a71b7a989abb72a0ede50d25f2c1652) - @gugu
- [migrated secondary files to typescript, add .d.ts and sourcemaps](https://github.com/node-saml/passport-saml/commit/19afcb24b0360d2f303742305fb750db548c08c5) - @gugu
- [chore: update package-lock.json, remove yarn.lock.](https://github.com/node-saml/passport-saml/commit/dc9eb8deb098b60b1e2a6cdb5a3b2af08c0eaad4) - @markstos
- [bumped xml-crypto from 1.5.3 to 2.0.0](https://github.com/node-saml/passport-saml/commit/104788ed40b7a9474335789eb6c82ccebed9c3a1) - @KeiferC
- [don't package src folder](https://github.com/node-saml/passport-saml/commit/c81a47cb61c065888887bc5f39a39b698ac60426) - @gugu
- [typescript: fix test running](https://github.com/node-saml/passport-saml/commit/8c0226c9140ff6c8c3487611108882c91a03b6b0) - @gugu
- [temporary make eslint return true after linting](https://github.com/node-saml/passport-saml/commit/e835f03c7be34a751c596e13ef60ffc39a5c3dcf) - @gugu
- [use src directory instead](https://github.com/node-saml/passport-saml/commit/1a57f472bc67c5c8b618520687a241252f689bd6) - @gugu
- [prepublish hook](https://github.com/node-saml/passport-saml/commit/2545286d1c1c2a15b3b09c08b2e0266d1d55cb9a) - @gugu
- [support typescript compilation](https://github.com/node-saml/passport-saml/commit/aa7636bb785c50565ad52b39db566bcaba55a042) - @gugu
- [Add PR template (#473)](https://github.com/node-saml/passport-saml/commit/dca255639c00670278bcd8aea185662ebe1036c5) - @cjbarth
- [Drop support for Node 8](https://github.com/node-saml/passport-saml/commit/08482ad2d0ee1ca4b6b5b4f4788f6d97304109ca) - @walokra
- [try to use curl when wget is not available (#468)](https://github.com/node-saml/passport-saml/commit/026edf2a422f70ee8f483c902594bf29a27def3c) - @rod-stuchi
- [Include package-lock.json in repo](https://github.com/node-saml/passport-saml/commit/b4b7fcc6de7c0436bfabe6a85383ab7cf8621c06) - @mans0954
- [Bump xml-crypto from 1.4.0 to 1.5.3](https://github.com/node-saml/passport-saml/commit/cbf7483c92ef3659ed19874b754f36e0c9f9277d) - @mans0954
- [Only make an attribute an object if it has child elements](https://github.com/node-saml/passport-saml/commit/384b28d672bd473d048009de8f1a9fe052a78b7c) - @mans0954
- [Add GitHub Actions as Continuos Integration provider (#463)](https://github.com/node-saml/passport-saml/commit/df8eb78a3d01e5decb18fb755b2a353bd7d680bc) - @walokra
- [Add test for issue 459](https://github.com/node-saml/passport-saml/commit/7995eeffd5267e0f468dd518c103aea70a8d31a3) - @mans0954
- [add catch block to NameID decryption (#461)](https://github.com/node-saml/passport-saml/commit/43465d6b4957218b05ca040dd5c8d853a1208cbd) - @bryan-lockhart
- [docs: remove badges broken by project rename.](https://github.com/node-saml/passport-saml/commit/e0480e13dba1c6635763cf31d2bb942a930bcc70) - @markstos
- [bump version to 1.3.5](https://github.com/node-saml/passport-saml/commit/9115a02b518d808335b7e88b63c82f71d05974d3) - @markstos
- [deps: really bump xml-encryption for node-forge sub-dep upgrade to address vuln.](https://github.com/node-saml/passport-saml/commit/b696e5895b8a7aa530280671d40ad487201a0564) - @markstos
- [docs: Update package.json / README to reflect site move.](https://github.com/node-saml/passport-saml/commit/af98f3677fc6bc3250e74f476be63551c09f5c33) - @markstos
- [deps: bump xml-encryption to address node-forge sub-dep vuln.](https://github.com/node-saml/passport-saml/commit/1e6ec3987000a1e7a4145ecd7ff40fe699e977d8) - @markstos
- [Update issue templates](https://github.com/node-saml/passport-saml/commit/bfcdb78f683937c51afe68d29269bac9fd87e24e) - @markstos
- [Update issue templates](https://github.com/node-saml/passport-saml/commit/85ffa052265795ab1894fe7339d5f561c698d6ce) - @markstos
- [Bump lodash from 4.17.15 to 4.17.20 (#449)](https://github.com/node-saml/passport-saml/commit/5abba17e10ccb404e5575e0ba94940a233528286) - @dependabot[bot]
- [Bump acorn from 7.1.0 to 7.4.0 (#448)](https://github.com/node-saml/passport-saml/commit/8a8d82bdd34df037768d751aec4088ed392f7d3e) - @dependabot[bot]
- [Return object for XML-valued AttributeValues (#447)](https://github.com/node-saml/passport-saml/commit/aed4a3d26ee3daba14fd08ede1465997b3a15468) - @mans0954
- [Revert "doc: announce site move." (#446)](https://github.com/node-saml/passport-saml/commit/bb025e645ecc7d9b78963e7f807ee90544be5f9a) - @mans0954
- [doc: announce site move.](https://github.com/node-saml/passport-saml/commit/f64cc7a30a916adb81e4451842b58b759651a7ca) - @markstos
- [add yarn-error.log to .gitignore](https://github.com/node-saml/passport-saml/commit/8fdd087ae9ef627f49f9addc5ab44f100de1b92d) - @markstos
- [bump version.](https://github.com/node-saml/passport-saml/commit/66bf7d611a9d7ab9e7ce5293ef437f23609c29f2) - @markstos
- [Fix multi saml strategy race conditions (#426)](https://github.com/node-saml/passport-saml/commit/ffbd2f61e05e8c6e932422fb4f54523b15c106df) - @stavros-wb
- [Fix typo](https://github.com/node-saml/passport-saml/commit/bf83d238f7edc75df5f0777e0362f3f7e38f7de0) - @willemli
- [v1.3.3](https://github.com/node-saml/passport-saml/commit/74fa6307652d3c7d785725655ce63a755938b270) - @markstos
- [Singleline private keys (#423)](https://github.com/node-saml/passport-saml/commit/fb1bda0d19e5b206e772562bf0ab6d1a1ce96ae4) - @big-kahuna-burger
- [v1.3.2](https://github.com/node-saml/passport-saml/commit/e70b6db8be2134620fa31345ec3fc12ab7017033) - @markstos
- [Revert "convert privateCert to PEM for signing" (#421)](https://github.com/node-saml/passport-saml/commit/a224a31fc7e711c73a81138e0bfc6e60ccf19344) - @markstos
- [Upgrade xml-encryption to 1.0.0 (#420)](https://github.com/node-saml/passport-saml/commit/707211ccd722b0cbb12a5b96a6ba3296228201e9) - @brandon-leapyear
- [deps: bump yarn.lock to match package.json](https://github.com/node-saml/passport-saml/commit/1869d272f53263abd259d39ac59f87457ba99e8d) - @markstos
- [Add tests to check for correct logout (#418)](https://github.com/node-saml/passport-saml/commit/ac7939fc1f74c3a350cee99d68268de7391db41e) - @cjbarth
