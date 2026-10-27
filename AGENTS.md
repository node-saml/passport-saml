# AGENTS.md

## What this is

`@node-saml/passport-saml` is the SAML 2.0 strategy for Passport. It sits between an
Express application and `@node-saml/node-saml`: it decides which node-saml validator a
request goes to, hands that validator the message the IdP sent, and turns node-saml's
verdict into a Passport outcome and a call to the application's verify function.

node-saml decides whether a SAML message is trustworthy. This library decides what reaches
that decision and what is done with the answer, so a bug here, such as routing a message
around validation or reading a value node-saml never checked, is an authentication bypass
in every application downstream. Treat every change as security-relevant.

## Purpose and scope

Keep the strategy secure, spec-compliant, and easy to use. Verify a concrete security,
correctness, conformance, or usability problem before proposing or doing work.

SAML itself belongs in node-saml: signatures, decryption, assertion and option validation,
and request and metadata generation. A defect there is fixed there, not worked around here.

## How to read this file

This describes the library we intend to have, not uniformly the library we have today.
The codebase carries years of contributions of varying quality, and some of it predates
the standards below.

So: **this file wins over precedent.** Finding an existing pattern that contradicts a rule
here is not permission to copy it — it is a debt. When you touch such code, move it toward
the target if you can do so within the scope you were given. When you can't, leave it alone
rather than widening the change; don't let cleanup swallow the fix you were asked for.

## Layout

- `src/` — TypeScript source; the only code that ships.
- `src/index.ts` — the public barrel. It re-exports all of `@node-saml/node-saml` beside
  this package's own exports, so node-saml's public API is part of this one.
- `src/strategy.ts` — `AbstractStrategy`, whose `authenticate` dispatches each request and
  whose `logout` starts an SP-initiated logout, and `Strategy`, which builds one node-saml
  `SAML` instance at construction.
- `src/multiSamlStrategy.ts` — `MultiSamlStrategy`, which builds a `SAML` instance per
  request from `getSamlOptions` and then runs `AbstractStrategy`'s code.
- `src/types.ts` — types. Of these, `src/index.ts` exports `PassportSamlConfig`,
  `MultiStrategyConfig`, and the verify function types; the rest are internal.
- `test/*.spec.ts` — Mocha specs. `test/types.ts` is a shared fixture helper, not a spec.
- `test/static/` and `docs/xml-signing-example.js` — left from before the SAML code moved
  to node-saml. No spec reads them; signed-XML fixtures belong in node-saml.
- `lib/` — build output. Generated and git-ignored; never edit.

## Commands

- `npm run build` — compile `src/` to `lib/`.
- `npm test` — compiles `src/` with `tsc`, then runs `nyc mocha` over `test/**/*.spec.ts`.
- `npm run lint` — ESLint plus `prettier --check`.
- `npm run lint:fix` — ESLint `--fix` over `src` plus `prettier --write` over everything;
  rewrites files.

`npm test && npm run lint` covers everything. Run it before calling work done.

Test order is randomized on every run (`choma`, wired up in `.mocharc.json`). A test that
depends on another test's leftover state fails intermittently rather than reproducibly, so
don't share mutable state between tests.

CI (`.github/workflows/workflow.yml`) runs the suite twice on every supported Node version:
against `package-lock.json`, and again after `npm update`, against the newest versions the
ranges in `package.json` allow. A change has to pass both.

## Hard constraints

### The supported Node floor is real

`engines` in `package.json` is the contract, and the matrix in
`.github/workflows/workflow.yml` runs the suite on every supported version, oldest
included. Read both rather than assuming; they change. Only Node LTS versions are
supported, and `README.md` states that dropping one is a breaking change that entails a
new major.

Production dependencies have to honor the floor. Development tooling has to install and
run on every version in the CI matrix; a devDependency whose own `engines` asks for a newer
Node is acceptable when every CI job passes.

`tsconfig.json` targets ES2018 with `lib: ["es2018"]`, and `@types/node` is pinned to the
v18 line. Anything newer than that is unavailable in `src/` even when it runs fine on your
local Node.

### The public API is semver-bound

Anything exported from `src/index.ts` is public, including everything it re-exports from
node-saml. So is the behavior applications code against: the verify function signatures
and when each is called, `passReqToCallback`, the strategy `name`, `getSamlOptions`, and
the `samlFallback` and `additionalParams` options to `passport.authenticate()`. Renaming,
removing, or tightening any of these is breaking, and so is moving `@node-saml/node-saml`
to a new major. Changes confined to `devDependencies`, tests, CI, or tooling are not.

Applications install whatever node-saml version the range in `package.json` allows, not
the one in our lockfile. When code here relies on node-saml behavior added in a minor
release, raise the range to that release in the same change.

### Express 4 and Express 5 are both supported

Applications run this strategy on Express 4.16 and later, including Express 5, and the
`README.md` examples are written for both. The public types still come from
`@types/express` 4. In Express 5, `req.body` is `undefined` until a body parser runs, and
`req.query` is a getter. Check `req.body` before reading from it, and don't write to
`req.query`.

## Defense posture

The rules below are invariants, not aspirations, and the standard for each is the same:
**an invariant that no test can fail is not an invariant.** If you add or change one, add
the test that catches its violation, and watch that test fail before you make it pass. If
you find an invariant here with no test behind it, that gap is worth fixing on its own.

### Read only what node-saml checked

- Hand node-saml the message as the IdP sent it. For the Redirect binding, that is the
  original query string from `req.url`, not a re-serialization of `req.query`, because the
  signature covers the bytes as they arrived.
- A value taken from the request is only as trustworthy as what node-saml checked for its
  binding. A Redirect-binding signature covers the SAML message, `RelayState`, and `SigAlg`
  in the query string, and nothing in the body. Under the POST binding, nothing outside the
  SAML message is signed. Read each value from where its binding carries it, and from
  nowhere else.
- Decide the binding once, from where the SAML message is, and let that one decision drive
  both which validator runs and where every other value comes from.
- Read what you need from `req` before calling a verify function that is given it
  (`passReqToCallback`). Application code can change `req`.
- Hand the application the `Profile` that node-saml returned. Don't add to it or change it.

### Every request is answered exactly once

Every path through `authenticate` answers the request exactly once: with one of Passport's
`success`, `fail`, `error`, `redirect`, or `pass`, or, for an HTTP-POST `AuthnRequest`, by
sending the form. A path that answers none leaves the request hanging, and one that answers
twice is a bug however the first answer turned out.

- Fail closed. A validation error, an error from the verify function, and a missing user
  each end in `error` or `fail`, never `success`. Never make a check more permissive to
  get a test green.
- Route every rejected promise to `error` or to the caller's callback. Node exits on an
  unhandled rejection, so one escaping here takes the application down, often over
  nothing worse than one provider's bad configuration.
- Prefer an explicit, specific error over silently accepting a malformed request, and over
  a generic one. The error message is how an integrator distinguishes a misconfiguration
  from an attack.

### Providers don't share what they shouldn't

`MultiSamlStrategy` builds a new `SAML` instance from the merged options on every request,
and runs it in a per-request copy of the strategy. Keep it that way: nothing one provider's
request sets may be visible to another provider's request.

## Make the caller choose

Prefer removing footguns over adding convenience. A default that makes a security decision
on the caller's behalf is a footgun: the caller lives with the consequence without ever
having made the choice, and — worse — never learns the choice existed.

- SAML options, their defaults, and their validation belong to node-saml, which checks
  them when `new SAML()` runs. Don't add defaults or checks for them here, where they would
  drift from node-saml's.
- Don't add a default for anything security-relevant. That includes state shared across
  requests: don't give `MultiSamlStrategy` a shared default `cacheProvider`. One cache
  shared by every provider lets a response to one provider's request pass the
  `InResponseTo` check at another provider's callback, so the application names its cache.
- Keep dangerous-but-legitimate behavior off until asked for, explicitly, by name.
- A choice is only real if it is documented. Document an option this package owns under
  "Config parameter details" in `README.md`, with the sensible values and their trade-offs.
  An option change that doesn't reach `README.md` isn't finished.

## Deprecation strategy

Removing a deprecated API is part of the work, not a someday. The process:

1. **Mark it.** `@deprecated` JSDoc on the export, naming the replacement and the reason in
   one line. This surfaces in the consumer's editor, which is where the migration actually
   starts.
2. **Document it.** A note in `README.md` next to the thing it replaces, with the migration
   in code, not prose.
3. **Keep it working.** A deprecated API keeps its tests and keeps passing them. Deprecation
   is a message to consumers, not permission to let the code rot.
4. **Remove it in a major.** Not before. `CHANGELOG.md` and the release notes carry it.

Don't test deprecation warnings.

node-saml deprecates APIs this library calls. Move to the replacement as soon as doing so
doesn't change what applications see. When it would, the move waits for a major, and the
issue tracking it says why.

## Tests

Tests protect durable, observable behavior, not implementation details. For a strategy,
that means the Passport action `authenticate` takes and its arguments, what the verify
functions receive, and the URL or form sent to the IdP. Security regressions matter most:
a test should ensure that a request cannot reach `success`, or put a value into a response
to the IdP, without passing node-saml's checks.

- The specs stub `SAML.prototype` with sinon, so they test this library's dispatch and its
  Passport contract, not SAML validation. A stub accepts anything, so build request
  fixtures a real request could be, such as a `req.url` whose query string matches
  `req.query`. Where the behavior under test is node-saml's, test it in node-saml.
- `authenticate` returns before its promises settle. The specs wait with `setImmediate`,
  which works because the stubs resolve at once.
- Assert what the application or the IdP would see. With node-saml stubbed, the arguments
  to the call that builds the response to the IdP stand in for that response. How a
  message is handed to a node-saml validator is an implementation detail that changes with
  node-saml's API.
- When a claim depends on what node-saml checks, read the installed code in
  `node_modules/@node-saml/node-saml/lib/`. node-saml's README can lag the release that is
  installed.
- Coverage is reported, not enforced: `check-coverage` is `false` in `.nycrc.json`, and
  Codecov's checks don't block a merge. Uncovered code indicates either inadequately tested
  behavior or code that may be unnecessary; determine which rather than adding tests merely
  to increase coverage. Don't delete a guard to make a branch disappear unless you have
  shown that nothing can reach it.
- Add a test when a change alters what the strategy accepts, rejects, dispatches, or sends.
- For a bug fix, observe the regression test failing for the reported reason before
  applying the fix. "For the reported reason" is the operative part — a test that fails for
  the wrong reason proves nothing and will keep passing after the bug returns.

## Style

- Strict TypeScript (`strict: true`), CommonJS, target ES2018.
- ESLint flat config lives in `eslint.config.mjs` and includes `typescript-eslint`'s
  `strict` preset. `@typescript-eslint/no-non-null-assertion` is an error, so no `!`
  assertions. `no-console` is a warning, and the strategy has no logger: report a problem
  through `error` or the caller's callback instead.
- Prettier owns formatting for everything it can parse, at `printWidth: 100`. It also
  rewraps every paragraph of `README.md` (`proseWrap: always`), so run
  `npm run prettier-format` after editing prose there. Don't hand-format, and don't argue
  with it in review.
- Line endings are LF, enforced by the `linebreak-style` lint rule.

## Comments

Code describes itself. Name things well and keep functions small enough that the _what_
and the _how_ are readable from the code, then don't restate them in prose that goes stale
the first time someone edits the line below it.

Comment only what the code cannot say: _why_ something is done, what would break if it
were done the obvious way, and which non-obvious constraint is being satisfied. Typically,
well-written tests and code are self-documenting.

Don't narrate history. A bug the code no longer has belongs in the commit message and the
PR, and `git blame` leads there.

If a comment is needed at all, keep it DRY. The `it()` name is usually the whole comment.
Link the SAML specification where the code implements it, but link an issue only for a
tricky edge case, where whoever breaks the test might otherwise decide the test is wrong.
Cite, don't quote: name the document and section, such as "SAML 2.0 Bindings, section
3.4.3", and put the URL on its own line. Keep it to a line or two.

A comment reading "call the verify function" above a call to the verify function, or one
restating a field's name as a sentence, earns nothing and costs a review every time the
code beneath it changes. Delete those rather than update them.

JSDoc on exported API is a separate thing and is welcome: it documents the contract for
consumers and surfaces in their editor. Keep it about the contract — parameters, return
values, what throws, what is deprecated — not about the implementation. Reserve the
`/** */` form for that; on internal code and tests it advertises a contract that isn't
there.

## Conventions

- Keep changes minimal and focused; use modern semantic coding practices.
- Work in `src/`, `test/`, and `README.md` unless asked otherwise.
- Never edit `node_modules/` or `lib/`.
- `CHANGELOG.md` is generated from merged pull requests by `npm run changelog`, grouped by
  each pull request's label (`.grenrc.js`). Don't hand-edit it.
- Fill in `.github/pull_request_template.md`: the summary, the issue, the use case, the
  specification link, and the checklist.
- When behavior follows the SAML specification, cite the relevant part. The maintainers use
  the link to keep the library spec-compliant. Start from
  <https://www.oasis-open.org/standards#samlv2.0>.
- Before changing behavior, read the relevant implementation, tests, `README.md`, and
  public API, and node-saml's installed code for anything this library hands to it. Do not
  infer behavior from names or issue descriptions when the repository can answer the
  question. Keep the change scoped to the requested problem; do not combine bug fixes with
  unrelated refactoring or cleanup.
- Scoped does not mean partial: that rule keeps out _unrelated_ work, and a fix is still
  expected to be complete. `AbstractStrategy`'s code runs for both `Strategy` and
  `MultiSamlStrategy`, and a logout is both answered (`authenticate` handling the IdP's
  `LogoutRequest`) and started (`logout()`, or `samlFallback: "logout-request"`). Check
  whether the invariant holds for each, and say in the pull request which ones the fix
  reaches.
- `README.md` examples are code users copy. Run a changed example on the oldest supported
  Node before saying it works.
