"use strict";

import type * as express from "express";
import { expect } from "chai";
import * as sinon from "sinon";
import { Strategy as SamlStrategy } from "../src";
import { Profile, SAML } from "@node-saml/node-saml";
import { RequestWithUser, VerifiedCallback, VerifyWithoutRequest } from "../src/types";
import { SAML_CONFIG } from "./types";

const noop = () => undefined;

// How a signed Redirect-binding query string ends, as it arrives and as Express parses it.
const sigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const signatureParameters = `SigAlg=${encodeURIComponent(sigAlg)}&Signature=c2lnbmF0dXJl`;
const parsedSignatureParameters = { SigAlg: sigAlg, Signature: "c2lnbmF0dXJl" };
const idpLogoutResponseUrl = "https://idp.example/slo?SAMLResponse=response";

describe("Strategy()", function () {
  it("should require ctor `options` argument", function () {
    // @ts-expect-error `noop` is not a valid options object
    expect(() => new SamlStrategy(noop)).to.throw("Mandatory SAML options missing");
  });

  it("should require that `signonVerify` be a function", function () {
    // @ts-expect-error `{}` is not a valid options object
    expect(() => new SamlStrategy({}, {})).to.throw(
      "SAML authentication strategy requires a verify function",
    );
  });

  describe("authenticate", function () {
    let getAuthorizeFormStub: sinon.SinonStub;
    let getAuthorizeUrlStub: sinon.SinonStub;
    let getLogoutResponseUrlStub: sinon.SinonStub;
    let getLogoutUrlAsyncStub: sinon.SinonStub;
    let validateRedirectAsyncStub: sinon.SinonStub;
    let validatePostResponseAsyncStub: sinon.SinonStub;
    let validatePostRequestAsyncStub: sinon.SinonStub;
    let errorStub: sinon.SinonStub;
    let redirectStub: sinon.SinonStub;
    let successStub: sinon.SinonStub;
    let requestWithUser = {} as unknown as RequestWithUser;
    let requestWithUserGetResponse = {} as unknown as RequestWithUser;
    let requestWithUserPostResponse = {} as unknown as RequestWithUser;
    let requestWithUserPostRequest = {} as unknown as RequestWithUser;
    let logoutSpy: sinon.SinonSpy;

    beforeEach(function () {
      getAuthorizeFormStub = sinon.stub(SAML.prototype, "getAuthorizeFormAsync").resolves();
      getAuthorizeUrlStub = sinon.stub(SAML.prototype, "getAuthorizeUrlAsync").resolves();
      getLogoutResponseUrlStub = sinon.stub(SAML.prototype, "getLogoutResponseUrl");
      getLogoutUrlAsyncStub = sinon.stub(SAML.prototype, "getLogoutUrlAsync").resolves();
      validateRedirectAsyncStub = sinon.stub(SAML.prototype, "validateRedirectAsync").resolves();
      validatePostResponseAsyncStub = sinon
        .stub(SAML.prototype, "validatePostResponseAsync")
        .resolves();
      validatePostRequestAsyncStub = sinon
        .stub(SAML.prototype, "validatePostRequestAsync")
        .resolves();
      errorStub = sinon.stub(SamlStrategy.prototype, "error");
      redirectStub = sinon.stub(SamlStrategy.prototype, "redirect");
      successStub = sinon.stub(SamlStrategy.prototype, "success");
      logoutSpy = sinon.spy();

      requestWithUser = {
        logout: logoutSpy,
        res: { send: noop },
      } as unknown as RequestWithUser;
      requestWithUserGetResponse = {
        query: { SAMLResponse: "response", ...parsedSignatureParameters },
        url: `/logout/callback?SAMLResponse=response&${signatureParameters}`,
        logout: logoutSpy,
        res: { send: noop },
      } as unknown as RequestWithUser;
      requestWithUserPostResponse = {
        body: { SAMLResponse: "response" },
        query: {},
        url: "/login/callback",
        logout: logoutSpy,
        res: { send: noop },
      } as unknown as RequestWithUser;
      requestWithUserPostRequest = {
        body: { SAMLRequest: "request" },
        query: {},
        url: "/logout/callback",
        logout: logoutSpy,
        res: { send: noop },
      } as unknown as RequestWithUser;
    });

    afterEach(function () {
      getAuthorizeFormStub.restore();
      getAuthorizeUrlStub.restore();
      getLogoutResponseUrlStub.restore();
      getLogoutUrlAsyncStub.restore();
      validateRedirectAsyncStub.restore();
      validatePostResponseAsyncStub.restore();
      validatePostRequestAsyncStub.restore();
      errorStub.restore();
      redirectStub.restore();
      successStub.restore();
      logoutSpy.resetHistory();
    });

    it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST for login-request", function (done) {
      const strategy = new SamlStrategy(
        { ...SAML_CONFIG, authnRequestBinding: "HTTP-POST" },
        noop,
        noop,
      );

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getAuthorizeFormStub);
        done();
      });
    });

    it("calls getAuthorizeForm when authnRequestBinding is not HTTP-POST for logout-request", function (done) {
      const strategy = new SamlStrategy(SAML_CONFIG, noop, noop);

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, { samlFallback: "logout-request" });

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getLogoutUrlAsyncStub);
        done();
      });
    });

    it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST for login-request", function (done) {
      const strategy = new SamlStrategy(SAML_CONFIG, noop, noop);

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getAuthorizeUrlStub);
        sinon.assert.calledOnce(redirectStub);
        done();
      });
    });

    it("passes RelayState from the query string to getAuthorizeUrl for login-request", function (done) {
      const strategy = new SamlStrategy(SAML_CONFIG, noop, noop);
      requestWithUser.query = { RelayState: "/reports/42" };
      const options = {};

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, options);

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithExactly(getAuthorizeUrlStub, "/reports/42", options);
        done();
      });
    });

    it("passes RelayState from the body to getAuthorizeForm when authnRequestBinding is HTTP-POST", function (done) {
      const strategy = new SamlStrategy(
        { ...SAML_CONFIG, authnRequestBinding: "HTTP-POST" },
        noop,
        noop,
      );
      requestWithUser.body = { RelayState: "/reports/42" };

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithExactly(getAuthorizeFormStub, "/reports/42");
        done();
      });
    });

    it("returns the IdP's RelayState in the LogoutResponse to an IdP-initiated logout", function (done) {
      const strategy = new SamlStrategy(
        SAML_CONFIG,
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          cb(new Error("Logout shouldn't call signon."));
        },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        },
      );

      validatePostRequestAsyncStub.resolves({
        profile: {
          ID: "ID",
          issuer: "issuer",
          nameID: "some user",
          nameIDFormat: "nameIDFormat",
        },
        loggedOut: true,
      });
      requestWithUserPostRequest.user = { name: "some user" };
      requestWithUserPostRequest.body.RelayState = "idp-relay-state";

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUserPostRequest, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithMatch(
          getLogoutResponseUrlStub,
          sinon.match.any,
          "idp-relay-state",
        );
        done();
      });
    });

    describe("Redirect-binding logout request", function () {
      const logoutRequestProfile = {
        ID: "ID",
        issuer: "issuer",
        nameID: "some user",
        nameIDFormat: "nameIDFormat",
      };
      const queryString = `SAMLRequest=request&RelayState=idp-relay-state&${signatureParameters}`;
      let strategy: SamlStrategy;
      let redirectLogoutRequest: RequestWithUser;

      beforeEach(function () {
        strategy = new SamlStrategy(
          SAML_CONFIG,
          function signonVerify(_profile: Profile | null, cb: VerifiedCallback) {
            cb(new Error("Logout shouldn't call signon."));
          },
          function logoutVerify(profile: Profile | null, cb: VerifiedCallback) {
            cb(null, { name: profile?.nameID });
          },
        );
        validateRedirectAsyncStub.resolves({ profile: logoutRequestProfile, loggedOut: true });
        getLogoutResponseUrlStub.yields(null, idpLogoutResponseUrl);
        redirectLogoutRequest = {
          query: {
            SAMLRequest: "request",
            RelayState: "idp-relay-state",
            ...parsedSignatureParameters,
          },
          url: `/logout/callback?${queryString}`,
          user: { name: "some user" },
          logout: logoutSpy,
          res: { send: noop },
        } as unknown as RequestWithUser;
      });

      it("hands only validateRedirectAsync the parsed query and the query string as it arrived, then redirects to the IdP", function (done) {
        strategy.authenticate(redirectLogoutRequest, {});

        setImmediate(() => {
          sinon.assert.calledOnceWithExactly(
            validateRedirectAsyncStub,
            redirectLogoutRequest.query,
            queryString,
          );
          sinon.assert.notCalled(validatePostRequestAsyncStub);
          sinon.assert.notCalled(validatePostResponseAsyncStub);
          sinon.assert.notCalled(errorStub);
          sinon.assert.calledOnceWithMatch(
            getLogoutResponseUrlStub,
            logoutRequestProfile,
            "idp-relay-state",
          );
          sinon.assert.calledOnceWithExactly(redirectStub, idpLogoutResponseUrl);
          done();
        });
      });

      it("ignores a RelayState in the body, which the query string's signature does not cover", function (done) {
        redirectLogoutRequest.body = { RelayState: "https://evil.example" };

        strategy.authenticate(redirectLogoutRequest, {});

        setImmediate(() => {
          sinon.assert.notCalled(errorStub);
          sinon.assert.calledOnceWithMatch(
            getLogoutResponseUrlStub,
            sinon.match.any,
            "idp-relay-state",
          );
          done();
        });
      });
    });

    describe("POST-binding logout request", function () {
      beforeEach(function () {
        validatePostRequestAsyncStub.resolves({
          profile: {
            ID: "ID",
            issuer: "issuer",
            nameID: "some user",
            nameIDFormat: "nameIDFormat",
          },
          loggedOut: true,
        });
        requestWithUserPostRequest.user = { name: "some user" };
        requestWithUserPostRequest.body.RelayState = "idp-relay-state";
      });

      it("hands only validatePostRequestAsync the body, then redirects to the IdP", function (done) {
        const strategy = new SamlStrategy(
          SAML_CONFIG,
          function signonVerify(_profile: Profile | null, cb: VerifiedCallback) {
            cb(new Error("Logout shouldn't call signon."));
          },
          function logoutVerify(profile: Profile | null, cb: VerifiedCallback) {
            cb(null, { name: profile?.nameID });
          },
        );
        getLogoutResponseUrlStub.yields(null, idpLogoutResponseUrl);

        strategy.authenticate(requestWithUserPostRequest, {});

        setImmediate(() => {
          sinon.assert.calledOnceWithExactly(
            validatePostRequestAsyncStub,
            requestWithUserPostRequest.body,
          );
          sinon.assert.notCalled(validateRedirectAsyncStub);
          sinon.assert.notCalled(validatePostResponseAsyncStub);
          sinon.assert.notCalled(errorStub);
          sinon.assert.calledOnceWithExactly(redirectStub, idpLogoutResponseUrl);
          done();
        });
      });

      it("returns the body's RelayState, where the POST binding carries it, not the query string's", function (done) {
        const strategy = new SamlStrategy(
          SAML_CONFIG,
          function signonVerify(_profile: Profile | null, cb: VerifiedCallback) {
            cb(new Error("Logout shouldn't call signon."));
          },
          function logoutVerify(profile: Profile | null, cb: VerifiedCallback) {
            cb(null, { name: profile?.nameID });
          },
        );
        requestWithUserPostRequest.query = { RelayState: "https://evil.example" };
        requestWithUserPostRequest.url = "/logout/callback?RelayState=https%3A%2F%2Fevil.example";

        strategy.authenticate(requestWithUserPostRequest, {});

        setImmediate(() => {
          sinon.assert.notCalled(errorStub);
          sinon.assert.calledOnceWithMatch(
            getLogoutResponseUrlStub,
            sinon.match.any,
            "idp-relay-state",
          );
          done();
        });
      });

      it("returns the RelayState even if a verifier given the request clears the body", function (done) {
        const strategy = new SamlStrategy(
          { ...SAML_CONFIG, passReqToCallback: true },
          function signonVerify(
            _req: express.Request,
            _profile: Profile | null,
            cb: VerifiedCallback,
          ) {
            cb(new Error("Logout shouldn't call signon."));
          },
          function logoutVerify(
            req: express.Request,
            profile: Profile | null,
            cb: VerifiedCallback,
          ) {
            req.body = undefined;
            cb(null, { name: profile?.nameID });
          },
        );

        strategy.authenticate(requestWithUserPostRequest, {});

        setImmediate(() => {
          sinon.assert.notCalled(errorStub);
          sinon.assert.calledOnceWithMatch(
            getLogoutResponseUrlStub,
            sinon.match.any,
            "idp-relay-state",
          );
          sinon.assert.calledOnce(logoutSpy);
          done();
        });
      });
    });

    it("hands only validatePostResponseAsync the body of a POST-binding SAMLResponse, then succeeds", function (done) {
      const strategy = new SamlStrategy(
        SAML_CONFIG,
        function signonVerify(profile: Profile | null, cb: VerifiedCallback) {
          cb(null, { name: profile?.nameID });
        },
        function logoutVerify(_profile: Profile | null, cb: VerifiedCallback) {
          cb(new Error("Signon shouldn't call logout."));
        },
      );
      validatePostResponseAsyncStub.resolves({
        profile: { ID: "ID", issuer: "issuer", nameID: "some user", nameIDFormat: "nameIDFormat" },
        loggedOut: false,
      });

      strategy.authenticate(requestWithUserPostResponse, {});

      setImmediate(() => {
        sinon.assert.calledOnceWithExactly(
          validatePostResponseAsyncStub,
          requestWithUserPostResponse.body,
        );
        sinon.assert.notCalled(validateRedirectAsyncStub);
        sinon.assert.notCalled(validatePostRequestAsyncStub);
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithExactly(successStub, { name: "some user" }, undefined);
        done();
      });
    });

    it("determines that logout was unsuccessful where user doesn't match, POST", function (done) {
      const strategy = new SamlStrategy(
        { ...SAML_CONFIG, passReqToCallback: true },
        function (req: express.Request, _profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          cb(new Error("Logout shouldn't call signon."));
        },
        function (req: express.Request, _profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        },
      );

      validatePostResponseAsyncStub.resolves({
        profile: {
          ID: "ID",
          issuer: "issuer",
          nameID: "some other user",
          nameIDFormat: "nameIDFormat",
        },
        loggedOut: true,
      });

      // Pretend we already loaded a users session from a cookie or something
      // by calling `strategy.authenticate` when the request comes in
      requestWithUserPostResponse.user = {
        name: "some user",
      };

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUserPostResponse, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithMatch(
          getLogoutResponseUrlStub,
          sinon.match.any,
          sinon.match.any,
          sinon.match.any,
          false,
          sinon.match.func,
        );
        sinon.assert.calledOnce(getLogoutResponseUrlStub);
        sinon.assert.calledOnce(logoutSpy);
        done();
      });
    });

    it("determines that logout was successful where user matches, GET", function (done) {
      const strategy = new SamlStrategy(
        SAML_CONFIG,
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          cb(new Error("Logout shouldn't call signon."));
        },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        },
      );

      validateRedirectAsyncStub.resolves({
        profile: {
          ID: "ID",
          issuer: "issuer",
          nameID: "some user",
          nameIDFormat: "nameIDFormat",
        },
        loggedOut: true,
      });

      // Pretend we already loaded a users session from a cookie or something
      // by calling `strategy.authenticate` when the request comes in
      requestWithUserGetResponse.user = {
        name: "some user",
      };

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUserGetResponse, {});

      getLogoutResponseUrlStub.yields(null, requestWithUserGetResponse.url);

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithMatch(
          getLogoutResponseUrlStub,
          sinon.match.any,
          sinon.match.any,
          sinon.match.any,
          true,
          sinon.match.func,
        );
        sinon.assert.calledOnce(getLogoutResponseUrlStub);
        sinon.assert.calledOnceWithMatch(redirectStub, requestWithUserGetResponse.url);
        sinon.assert.calledOnce(logoutSpy);
        done();
      });
    });

    it("determines that signon was successful where user matches, POST", function (done) {
      const strategy = new SamlStrategy(
        SAML_CONFIG,
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          cb(new Error("Signon shouldn't call logout."));
        },
      );

      validatePostRequestAsyncStub.resolves({
        profile: {
          ID: "ID",
          issuer: "issuer",
          nameID: "some user",
          nameIDFormat: "nameIDFormat",
        },
      });

      // Pretend we already loaded a users session from a cookie or something
      // by calling `strategy.authenticate` when the request comes in
      requestWithUserPostRequest.user = {
        name: "some user",
      };

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUserPostRequest, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnceWithMatch(successStub, requestWithUserPostRequest.user, undefined);
        done();
      });
    });
  });

  describe("logout", function () {
    let getLogoutUrlAsyncStub: sinon.SinonStub;

    beforeEach(function () {
      getLogoutUrlAsyncStub = sinon.stub(SAML.prototype, "getLogoutUrlAsync").resolves();
    });

    afterEach(function () {
      getLogoutUrlAsyncStub.restore();
    });

    it("should call through to get logout URL", function () {
      new SamlStrategy(SAML_CONFIG, noop, noop).logout(
        {
          // @ts-expect-error `string` isn't valid for `query`
          query: "",
        },
        noop,
      );
      sinon.assert.calledOnce(getLogoutUrlAsyncStub);
    });

    it("should pass RelayState through to get logout URL", function () {
      new SamlStrategy(SAML_CONFIG, noop, noop).logout(
        { query: { RelayState: "/goodbye" } } as unknown as RequestWithUser,
        noop,
      );
      sinon.assert.calledOnceWithMatch(getLogoutUrlAsyncStub, sinon.match.any, "/goodbye");
    });
  });

  describe("generateServiceProviderMetadata", function () {
    let generateServiceProviderMetadataStub: sinon.SinonStub;

    beforeEach(function () {
      generateServiceProviderMetadataStub = sinon.stub(
        SAML.prototype,
        "generateServiceProviderMetadata",
      );
    });

    afterEach(function () {
      generateServiceProviderMetadataStub.restore();
    });

    it("should call through to generate metadata", function () {
      const signonVerify: VerifyWithoutRequest = function (): void {
        throw Error("This shouldn't be called to generate metadata");
      };

      const logoutVerify: VerifyWithoutRequest = function (): void {
        throw Error("This shouldn't be called to generate metadata");
      };
      new SamlStrategy(SAML_CONFIG, signonVerify, logoutVerify).generateServiceProviderMetadata("");
      sinon.assert.calledOnce(generateServiceProviderMetadataStub);
    });
  });
});
