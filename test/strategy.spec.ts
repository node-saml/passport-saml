"use strict";

import type * as express from "express";
import { expect } from "chai";
import * as sinon from "sinon";
import { Profile, SAML, Strategy as SamlStrategy } from "../src";
import {
  RequestWithUser,
  VerifiedCallback,
  VerifyWithoutRequest,
  PassportSamlConfig,
} from "../src/types";
import { FAKE_CERT } from "./types";

const noop = () => undefined;

describe("Strategy()", function () {
  it("should require ctor `options` argument", function () {
    // @ts-ignore
    expect(() => new SamlStrategy(noop)).to.throw("Mandatory SAML options missing");
  });

  it("should require that `signonVerify` be a function", function () {
    // @ts-ignore
    expect(() => new SamlStrategy({}, {})).to.throw(
      "SAML authentication strategy requires a verify function"
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
        query: { SAMLResponse: {} },
        url: "https://www.example.com/?key=value",
        logout: logoutSpy,
        res: { send: noop },
      } as unknown as RequestWithUser;
      requestWithUserPostResponse = {
        body: { SAMLResponse: {} },
        logout: logoutSpy,
        res: { send: noop },
      } as unknown as RequestWithUser;
      requestWithUserPostRequest = {
        body: { SAMLRequest: {} },
        url: "https://www.example.com/?key=value",
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
        {
          authnRequestBinding: "HTTP-POST",
          cert: FAKE_CERT,
          issuer: "onesaml_login",
        },
        noop,
        noop
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
      const strategy = new SamlStrategy(
        {
          cert: FAKE_CERT,
          issuer: "onesaml_login",
        },
        noop,
        noop
      );

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, { samlFallback: "logout-request" });

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getLogoutUrlAsyncStub);
        done();
      });
    });

    it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST for login-request", function (done) {
      const strategy = new SamlStrategy({ cert: FAKE_CERT, issuer: "onesaml_login" }, noop, noop);

      // This returns immediately, but calls async functions; need to turn event loop
      strategy.authenticate(requestWithUser, {});

      setImmediate(() => {
        sinon.assert.notCalled(errorStub);
        sinon.assert.calledOnce(getAuthorizeUrlStub);
        sinon.assert.calledOnce(redirectStub);
        done();
      });
    });

    it("determines that logout was unsuccessful where user doesn't match, POST", function (done) {
      const strategy = new SamlStrategy(
        { cert: FAKE_CERT, passReqToCallback: true, issuer: "onesaml_login" },
        function (req: express.Request, _profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          cb(new Error("Logout shouldn't call signon."));
        },
        function (req: express.Request, _profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        }
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
          sinon.match.func
        );
        sinon.assert.calledOnce(getLogoutResponseUrlStub);
        sinon.assert.calledOnce(logoutSpy);
        done();
      });
    });

    it("determines that logout was successful where user matches, GET", function (done) {
      const strategy = new SamlStrategy(
        { cert: FAKE_CERT, issuer: "onesaml_login" },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          cb(new Error("Logout shouldn't call signon."));
        },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        }
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
          sinon.match.func
        );
        sinon.assert.calledOnce(getLogoutResponseUrlStub);
        sinon.assert.calledOnceWithMatch(redirectStub, requestWithUserGetResponse.url);
        sinon.assert.calledOnce(logoutSpy);
        done();
      });
    });

    it("determines that signon was successful where user matches, POST", function (done) {
      const strategy = new SamlStrategy(
        { cert: FAKE_CERT, issuer: "onesaml_login" },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for signon
          if (_profile) {
            cb(null, { name: _profile.nameID });
          }
        },
        function (_profile: Profile | null, cb: VerifiedCallback) {
          // for logout
          cb(new Error("Signon shouldn't call logout."));
        }
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
      new SamlStrategy({ cert: FAKE_CERT, issuer: "onesaml_login" }, noop, noop).logout(
        {
          // @ts-expect-error
          query: "",
        },
        noop
      );
      sinon.assert.calledOnce(getLogoutUrlAsyncStub);
    });
  });

  describe("generateServiceProviderMetadata", function () {
    let generateServiceProviderMetadataStub: sinon.SinonStub;

    beforeEach(function () {
      generateServiceProviderMetadataStub = sinon.stub(
        SAML.prototype,
        "generateServiceProviderMetadata"
      );
    });

    afterEach(function () {
      generateServiceProviderMetadataStub.restore();
    });

    it("should call through to generate metadata", function () {
      const samlConfig: PassportSamlConfig = { cert: FAKE_CERT, issuer: "onesaml_login" };
      const signonVerify: VerifyWithoutRequest = function (): void {
        throw Error("This shouldn't be called to generate metadata");
      };

      const logoutVerify: VerifyWithoutRequest = function (): void {
        throw Error("This shouldn't be called to generate metadata");
      };
      new SamlStrategy(samlConfig, signonVerify, logoutVerify).generateServiceProviderMetadata("");
      sinon.assert.calledOnce(generateServiceProviderMetadataStub);
    });
  });
});
