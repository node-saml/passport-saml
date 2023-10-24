"use strict";
import * as express from "express";
import { Strategy } from "passport-strategy";
import * as sinon from "sinon";
import { expect } from "chai";
import { MultiSamlStrategy, SAML, AbstractStrategy } from "../src";
import {
  MultiStrategyConfig,
  RequestWithUser,
  StrategyOptionsCallback,
  PassportSamlConfig,
} from "../src/types";
import * as assert from "assert";
import { FAKE_CERT } from "./types";

const noop = () => undefined;

describe("MultiSamlStrategy()", function () {
  it("extends passport Strategy", function () {
    function getSamlOptions(): PassportSamlConfig {
      return { cert: FAKE_CERT, issuer: "onesaml_login" };
    }
    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop, noop);
    expect(strategy).to.be.an.instanceOf(AbstractStrategy);
    expect(strategy).to.be.an.instanceOf(Strategy);
  });

  it("does not require issuer in the SamlOptionsCallback", function () {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const getSamlOptions: StrategyOptionsCallback = (
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      err: Error | null,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      samlOptions?: Partial<PassportSamlConfig>
    ) => {
      // do nothing; the return type is void
    };
  });

  it("throws if wrong finder is provided", function () {
    function createStrategy() {
      return new MultiSamlStrategy({} as MultiStrategyConfig, noop, noop);
    }
    assert.throws(createStrategy);
  });

  describe("authenticate", function () {
    beforeEach(function () {
      this.superAuthenticateStub = sinon.stub(AbstractStrategy.prototype, "authenticate");
    });

    afterEach(function () {
      this.superAuthenticateStub.restore();
    });

    it("calls super with request and auth options", function (done) {
      const superAuthenticateStub = this.superAuthenticateStub;
      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
          sinon.assert.calledOnce(superAuthenticateStub);
          done();
        } catch (err2) {
          done(err2);
        }
      }

      const strategy = new MultiSamlStrategy(
        {
          getSamlOptions,
        },
        noop,
        noop
      );
      // @ts-expect-error
      strategy.authenticate("random", "random");
    });

    it("passes options on to saml strategy", function (done) {
      const passportOptions = {
        passReqToCallback: true,
        getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
          try {
            fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
            expect(strategy._passReqToCallback).to.equal(true);
            done();
          } catch (err2) {
            done(err2);
          }
        },
      };

      const strategy = new MultiSamlStrategy(passportOptions, noop, noop);
      // @ts-expect-error
      strategy.authenticate("random", "random");
    });

    it("uses given options to setup internal saml provider", function (done) {
      const superAuthenticateStub = this.superAuthenticateStub;
      const samlOptions: PassportSamlConfig = {
        issuer: "http://foo.issuer",
        callbackUrl: "http://foo.callback",
        cert: "deadbeef",
        host: "lvh",
        acceptedClockSkewMs: -1,
        identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        path: "/saml/callback",
        logoutUrl: "http://foo.slo",
        signatureAlgorithm: "sha256",
      };

      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, samlOptions);
          sinon.assert.calledOnce(superAuthenticateStub);
          superAuthenticateStub.calledWith(
            Object.assign({}, { cacheProvider: "mock cache provider" }, samlOptions)
          );
          done();
        } catch (err2) {
          done(err2);
        }
      }

      const strategy = new MultiSamlStrategy(
        // @ts-expect-error
        { getSamlOptions, cacheProvider: "mock cache provider" },
        noop,
        noop
      );
      // @ts-expect-error
      strategy.authenticate("random", "random");
    });
  });

  describe("authorize", function () {
    let getAuthorizeFormStub: sinon.SinonStub;
    let getAuthorizeUrlStub: sinon.SinonStub;
    let errorStub: sinon.SinonStub;

    beforeEach(function () {
      getAuthorizeFormStub = sinon.stub(SAML.prototype, "getAuthorizeFormAsync").resolves();
      getAuthorizeUrlStub = sinon.stub(SAML.prototype, "getAuthorizeUrlAsync").resolves();
      errorStub = sinon.stub(MultiSamlStrategy.prototype, "error");
    });

    afterEach(function () {
      getAuthorizeFormStub.restore();
      getAuthorizeUrlStub.restore();
      errorStub.restore();
    });

    it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST", function () {
      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        fn(null, { authnRequestBinding: "HTTP-POST", cert: FAKE_CERT, issuer: "onesaml_login" });
      }
      const strategy = new MultiSamlStrategy({ getSamlOptions }, noop, noop);
      strategy.authenticate({} as RequestWithUser, {});
      sinon.assert.notCalled(errorStub);
      sinon.assert.calledOnce(getAuthorizeFormStub);
    });

    it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function () {
      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
      }
      const strategy = new MultiSamlStrategy({ getSamlOptions }, noop, noop);
      strategy.authenticate({} as RequestWithUser, {});
      sinon.assert.notCalled(errorStub);
      sinon.assert.calledOnce(getAuthorizeUrlStub);
    });
  });

  describe("logout", function () {
    beforeEach(function () {
      this.superLogoutMock = sinon.stub(AbstractStrategy.prototype, "logout");
    });

    afterEach(function () {
      this.superLogoutMock.restore();
    });

    it("calls super with request and auth options", function (done) {
      const superLogoutMock = this.superLogoutMock;
      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
          sinon.assert.calledOnce(superLogoutMock);
          done();
        } catch (err2) {
          done(err2);
        }
      }

      const strategy = new MultiSamlStrategy({ getSamlOptions }, noop, noop);
      // @ts-expect-error
      strategy.logout("random", "random");
    });

    it("passes options on to saml strategy", function (done) {
      const passportOptions = {
        passReqToCallback: true,
        getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
          try {
            fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
            expect(strategy._passReqToCallback).to.equal(true);
            done();
          } catch (err2) {
            done(err2);
          }
        },
      };

      const strategy = new MultiSamlStrategy(passportOptions, noop, noop);
      // @ts-expect-error
      strategy.logout("random", "random");
    });

    it("uses given options to setup internal saml provider", function (done) {
      const superLogoutMock = this.superLogoutMock;
      const samlOptions: PassportSamlConfig = {
        issuer: "http://foo.issuer",
        callbackUrl: "http://foo.callback",
        authnRequestBinding: "HTTP-POST",
        cert: "deadbeef",
        host: "lvh",
        acceptedClockSkewMs: -1,
        identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        path: "/saml/callback",
        logoutUrl: "http://foo.slo",
        signatureAlgorithm: "sha256",
      };

      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, samlOptions);
          sinon.assert.calledOnce(superLogoutMock);
          superLogoutMock.calledWith(Object.assign({}, samlOptions));
          done();
        } catch (err2) {
          done(err2);
        }
      }

      const strategy = new MultiSamlStrategy({ getSamlOptions }, noop, noop);
      // @ts-expect-error
      strategy.logout("random", sinon.spy());
    });
  });

  describe("generateServiceProviderMetadata", function () {
    beforeEach(function () {
      this.superGenerateServiceProviderMetadata = sinon
        .stub(SAML.prototype, "generateServiceProviderMetadata")
        .returns("My Metadata Result");
    });

    afterEach(function () {
      this.superGenerateServiceProviderMetadata.restore();
    });

    it("calls super with request and generateServiceProviderMetadata options", function (done) {
      const superGenerateServiceProviderMetadata = this.superGenerateServiceProviderMetadata;
      function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
          sinon.assert.calledOnce(superGenerateServiceProviderMetadata);
          superGenerateServiceProviderMetadata.calledWith("bar", "baz");
          expect(req).to.equal("foo");
          done();
        } catch (err2) {
          done(err2);
        }
      }

      const strategy = new MultiSamlStrategy({ getSamlOptions }, noop, noop);
      // @ts-expect-error
      strategy.generateServiceProviderMetadata("foo", "bar", "baz", noop);
    });

    it("passes options on to saml strategy", function (done) {
      const passportOptions: MultiStrategyConfig = {
        passReqToCallback: true,

        getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
          try {
            fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
            expect(strategy._passReqToCallback).to.equal(true);
            done();
          } catch (err2) {
            done(err2);
          }
        },
      };

      const strategy = new MultiSamlStrategy(passportOptions, noop, noop);
      // @ts-expect-error
      strategy.generateServiceProviderMetadata("foo", "bar", "baz", noop);
    });

    it("should pass error to callback function", function (done) {
      const passportOptions = {
        getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
          fn(new Error("My error"));
        },
      };

      const strategy = new MultiSamlStrategy(passportOptions, noop, noop);
      // @ts-expect-error
      strategy.generateServiceProviderMetadata("foo", "bar", "baz", function (error) {
        try {
          expect(error?.message).to.equal("My error");
          done();
        } catch (err2) {
          done(err2);
        }
      });
    });

    it("should pass result to callback function", function (done) {
      const passportOptions = {
        getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
          fn(null, { cert: FAKE_CERT, issuer: "onesaml_login" });
        },
      };

      const strategy = new MultiSamlStrategy(passportOptions, noop, noop);
      strategy.generateServiceProviderMetadata(
        // @ts-expect-error
        "foo",
        "bar",
        "baz",
        function (error, result) {
          try {
            expect(result).to.equal("My Metadata Result");
            done();
          } catch (err2) {
            done(err2);
          }
        }
      );
    });
  });
});
