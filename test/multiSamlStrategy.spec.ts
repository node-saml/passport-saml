"use strict";
import * as express from "express";
import { Strategy } from "passport-strategy";
import * as sinon from "sinon";
import * as should from "should";
import { MultiSamlStrategy, SAML, AbstractStrategy, SamlConfig } from "../src";
import { MultiStrategyConfig, RequestWithUser, StrategyOptionsCallback } from "../src/types";
import assert = require("assert");
import { FAKE_CERT } from "./types";

const noop = () => undefined;

describe("MultiSamlStrategy()", function () {
  it("extends passport Strategy", function () {
    function getSamlOptions(): SamlConfig {
      return { cert: FAKE_CERT };
    }
    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop);
    strategy.should.be.an.instanceOf(AbstractStrategy);
    strategy.should.be.an.instanceOf(Strategy);
  });

  it("throws if wrong finder is provided", function () {
    function createStrategy() {
      return new MultiSamlStrategy({} as MultiStrategyConfig, noop);
    }
    assert.throws(createStrategy);
  });
});

describe("MultiSamlStrategy#authenticate", function () {
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
        fn(null, { cert: FAKE_CERT });
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
      noop
    );
    strategy.authenticate("random" as any, "random" as any);
  });

  it("passes options on to saml strategy", function (done) {
    const passportOptions = {
      passReqToCallback: true,
      getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, { cert: FAKE_CERT });
          strategy._passReqToCallback!.should.eql(true);
          done();
        } catch (err2) {
          done(err2);
        }
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, noop);
    strategy.authenticate("random" as any, "random" as any);
  });

  it("uses given options to setup internal saml provider", function (done) {
    const superAuthenticateStub = this.superAuthenticateStub;
    const samlOptions: SamlConfig = {
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
      { getSamlOptions, cacheProvider: "mock cache provider" as any },
      noop
    );
    strategy.authenticate("random" as any, "random" as any);
  });
});

describe("MultiSamlStrategy#authorize", function () {
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
      fn(null, { authnRequestBinding: "HTTP-POST", cert: FAKE_CERT });
    }
    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop);
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.notCalled(errorStub);
    sinon.assert.calledOnce(getAuthorizeFormStub);
  });

  it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function () {
    function getSamlOptions(req: express.Request, fn: StrategyOptionsCallback) {
      fn(null, { cert: FAKE_CERT });
    }
    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop);
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.notCalled(errorStub);
    sinon.assert.calledOnce(getAuthorizeUrlStub);
  });
});

describe("MultiSamlStrategy#logout", function () {
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
        fn(null, { cert: FAKE_CERT });
        sinon.assert.calledOnce(superLogoutMock);
        done();
      } catch (err2) {
        done(err2);
      }
    }

    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop);
    strategy.logout("random" as any, "random" as any);
  });

  it("passes options on to saml strategy", function (done) {
    const passportOptions = {
      passReqToCallback: true,
      getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, { cert: FAKE_CERT });
          strategy._passReqToCallback!.should.eql(true);
          done();
        } catch (err2) {
          done(err2);
        }
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, noop);
    strategy.logout("random" as any, "random" as any);
  });

  it("uses given options to setup internal saml provider", function (done) {
    const superLogoutMock = this.superLogoutMock;
    const samlOptions: SamlConfig = {
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

    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop);
    strategy.logout("random" as any, sinon.spy());
  });
});

describe("MultiSamlStrategy#generateServiceProviderMetadata", function () {
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
        fn(null, { cert: FAKE_CERT });
        sinon.assert.calledOnce(superGenerateServiceProviderMetadata);
        superGenerateServiceProviderMetadata.calledWith("bar", "baz");
        req.should.eql("foo");
        done();
      } catch (err2) {
        done(err2);
      }
    }

    const strategy = new MultiSamlStrategy({ getSamlOptions }, noop);
    strategy.generateServiceProviderMetadata("foo" as any, "bar", "baz", noop);
  });

  it("passes options on to saml strategy", function (done) {
    const passportOptions: MultiStrategyConfig = {
      passReqToCallback: true,

      getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
        try {
          fn(null, { cert: FAKE_CERT });
          strategy._passReqToCallback!.should.eql(true);
          done();
        } catch (err2) {
          done(err2);
        }
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, noop);
    strategy.generateServiceProviderMetadata("foo" as any, "bar", "baz", noop);
  });

  it("should pass error to callback function", function (done) {
    const passportOptions = {
      getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
        fn(new Error("My error"));
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, noop);
    strategy.generateServiceProviderMetadata("foo" as any, "bar", "baz", function (error, result) {
      try {
        should(error?.message).equal("My error");
        done();
      } catch (err2) {
        done(err2);
      }
    });
  });

  it("should pass result to callback function", function (done) {
    const passportOptions = {
      getSamlOptions: function (req: express.Request, fn: StrategyOptionsCallback) {
        fn(null, { cert: FAKE_CERT });
      },
    };

    const strategy = new MultiSamlStrategy(passportOptions, noop);
    strategy.generateServiceProviderMetadata("foo" as any, "bar", "baz", function (error, result) {
      try {
        should(result).equal("My Metadata Result");
        done();
      } catch (err2) {
        done(err2);
      }
    });
  });
});
