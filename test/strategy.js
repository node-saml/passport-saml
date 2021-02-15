"use strict";

var sinon = require("sinon");
var saml = require("../lib/passport-saml/saml.js");
var SamlStrategy = require("../lib/passport-saml/index.js").Strategy;

function verify() {}

describe("strategy#authorize", function () {
  beforeEach(function () {
    this.getAuthorizeFormStub = sinon.stub(saml.SAML.prototype, "getAuthorizeForm");
    this.getAuthorizeUrlStub = sinon.stub(saml.SAML.prototype, "getAuthorizeUrl");
  });

  afterEach(function () {
    this.getAuthorizeFormStub.restore();
    this.getAuthorizeUrlStub.restore();
  });

  it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST", function () {
    var strategy = new SamlStrategy(
      {
        authnRequestBinding: "HTTP-POST",
      },
      verify
    );
    strategy.authenticate({}, {});
    sinon.assert.calledOnce(this.getAuthorizeFormStub);
  });

  it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function () {
    var strategy = new SamlStrategy({}, verify);
    strategy.authenticate({}, {});
    sinon.assert.calledOnce(this.getAuthorizeUrlStub);
  });
});
