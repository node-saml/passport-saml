"use strict";

import * as sinon from "sinon";
import { Strategy as SamlStrategy, SAML } from "../src/passport-saml";
import { RequestWithUser } from "../src/passport-saml/types";

const noop = () => undefined;

describe("strategy#authorize", function () {
  beforeEach(function () {
    this.getAuthorizeFormStub = sinon.stub(SAML.prototype, "getAuthorizeFormAsync").resolves();
    this.getAuthorizeUrlStub = sinon.stub(SAML.prototype, "getAuthorizeUrlAsync").resolves();
  });

  afterEach(function () {
    this.getAuthorizeFormStub.restore();
    this.getAuthorizeUrlStub.restore();
  });

  it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST", function () {
    const strategy = new SamlStrategy(
      {
        authnRequestBinding: "HTTP-POST",
      },
      noop
    );
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.calledOnce(this.getAuthorizeFormStub);
  });

  it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function () {
    const strategy = new SamlStrategy({}, noop);
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.calledOnce(this.getAuthorizeUrlStub);
  });
});
