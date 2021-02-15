"use strict";

import * as sinon from "sinon";
import { Strategy as SamlStrategy } from "../src/passport-saml";
import { RequestWithUser } from "../src/passport-saml/types";

function verify() {}

describe("strategy#authorize", function () {
  beforeEach(function () {
    this.getAuthorizeFormStub = sinon.stub(SamlStrategy.prototype, "getAuthorizeForm");
    this.getAuthorizeUrlStub = sinon.stub(SamlStrategy.prototype, "getAuthorizeUrl");
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
      verify
    );
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.calledOnce(this.getAuthorizeFormStub);
  });

  it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function () {
    const strategy = new SamlStrategy({}, verify);
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.calledOnce(this.getAuthorizeUrlStub);
  });
});
