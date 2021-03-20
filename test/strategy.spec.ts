"use strict";

import * as sinon from "sinon";
import { SAML, Strategy as SamlStrategy } from "../src/passport-saml";
import { RequestWithUser } from "../src/passport-saml/types";
import { FAKE_CERT } from "./types";

const noop = () => undefined;

describe("strategy#authorize", function () {
  let getAuthorizeFormStub: sinon.SinonStub;
  let getAuthorizeUrlStub: sinon.SinonStub;
  let errorStub: sinon.SinonStub;

  beforeEach(function () {
    getAuthorizeFormStub = sinon.stub(SAML.prototype, "getAuthorizeFormAsync").resolves();
    getAuthorizeUrlStub = sinon.stub(SAML.prototype, "getAuthorizeUrlAsync").resolves();
    errorStub = sinon.stub(SamlStrategy.prototype, "error");
  });

  afterEach(function () {
    getAuthorizeFormStub.restore();
    getAuthorizeUrlStub.restore();
    errorStub.restore();
  });

  it("calls getAuthorizeForm when authnRequestBinding is HTTP-POST", function () {
    const strategy = new SamlStrategy(
      {
        authnRequestBinding: "HTTP-POST",
        cert: FAKE_CERT,
      },
      noop
    );
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.notCalled(errorStub);
    sinon.assert.calledOnce(getAuthorizeFormStub);
  });

  it("calls getAuthorizeUrl when authnRequestBinding is not HTTP-POST", function () {
    const strategy = new SamlStrategy({ cert: FAKE_CERT }, noop);
    strategy.authenticate({} as RequestWithUser, {});
    sinon.assert.notCalled(errorStub);
    sinon.assert.calledOnce(getAuthorizeUrlStub);
  });
});
