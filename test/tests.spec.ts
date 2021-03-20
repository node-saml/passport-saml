"use strict";
import * as express from "express";
import { Strategy as SamlStrategy, SAML } from "../src/passport-saml";
import url = require("url");
import * as querystring from "querystring";
import { parseString } from "xml2js";
import * as fs from "fs";
import * as sinon from "sinon";
import { RacComparision, RequestWithUser, SamlConfig } from "../src/passport-saml/types.js";
import * as should from "should";
import assert = require("assert");
import { FAKE_CERT, TEST_CERT } from "./types";
import { signXmlResponse } from "../src/passport-saml/utility";

export const BAD_TEST_CERT =
  "MIIEOTCCAyGgAwIBAgIJAKZgJdKdCdL6MA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNVBAYTAkFVMREwDwYDVQQIEwhWaWN0b3JpYTESMBAGA1UEBxMJTWVsYm91cm5lMSEwHwYDVQQKExhUYWJjb3JwIEhvbGRpbmdzIExpbWl0ZWQxFzAVBgNVBAMTDnN0cy50YWIuY29tLmF1MB4XDTE3MDUzMDA4NTQwOFoXDTI3MDUyODA4NTQwOFowcDELMAkGA1UEBhMCQVUxETAPBgNVBAgTCFZpY3RvcmlhMRIwEAYDVQQHEwlNZWxib3VybmUxITAfBgNVBAoTGFRhYmNvcnAgSG9sZGluZ3MgTGltaXRlZDEXMBUGA1UEAxMOc3RzLnRhYi5jb20uYXUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0NuMcflq3rtupKYDf4a7lWmsXy66fYe9n8jB2DuLMakEJBlzn9j6B98IZftrilTq21VR7wUXROxG8BkN8IHY+l8X7lATmD28fFdZJj0c8Qk82eoq48faemth4fBMx2YrpnhU00jeXeP8dIIaJTPCHBTNgZltMMhphklN1YEPlzefJs3YD+Ryczy1JHbwETxt+BzO1JdjBe1fUTyl6KxAwWvtsNBURmQRYlDOk4GRgdkQnfxBuCpOMeOpV8wiBAi3h65Lab9C5avu4AJlA9e4qbOmWt6otQmgy5fiJVy6bH/d8uW7FJmSmePX9sqAWa9szhjdn36HHVQsfHC+IUEX7AgMBAAGjgdUwgdIwHQYDVR0OBBYEFN6z6cuxY7FTkg1S/lIjnS4x5ARWMIGiBgNVHSMEgZowgZeAFN6z6cuxY7FTkg1S/lIjnS4x5ARWoXSkcjBwMQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExEjAQBgNVBAcTCU1lbGJvdXJuZTEhMB8GA1UEChMYVGFiY29ycCBIb2xkaW5ncyBMaW1pdGVkMRcwFQYDVQQDEw5zdHMudGFiLmNvbS5hdYIJAKZgJdKdCdL6MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAMi5HyvXgRa4+kKz3dk4SwAEXzeZRcsbeDJWVUxdb6a+JQxIoG7L9rSbd6yZvP/Xel5TrcwpCpl5eikzXB02/C0wZKWicNmDEBlOfw0Pc5ngdoh6ntxHIWm5QMlAfjR0dgTlojN4Msw2qk7cP1QEkV96e2BJUaqaNnM3zMvd7cfRjPNfbsbwl6hCCCAdwrALKYtBnjKVrCGPwO+xiw5mUJhZ1n6ZivTOdQEWbl26UO60J9ItiWP8VK0d0aChn326Ovt7qC4S3AgDlaJwcKe5Ifxl/UOWePGRwXj2UUuDWFhjtVmRntMmNZbe5yE8MkEvU+4/c6LqGwTCgDenRbK53Dgg";

export const noop = (): void => undefined;

describe("passport-saml /", function () {
  describe("saml.js / ", function () {
    it("should throw an error if cert property is provided to saml constructor but is empty", function () {
      should(function () {
        const strategy = new SAML({ cert: undefined as any });
        typeof strategy.options.cert === "undefined";
      }).throw("cert is required");
    });

    it("generateUniqueID should generate 20 char IDs", function () {
      const samlObj = new SAML({ entryPoint: "foo", cert: FAKE_CERT });
      for (let i = 0; i < 200; i++) {
        samlObj.generateUniqueID().length.should.eql(20);
      }
    });

    it("generateLogoutRequest", function (done) {
      try {
        const expectedRequest = {
          "samlp:LogoutRequest": {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
              //ID: '_85ba0a112df1ffb57805',
              Version: "2.0",
              //IssueInstant: '2014-05-29T03:32:23Z',
              Destination: "foo",
            },
            "saml:Issuer": [
              { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
            ],
            "saml:NameID": [{ _: "bar", $: { Format: "foo" } }],
          },
        };

        const samlObj = new SAML({ entryPoint: "foo", cert: FAKE_CERT });
        const logoutRequestPromise = samlObj.generateLogoutRequest({
          user: {
            nameIDFormat: "foo",
            nameID: "bar",
          },
        } as RequestWithUser);

        logoutRequestPromise
          .then(function (logoutRequest) {
            parseString(logoutRequest, function (err, doc) {
              try {
                delete doc["samlp:LogoutRequest"]["$"]["ID"];
                delete doc["samlp:LogoutRequest"]["$"]["IssueInstant"];
                doc.should.eql(expectedRequest);
                done();
              } catch (err2) {
                done(err2);
              }
            });
          })
          .catch((err: Error) => {
            done(err);
          });
      } catch (err3) {
        done(err3);
      }
    });

    it("generateLogoutRequest adds the NameQualifier and SPNameQualifier to the saml request", function (done) {
      try {
        const expectedRequest = {
          "samlp:LogoutRequest": {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
              //ID: '_85ba0a112df1ffb57805',
              Version: "2.0",
              //IssueInstant: '2014-05-29T03:32:23Z',
              Destination: "foo",
            },
            "saml:Issuer": [
              { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
            ],
            "saml:NameID": [
              {
                _: "bar",
                $: {
                  Format: "foo",
                  SPNameQualifier: "Service Provider",
                  NameQualifier: "Identity Provider",
                },
              },
            ],
          },
        };

        const samlObj = new SAML({ entryPoint: "foo", cert: FAKE_CERT });
        const logoutRequestPromise = samlObj.generateLogoutRequest({
          user: {
            nameIDFormat: "foo",
            nameID: "bar",
            nameQualifier: "Identity Provider",
            spNameQualifier: "Service Provider",
          },
        } as RequestWithUser);

        logoutRequestPromise
          .then(function (logoutRequest) {
            parseString(logoutRequest, function (err, doc) {
              try {
                delete doc["samlp:LogoutRequest"]["$"]["ID"];
                delete doc["samlp:LogoutRequest"]["$"]["IssueInstant"];
                doc.should.eql(expectedRequest);
                done();
              } catch (err2) {
                done(err2);
              }
            });
          })
          .catch((err: Error) => {
            done(err);
          });
      } catch (err3) {
        done(err3);
      }
    });

    it("generateLogoutResponse", function (done) {
      const expectedResponse = {
        "samlp:LogoutResponse": {
          $: {
            "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            //ID: '_d11b3c5e085b2417f4aa',
            Version: "2.0",
            //IssueInstant: '2014-05-29T01:11:32Z',
            Destination: "foo",
            InResponseTo: "quux",
          },
          "saml:Issuer": ["onelogin_saml"],
          "samlp:Status": [
            {
              "samlp:StatusCode": [{ $: { Value: "urn:oasis:names:tc:SAML:2.0:status:Success" } }],
            },
          ],
        },
      };

      const samlObj = new SAML({ entryPoint: "foo", cert: FAKE_CERT });
      const logoutRequest = samlObj.generateLogoutResponse({} as express.Request, { ID: "quux" });
      parseString(logoutRequest, function (err, doc) {
        try {
          delete doc["samlp:LogoutResponse"]["$"]["ID"];
          delete doc["samlp:LogoutResponse"]["$"]["IssueInstant"];
          doc.should.eql(expectedResponse);
          done();
        } catch (err2) {
          done(err2);
        }
      });
    });

    it("generateLogoutRequest with session index", function (done) {
      try {
        const expectedRequest = {
          "samlp:LogoutRequest": {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
              //ID: '_85ba0a112df1ffb57805',
              Version: "2.0",
              //IssueInstant: '2014-05-29T03:32:23Z',
              Destination: "foo",
            },
            "saml:Issuer": [
              { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
            ],
            "saml:NameID": [{ _: "bar", $: { Format: "foo" } }],
            "saml2p:SessionIndex": [
              { _: "session-id", $: { "xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol" } },
            ],
          },
        };

        const samlObj = new SAML({ entryPoint: "foo", cert: FAKE_CERT });
        const logoutRequestPromise = samlObj.generateLogoutRequest({
          user: {
            nameIDFormat: "foo",
            nameID: "bar",
            sessionIndex: "session-id",
          },
        } as RequestWithUser);

        logoutRequestPromise
          .then(function (logoutRequest) {
            parseString(logoutRequest, function (err, doc) {
              try {
                delete doc["samlp:LogoutRequest"]["$"]["ID"];
                delete doc["samlp:LogoutRequest"]["$"]["IssueInstant"];
                doc.should.eql(expectedRequest);
                done();
              } catch (err2) {
                done(err2);
              }
            });
          })
          .catch((err: Error) => {
            done(err);
          });
      } catch (err3) {
        done(err3);
      }
    });

    it("generateLogoutRequest saves id and instant to cache", function (done) {
      const expectedRequest = {
        "samlp:LogoutRequest": {
          $: {
            "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            //ID: '_85ba0a112df1ffb57805',
            Version: "2.0",
            //IssueInstant: '2014-05-29T03:32:23Z',
            Destination: "foo",
          },
          "saml:Issuer": [
            { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
          ],
          "saml:NameID": [{ _: "bar", $: { Format: "foo" } }],
          "saml2p:SessionIndex": [
            { _: "session-id", $: { "xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol" } },
          ],
        },
      };

      const samlObj = new SAML({ entryPoint: "foo", cert: FAKE_CERT });
      const cacheSaveSpy = sinon.spy(samlObj.cacheProvider, "saveAsync");
      const logoutRequestPromise = samlObj.generateLogoutRequest({
        user: {
          nameIDFormat: "foo",
          nameID: "bar",
          sessionIndex: "session-id",
        },
      } as RequestWithUser);

      logoutRequestPromise.then(function (logoutRequest) {
        parseString(logoutRequest, function (err, doc) {
          try {
            const id = doc["samlp:LogoutRequest"]["$"]["ID"];
            const issueInstant = doc["samlp:LogoutRequest"]["$"]["IssueInstant"];

            id.should.be.an.instanceOf(String);
            issueInstant.should.be.an.instanceOf(String);
            cacheSaveSpy.called.should.eql(true);
            cacheSaveSpy.calledWith(id, issueInstant).should.eql(true);
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    describe("generateServiceProviderMetadata tests /", function () {
      function testMetadata(
        samlConfig: SamlConfig,
        expectedMetadata: string,
        signingCert?: string
      ) {
        const samlObj = new SAML(samlConfig);
        const decryptionCert = fs.readFileSync(
          __dirname + "/static/testshib encryption cert.pem",
          "utf-8"
        );
        let metadata = samlObj.generateServiceProviderMetadata(decryptionCert, signingCert);
        // splits are to get a nice diff if they don't match for some reason
        metadata.split("\n").should.eql(expectedMetadata.split("\n"));

        // verify that we are exposed through Strategy as well
        const strategy = new SamlStrategy(samlConfig, noop);
        metadata = strategy.generateServiceProviderMetadata(decryptionCert, signingCert);
        metadata.split("\n").should.eql(expectedMetadata.split("\n"));
      }

      it("config with callbackUrl and decryptionPvk should pass", function () {
        const samlConfig = {
          issuer: "http://example.serviceprovider.com",
          callbackUrl: "http://example.serviceprovider.com/saml/callback",
          identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
          cert: FAKE_CERT,
        };
        const expectedMetadata = fs.readFileSync(
          __dirname + "/static/expected metadata.xml",
          "utf-8"
        );

        testMetadata(samlConfig, expectedMetadata);
      });

      it("config with callbackUrl should pass", function () {
        const samlConfig = {
          issuer: "http://example.serviceprovider.com",
          callbackUrl: "http://example.serviceprovider.com/saml/callback",
          identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          cert: FAKE_CERT,
        };
        const expectedMetadata = fs.readFileSync(
          __dirname + "/static/expected metadata without key.xml",
          "utf-8"
        );

        testMetadata(samlConfig, expectedMetadata);
      });

      it("config with protocol, path, host, and decryptionPvk should pass", function () {
        const samlConfig = {
          issuer: "http://example.serviceprovider.com",
          protocol: "http://",
          host: "example.serviceprovider.com",
          path: "/saml/callback",
          identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
          cert: FAKE_CERT,
        };
        const expectedMetadata = fs.readFileSync(
          __dirname + "/static/expected metadata.xml",
          "utf-8"
        );

        testMetadata(samlConfig, expectedMetadata);
      });

      it("config with protocol, path, and host should pass", function () {
        const samlConfig = {
          issuer: "http://example.serviceprovider.com",
          protocol: "http://",
          host: "example.serviceprovider.com",
          path: "/saml/callback",
          identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          cert: FAKE_CERT,
        };
        const expectedMetadata = fs.readFileSync(
          __dirname + "/static/expected metadata without key.xml",
          "utf-8"
        );

        testMetadata(samlConfig, expectedMetadata);
      });

      it("config with protocol, path, host, decryptionPvk and privateCert should pass", function () {
        const samlConfig = {
          issuer: "http://example.serviceprovider.com",
          protocol: "http://",
          host: "example.serviceprovider.com",
          path: "/saml/callback",
          identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
          privateCert: fs.readFileSync(__dirname + "/static/acme_tools_com.key"),
          cert: FAKE_CERT,
        };
        const expectedMetadata = fs.readFileSync(
          __dirname + "/static/expectedMetadataWithBothKeys.xml",
          "utf-8"
        );
        const signingCert = fs.readFileSync(__dirname + "/static/acme_tools_com.cert").toString();

        testMetadata(samlConfig, expectedMetadata, signingCert);
      });

      it("config with protocol, path, host, decryptionPvk and privateKey should pass", function () {
        const samlConfig = {
          issuer: "http://example.serviceprovider.com",
          protocol: "http://",
          host: "example.serviceprovider.com",
          path: "/saml/callback",
          identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
          privateKey: fs.readFileSync(__dirname + "/static/acme_tools_com.key"),
          cert: FAKE_CERT,
        };
        const expectedMetadata = fs.readFileSync(
          __dirname + "/static/expectedMetadataWithBothKeys.xml",
          "utf-8"
        );
        const signingCert = fs.readFileSync(__dirname + "/static/acme_tools_com.cert").toString();

        testMetadata(samlConfig, expectedMetadata, signingCert);
      });
    });

    it("generateServiceProviderMetadata contains logout callback url", function () {
      const samlConfig = {
        issuer: "http://example.serviceprovider.com",
        callbackUrl: "http://example.serviceprovider.com/saml/callback",
        identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
        logoutCallbackUrl: "http://example.serviceprovider.com/logout",
        cert: FAKE_CERT,
      };

      const samlObj = new SAML(samlConfig);
      const decryptionCert = fs.readFileSync(
        __dirname + "/static/testshib encryption cert.pem",
        "utf-8"
      );
      const metadata = samlObj.generateServiceProviderMetadata(decryptionCert);
      metadata.should.containEql("SingleLogoutService");
      metadata.should.containEql(samlConfig.logoutCallbackUrl);
    });

    it("generateServiceProviderMetadata contains WantAssertionsSigned", function () {
      const samlConfig = {
        cert: TEST_CERT,
        issuer: "http://example.serviceprovider.com",
        callbackUrl: "http://example.serviceprovider.com/saml/callback",
        identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
        wantAssertionsSigned: true,
      };

      const samlObj = new SAML(samlConfig);
      const decryptionCert = fs.readFileSync(
        __dirname + "/static/testshib encryption cert.pem",
        "utf-8"
      );
      const metadata = samlObj.generateServiceProviderMetadata(decryptionCert);
      metadata.should.containEql('WantAssertionsSigned="true"');
    });

    it("#certToPEM should generate valid certificate", function () {
      const samlConfig = {
        entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
        cert: "-----BEGIN CERTIFICATE-----" + TEST_CERT + "-----END CERTIFICATE-----",
        acceptedClockSkewMs: -1,
      };
      const samlObj = new SAML(samlConfig);
      const certificate = samlObj.certToPEM(samlConfig.cert);

      if (!(certificate.match(/BEGIN/g)!.length == 1 && certificate.match(/END/g)!.length == 1)) {
        throw Error("Certificate should have only 1 BEGIN and 1 END block");
      }
    });

    describe("validatePostResponse checks /", function () {
      let fakeClock: sinon.SinonFakeTimers;

      afterEach(() => {
        if (fakeClock) {
          // If fakeClock is retored in a test, it will cause intermittant problems for other tests
          fakeClock.restore();
        }
      });

      it("response with junk content should explain the XML or base64 is not valid", async () => {
        const samlObj = new SAML({ cert: TEST_CERT });
        await assert.rejects(samlObj.validatePostResponseAsync({ SAMLResponse: "BOOM" }), {
          message: /SAMLResponse is not valid base64-encoded XML/,
        });
      });
      it("response with error status message should generate appropriate error", async () => {
        const xml =
          '<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost/browserSamlLogin" ID="_6a377272c8662561acf1056274ef3f81" InResponseTo="_4324fb0d00661146f7dc" IssueInstant="2014-07-02T18:16:31.278Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/></saml2p:StatusCode><saml2p:StatusMessage>Required NameID format not supported</saml2p:StatusMessage></saml2p:Status></saml2p:Response>';
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML({
          cert: "-----BEGIN CERTIFICATE-----" + TEST_CERT + "-----END CERTIFICATE-----",
        });
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: /Responder.*Required NameID format not supported/,
        });
      });

      it("response with error status code should generate appropriate error", async () => {
        const xml =
          '<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost/browserSamlLogin" ID="_6a377272c8662561acf1056274ef3f81" InResponseTo="_4324fb0d00661146f7dc" IssueInstant="2014-07-02T18:16:31.278Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/></saml2p:StatusCode></saml2p:Status></saml2p:Response>';
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML({ cert: FAKE_CERT });
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: /Responder.*InvalidNameIDPolicy/,
        });
      });

      it("accept response with an attributeStatement element without attributeValue", async () => {
        fakeClock = sinon.useFakeTimers(Date.parse("2015-08-31T08:55:00+00:00"));

        const container = {
          SAMLResponse: fs
            .readFileSync(__dirname + "/static/response-with-uncomplete-attribute.xml")
            .toString("base64"),
        };

        const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");

        const samlObj = new SAML({ cert: signingCert });
        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.issuer!.should.eql("https://evil-corp.com");
        profile!.nameID!.should.eql("vincent.vega@evil-corp.com");
        should(profile).have.property("evil-corp.egroupid").eql("vincent.vega@evil-corp.com");
        // attributes without attributeValue child should be ignored
        should(profile).not.have.property("evilcorp.roles");
      });

      it("removes InResponseTo value if response validation fails", async () => {
        const requestId = "_a6fc46be84e1e3cf3c50";
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: TEST_CERT,
          validateInResponseTo: true,
        };
        const samlObj = new SAML(samlConfig);

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: /Invalid signature/,
        });

        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: /InResponseTo is not valid/,
        });
      });

      describe("validatePostResponse xml signature checks /", function () {
        const ALT_TEST_CERT =
          "MIIEOTCCAyGgAwIBAgIJAKZgJdKdCdL6MA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNVBAYTAkFVMREwDwYDVQQIEwhWaWN0b3JpYTESMBAGA1UEBxMJTWVsYm91cm5lMSEwHwYDVQQKExhUYWJjb3JwIEhvbGRpbmdzIExpbWl0ZWQxFzAVBgNVBAMTDnN0cy50YWIuY29tLmF1MB4XDTE3MDUzMDA4NTQwOFoXDTI3MDUyODA4NTQwOFowcDELMAkGA1UEBhMCQVUxETAPBgNVBAgTCFZpY3RvcmlhMRIwEAYDVQQHEwlNZWxib3VybmUxITAfBgNVBAoTGFRhYmNvcnAgSG9sZGluZ3MgTGltaXRlZDEXMBUGA1UEAxMOc3RzLnRhYi5jb20uYXUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0NuMcflq3rtupKYDf4a7lWmsXy66fYe9n8jB2DuLMakEJBlzn9j6B98IZftrilTq21VR7wUXROxG8BkN8IHY+l8X7lATmD28fFdZJj0c8Qk82eoq48faemth4fBMx2YrpnhU00jeXeP8dIIaJTPCHBTNgZltMMhphklN1YEPlzefJs3YD+Ryczy1JHbwETxt+BzO1JdjBe1fUTyl6KxAwWvtsNBURmQRYlDOk4GRgdkQnfxBuCpOMeOpV8wiBAi3h65Lab9C5avu4AJlA9e4qbOmWt6otQmgy5fiJVy6bH/d8uW7FJmSmePX9sqAWa9szhjdn36HHVQsfHC+IUEX7AgMBAAGjgdUwgdIwHQYDVR0OBBYEFN6z6cuxY7FTkg1S/lIjnS4x5ARWMIGiBgNVHSMEgZowgZeAFN6z6cuxY7FTkg1S/lIjnS4x5ARWoXSkcjBwMQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExEjAQBgNVBAcTCU1lbGJvdXJuZTEhMB8GA1UEChMYVGFiY29ycCBIb2xkaW5ncyBMaW1pdGVkMRcwFQYDVQQDEw5zdHMudGFiLmNvbS5hdYIJAKZgJdKdCdL6MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAMi5HyvXgRa4+kKz3dk4SwAEXzeZRcsbeDJWVUxdb6a+JQxIoG7L9rSbd6yZvP/Xel5TrcwpCpl5eikzXB02/C0wZKWicNmDEBlOfw0Pc5ngdoh6ntxHIWm5QMlAfjR0dgTlojN4Msw2qk7cP1QEkV96e2BJUaqaNnM3zMvd7cfRjPNfbsbwl6hCCCAdwrALKYtBnjKVrCGPwO+xiw5mUJhZ1n6ZivTOdQEWbl26UO60J9ItiWP8VK0d0aChn326Ovt7qC4S3AgDlaJwcKe5Ifxl/UOWePGRwXj2UUuDWFhjtVmRntMmNZbe5yE8MkEvU+4/c6LqGwTCgDenRbK53Dg=";
        let fakeClock: sinon.SinonFakeTimers;

        beforeEach(function () {
          fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:09Z"));
        });
        afterEach(function () {
          fakeClock.restore();
        });

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: TEST_CERT,
        };
        const noCertSamlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
        } as SamlConfig;
        const badCertSamlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: BAD_TEST_CERT,
        };

        it("must have a cert to construct a SAML object", function () {
          try {
            new SAML(noCertSamlConfig);
          } catch (err) {
            should.exist(err);
            err!.message!.should.match(/cert is required/);
          }
        });

        it("must have a valid cert to construct a SAML object", function () {
          try {
            new SAML(badCertSamlConfig);
          } catch (err) {
            should.exist(err);
            err!.message!.should.match(/cert is required/);
          }
        });

        it("valid onelogin xml document should validate", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);

          const { profile } = await samlObj.validatePostResponseAsync(container);
          profile!.nameID!.should.startWith("ploer");
        });
        it("valid onelogin xml document should fail with no cert", function () {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          try {
            const samlObj = new SAML(noCertSamlConfig);
          } catch (err) {
            should.exist(err);
            err!.message!.should.match(/cert is required/);
          }
        });

        it("onelogin xml document with altered NameID should fail", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">aaaaaaaa@bbbbb.local</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);
          await assert.rejects(samlObj.validatePostResponseAsync(container), /Invalid signature/);
        });

        it("onelogin xml document with altered assertion name should fail", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">aaaaaaaa@bbbbb.local</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);
          await assert.rejects(samlObj.validatePostResponseAsync(container), /Invalid signature/);
        });

        it("onelogin xml document with altered assertion should fail", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);
          await assert.rejects(samlObj.validatePostResponseAsync(container), /Invalid signature/);
        });

        it("onelogin xml document with duplicate altered assertion should fail", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);
          await assert.rejects(samlObj.validatePostResponseAsync(container), /Invalid signature/);
        });

        it("onelogin xml document with extra unsigned & altered assertion should fail", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efab" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);
          await assert.rejects(samlObj.validatePostResponseAsync(container), /Invalid signature/);
        });

        it("onelogin xml document with extra nexted assertion should fail", async () => {
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
            "<ds:Object>" +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</ds:Object>" +
            '</ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(samlConfig);
          await assert.rejects(samlObj.validatePostResponseAsync(container), /Invalid signature/);
        });

        it("multiple certs should validate with one of the certs", async () => {
          const multiCertSamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: [ALT_TEST_CERT, samlConfig.cert],
          };
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(multiCertSamlConfig);
          const { profile } = await samlObj.validatePostResponseAsync(container);
          profile!.nameID!.should.startWith("ploer");
        });

        it("cert as a function should validate with the returned cert", async () => {
          const functionCertSamlConfig: SamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: function (callback) {
              callback(null, samlConfig.cert);
            },
          };
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(functionCertSamlConfig);
          const { profile } = await samlObj.validatePostResponseAsync(container);
          profile!.nameID!.should.startWith("ploer");
        });

        it("cert as a function should validate with one of the returned certs", async () => {
          const functionMultiCertSamlConfig: SamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: function (callback) {
              callback(null, [ALT_TEST_CERT, samlConfig.cert]);
            },
          };
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(functionMultiCertSamlConfig);
          const { profile } = await samlObj.validatePostResponseAsync(container);
          profile!.nameID!.should.startWith("ploer");
        });

        it("cert as a function should return an error if the cert function returns an error", async () => {
          const errorToReturn = new Error("test");
          const functionErrorCertSamlConfig: SamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: function (callback) {
              callback(errorToReturn);
            },
          };
          const xml =
            '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
            TEST_CERT +
            '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            "</samlp:Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML(functionErrorCertSamlConfig);
          try {
            await samlObj.validatePostResponseAsync(container);
            should.not.exist(true);
          } catch (err) {
            should.exist(err);
            err!.should.eql(errorToReturn);
          }
        });

        it("XML AttributeValue should return object", async () => {
          const nameid_opaque_string = "*******************************";
          const nameQualifier = "https://idp.example.org/idp/saml";
          const spNameQualifier = "https://sp.example.org/sp/entity";
          const format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
          const xml =
            '<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="response0">' +
            '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="assertion0">' +
            "<saml2:AttributeStatement>" +
            '<saml2:Attribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">' +
            "<saml2:AttributeValue>" +
            '<saml2:NameID Format="' +
            format +
            '" NameQualifier="' +
            nameQualifier +
            '" SPNameQualifier="' +
            spNameQualifier +
            '">' +
            nameid_opaque_string +
            "</saml2:NameID>" +
            "</saml2:AttributeValue>" +
            "</saml2:Attribute>" +
            "</saml2:AttributeStatement>" +
            "</saml2:Assertion>" +
            "</Response>";

          const signingKey = fs.readFileSync(__dirname + "/static/key.pem");
          const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");
          const signedXml = signXmlResponse(xml, { privateKey: signingKey });

          const base64xml = Buffer.from(signedXml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML({ cert: signingCert });
          const { profile } = await samlObj.validatePostResponseAsync(container);
          const eptid = profile!["urn:oid:1.3.6.1.4.1.5923.1.1.1.10"] as any;
          const nameid = eptid["NameID"][0];
          nameid._.should.eql(nameid_opaque_string);
          nameid.$.NameQualifier.should.equal(nameQualifier);
          nameid.$.SPNameQualifier.should.equal(spNameQualifier);
          nameid.$.Format.should.equal(format);
        });

        it("XML AttributeValue without signature should throw", async () => {
          const nameid_opaque_string = "*******************************";
          const nameQualifier = "https://idp.example.org/idp/saml";
          const spNameQualifier = "https://sp.example.org/sp/entity";
          const format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
          const xml =
            "<Response>" +
            '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">' +
            "<saml2:AttributeStatement>" +
            '<saml2:Attribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">' +
            "<saml2:AttributeValue>" +
            '<saml2:NameID Format="' +
            format +
            '" NameQualifier="' +
            nameQualifier +
            '" SPNameQualifier="' +
            spNameQualifier +
            '">' +
            nameid_opaque_string +
            "</saml2:NameID>" +
            "</saml2:AttributeValue>" +
            "</saml2:Attribute>" +
            "</saml2:AttributeStatement>" +
            "</saml2:Assertion>" +
            "</Response>";
          const base64xml = Buffer.from(xml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML({ cert: TEST_CERT });
          await assert.rejects(samlObj.validatePostResponseAsync(container), {
            message: "Invalid signature",
          });
        });

        it("An undefined value given with an object should still be undefined", async () => {
          const xml =
            '<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="response0">' +
            '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">' +
            "<saml2:AttributeStatement>" +
            '<saml2:Attribute Name="attributeName" ' +
            'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">' +
            '<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" ' +
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
            'xsi:type="xs:string"/>' +
            "</saml2:Attribute>" +
            "</saml2:AttributeStatement>" +
            "</saml2:Assertion>" +
            "</Response>";

          const signingKey = fs.readFileSync(__dirname + "/static/key.pem");
          const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");
          const signedXml = signXmlResponse(xml, { privateKey: signingKey });

          const base64xml = Buffer.from(signedXml).toString("base64");
          const container = { SAMLResponse: base64xml };
          const samlObj = new SAML({ cert: signingCert });
          const { profile } = await samlObj.validatePostResponseAsync(container);
          should(profile!["attributeName"]).be.undefined();
        });
      });
    });

    describe("getAuthorizeUrl request signature checks /", function () {
      let fakeClock: sinon.SinonFakeTimers;
      beforeEach(function () {
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:09Z"));
      });
      afterEach(function () {
        fakeClock.restore();
      });

      it("acme_tools request signed with sha256", async () => {
        const samlConfig: SamlConfig = {
          entryPoint: "https://adfs.acme_tools.com/adfs/ls/",
          issuer: "acme_tools_com",
          callbackUrl: "https://relyingparty/adfs/postResponse",
          privateCert: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
          authnContext: [
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
          ],
          identifierFormat: null,
          signatureAlgorithm: "sha256",
          additionalParams: {
            customQueryStringParam: "CustomQueryStringParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        samlObj.generateUniqueID = function () {
          return "12345678901234567890";
        };
        const authorizeUrl = await samlObj.getAuthorizeUrlAsync({} as express.Request, {});
        const qry = querystring.parse(url.parse(authorizeUrl).query || "");
        qry.SigAlg?.should.match("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        qry.Signature?.should.match(
          "hel9NaoLU0brY/VhrQsY+lTtuAbTsT/ul6nZ/eVlSMXQRaKn5LTbKadzxmPghX7s4xoHwdah+yZHK/0u4StYSj4b5MKcqbsJapVr2R7H90z8YfGfR2C/G0Gng721YV9Da6VBzKg8Was91zQotgsMpZ9pGX1kPKi6cgFwPwM4NEFugn8AYgXEriNvO5+Q23K/MdBT2bgwRTj2FQCWTuQcgwbyWHXoquHztZ0lbh8UhY5BfQRv7c6D9XPkQEMMQFQeME4PIEg3JnynwFZk5wwhkphMd5nXxau+zt7Nfp4fRm0G8WYnxV1etBnWimwSglZVaSHFYeQBRsC2wvKSiVS8JA=="
        );
        qry.customQueryStringParam?.should.match("CustomQueryStringParamValue");
      });
      it("acme_tools request signed with sha256 when using privateKey", async () => {
        const samlConfig: SamlConfig = {
          entryPoint: "https://adfs.acme_tools.com/adfs/ls/",
          issuer: "acme_tools_com",
          callbackUrl: "https://relyingparty/adfs/postResponse",
          privateKey: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
          authnContext: [
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
          ],
          identifierFormat: null,
          signatureAlgorithm: "sha256",
          additionalParams: {
            customQueryStringParam: "CustomQueryStringParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        samlObj.generateUniqueID = function () {
          return "12345678901234567890";
        };
        const authorizeUrl = await samlObj.getAuthorizeUrlAsync({} as express.Request, {});
        const qry = querystring.parse(url.parse(authorizeUrl).query || "");
        qry.SigAlg?.should.match("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        qry.Signature?.should.match(
          "hel9NaoLU0brY/VhrQsY+lTtuAbTsT/ul6nZ/eVlSMXQRaKn5LTbKadzxmPghX7s4xoHwdah+yZHK/0u4StYSj4b5MKcqbsJapVr2R7H90z8YfGfR2C/G0Gng721YV9Da6VBzKg8Was91zQotgsMpZ9pGX1kPKi6cgFwPwM4NEFugn8AYgXEriNvO5+Q23K/MdBT2bgwRTj2FQCWTuQcgwbyWHXoquHztZ0lbh8UhY5BfQRv7c6D9XPkQEMMQFQeME4PIEg3JnynwFZk5wwhkphMd5nXxau+zt7Nfp4fRm0G8WYnxV1etBnWimwSglZVaSHFYeQBRsC2wvKSiVS8JA=="
        );
        qry.customQueryStringParam?.should.match("CustomQueryStringParamValue");
      });
      it("acme_tools request not signed if missing entry point", async () => {
        const samlConfig: SamlConfig = {
          entryPoint: "",
          issuer: "acme_tools_com",
          callbackUrl: "https://relyingparty/adfs/postResponse",
          privateCert: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
          authnContext: [
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
          ],
          signatureAlgorithm: "sha256",
          additionalParams: {
            customQueryStringParam: "CustomQueryStringParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        samlObj.generateUniqueID = function () {
          return "12345678901234567890";
        };

        const request =
          '<?xml version=\\"1.0\\"?><samlp:AuthnRequest xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" ID=\\"_ea40a8ab177df048d645\\" Version=\\"2.0\\" IssueInstant=\\"2017-08-22T19:30:01.363Z\\" ProtocolBinding=\\"urn:oasis:names$tc:SAML:2.0:bindings:HTTP-POST\\" AssertionConsumerServiceURL=\\"https://example.com/login/callback\\" Destination=\\"https://www.example.com\\"><saml:Issuer xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">onelogin_saml</saml:Issuer><s$mlp:NameIDPolicy xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" Format=\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\" AllowCreate=\\"true\\"/><samlp:RequestedAuthnContext xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protoc$l\\" Comparison=\\"exact\\"><saml:AuthnContextClassRef xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp$AuthnRequest>';
        await assert.rejects(samlObj.requestToUrlAsync(request, null, "authorize", {}), {
          message: "entryPoint is required",
        });
      });
      it("acme_tools request not signed if missing entry point when using privateKey", async () => {
        const samlConfig: SamlConfig = {
          entryPoint: "",
          issuer: "acme_tools_com",
          callbackUrl: "https://relyingparty/adfs/postResponse",
          privateKey: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
          authnContext: [
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
          ],
          signatureAlgorithm: "sha256",
          additionalParams: {
            customQueryStringParam: "CustomQueryStringParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        samlObj.generateUniqueID = function () {
          return "12345678901234567890";
        };

        const request =
          '<?xml version=\\"1.0\\"?><samlp:AuthnRequest xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" ID=\\"_ea40a8ab177df048d645\\" Version=\\"2.0\\" IssueInstant=\\"2017-08-22T19:30:01.363Z\\" ProtocolBinding=\\"urn:oasis:names$tc:SAML:2.0:bindings:HTTP-POST\\" AssertionConsumerServiceURL=\\"https://example.com/login/callback\\" Destination=\\"https://www.example.com\\"><saml:Issuer xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">onelogin_saml</saml:Issuer><s$mlp:NameIDPolicy xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" Format=\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\" AllowCreate=\\"true\\"/><samlp:RequestedAuthnContext xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protoc$l\\" Comparison=\\"exact\\"><saml:AuthnContextClassRef xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp$AuthnRequest>';
        await assert.rejects(samlObj.requestToUrlAsync(request, null, "authorize", {}), {
          message: "entryPoint is required",
        });
      });
      it("acme_tools request signed with sha1", async () => {
        const samlConfig: SamlConfig = {
          entryPoint: "https://adfs.acme_tools.com/adfs/ls/",
          issuer: "acme_tools_com",
          callbackUrl: "https://relyingparty/adfs/postResponse",
          privateKey: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
          authnContext: [
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
          ],
          signatureAlgorithm: "sha1",
          additionalParams: {
            customQueryStringParam: "CustomQueryStringParamValue",
          },
          cert: fs.readFileSync(__dirname + "/static/acme_tools_com.cert", "utf-8"),
        };
        const samlObj = new SAML(samlConfig);
        samlObj.generateUniqueID = function () {
          return "12345678901234567890";
        };
        const authorizeUrl = await samlObj.getAuthorizeUrlAsync({} as express.Request, {});
        const qry = querystring.parse(url.parse(authorizeUrl).query || "");
        qry.SigAlg?.should.match("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        qry.Signature?.should.match(
          "GrRJDEmwB74g4CjGS4gjDhzR9Mnpo7S1DJyhaLxVRA97tumydsrJNpqbKDAsepnoFcZeS+mWn3hZSE/blsyCUJn5+010MsgQ8KWmRgaFEYPOfbBa2KK1atXNN8zcSdNukpd/rI17fB1HDeCPG8t+rtaE/QviL7DpsF6hGXbWSTi8eSRSNmLKFIntvS81CNiZdub1NI8hSd/rU873u7RfWnv6ChPltCs41Znj49ke6UJaSrHX7kNlnbzqw5WLJp73d3/yT2Yew+xpGDKAGrjYtbQEY0zZ8chfKWyTobLV9vNF1DCFRDeZbLrCzL29elo/aZ8BuIEdTNv/IOZoOMZxRA=="
        );
        qry.customQueryStringParam?.should.match("CustomQueryStringParamValue");
      });
      it("acme_tools request signed with sha1 when using privateKey", async () => {
        const samlConfig: SamlConfig = {
          entryPoint: "https://adfs.acme_tools.com/adfs/ls/",
          issuer: "acme_tools_com",
          callbackUrl: "https://relyingparty/adfs/postResponse",
          privateKey: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
          authnContext: [
            "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
          ],
          identifierFormat: null,
          signatureAlgorithm: "sha1",
          additionalParams: {
            customQueryStringParam: "CustomQueryStringParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        samlObj.generateUniqueID = function () {
          return "12345678901234567890";
        };
        const authorizeUrl = await samlObj.getAuthorizeUrlAsync({} as express.Request, {});
        const qry = querystring.parse(url.parse(authorizeUrl).query || "");
        qry.SigAlg?.should.match("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        qry.Signature?.should.match(
          "MeFo+LjufxP5A+sCRwzR/YH/RV6W14aYSFjUdie62JxkI6hDcVhoSZQUJ3wtWMhL59gJj05tTFnXAZRqUQVsavyy41cmUZVeCsat0gaHBQOILXpp9deB0iSJt1EVQTOJkVx8uu2/WYu/bBiH7w2bpwuCf1gJhlqZb/ca3B6yjHSMjnnVfc2LbNPWHpE5464lrs79VjDXf9GQWfrBr95dh3P51IAb7C+77KDWQUl9WfZfyyuEgS83vyZ0UGOxT4AObJ6NOcLs8+iidDdWJJkBaKQev6U+AghCjLQUYOrflivLIIyqATKu2q9PbOse6Phmnxok50+broXSG23+e+742Q=="
        );
        qry.customQueryStringParam?.should.match("CustomQueryStringParamValue");
      });
    });

    describe("getAdditionalParams checks /", function () {
      it("should not pass any additional params by default", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        ["logout", "authorize"].forEach(function (operation) {
          const additionalParams = samlObj.getAdditionalParams({} as express.Request, operation);
          additionalParams.should.be.empty;
        });
      });

      it("should not pass any additional params by default apart from the RelayState in request query", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        ["logout", "authorize"].forEach(function (operation) {
          const additionalParams = samlObj.getAdditionalParams(
            ({ query: { RelayState: "test" } } as unknown) as express.Request,
            operation
          );

          Object.keys(additionalParams).should.have.length(1);
          additionalParams.should.containEql({ RelayState: "test" });
        });
      });

      it("should not pass any additional params by default apart from the RelayState in request body", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        ["logout", "authorize"].forEach(function (operation) {
          const additionalParams = samlObj.getAdditionalParams(
            { body: { RelayState: "test" } } as express.Request,
            operation
          );

          Object.keys(additionalParams).should.have.length(1);
          additionalParams.should.containEql({ RelayState: "test" });
        });
      });

      it("should pass additional params with all operations if set in additionalParams", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalParams: {
            queryParam: "queryParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        ["logout", "authorize"].forEach(function (operation) {
          const additionalParams = samlObj.getAdditionalParams({} as express.Request, operation);
          Object.keys(additionalParams).should.have.length(1);
          additionalParams.should.containEql({ queryParam: "queryParamValue" });
        });
      });

      it('should pass additional params with "authorize" operations if set in additionalAuthorizeParams', function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalAuthorizeParams: {
            queryParam: "queryParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        const additionalAuthorizeParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "authorize"
        );
        Object.keys(additionalAuthorizeParams).should.have.length(1);
        additionalAuthorizeParams.should.containEql({ queryParam: "queryParamValue" });

        const additionalLogoutParams = samlObj.getAdditionalParams({} as express.Request, "logout");
        additionalLogoutParams.should.be.empty;
      });

      it('should pass additional params with "logout" operations if set in additionalLogoutParams', function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalLogoutParams: {
            queryParam: "queryParamValue",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        const additionalAuthorizeParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "authorize"
        );
        additionalAuthorizeParams.should.be.empty;

        const additionalLogoutParams = samlObj.getAdditionalParams({} as express.Request, "logout");
        Object.keys(additionalLogoutParams).should.have.length(1);
        additionalLogoutParams.should.containEql({ queryParam: "queryParamValue" });
      });

      it("should merge additionalLogoutParams and additionalAuthorizeParams with additionalParams", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalParams: {
            queryParam1: "queryParamValue",
          },
          additionalAuthorizeParams: {
            queryParam2: "queryParamValueAuthorize",
          },
          additionalLogoutParams: {
            queryParam2: "queryParamValueLogout",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        const additionalAuthorizeParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "authorize"
        );
        Object.keys(additionalAuthorizeParams).should.have.length(2);
        additionalAuthorizeParams.should.containEql({
          queryParam1: "queryParamValue",
          queryParam2: "queryParamValueAuthorize",
        });

        const additionalLogoutParams = samlObj.getAdditionalParams({} as express.Request, "logout");
        Object.keys(additionalLogoutParams).should.have.length(2);
        additionalLogoutParams.should.containEql({
          queryParam1: "queryParamValue",
          queryParam2: "queryParamValueLogout",
        });
      });

      it("should merge run-time params additionalLogoutParams and additionalAuthorizeParams with additionalParams", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalParams: {
            queryParam1: "queryParamValue",
          },
          additionalAuthorizeParams: {
            queryParam2: "queryParamValueAuthorize",
          },
          additionalLogoutParams: {
            queryParam2: "queryParamValueLogout",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        const options = {
          additionalParams: {
            queryParam3: "queryParamRuntimeValue",
          },
        };

        const additionalAuthorizeParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "authorize",
          options.additionalParams
        );
        Object.keys(additionalAuthorizeParams).should.have.length(3);
        additionalAuthorizeParams.should.containEql({
          queryParam1: "queryParamValue",
          queryParam2: "queryParamValueAuthorize",
          queryParam3: "queryParamRuntimeValue",
        });

        const additionalLogoutParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "logout",
          options.additionalParams
        );
        Object.keys(additionalLogoutParams).should.have.length(3);
        additionalLogoutParams.should.containEql({
          queryParam1: "queryParamValue",
          queryParam2: "queryParamValueLogout",
          queryParam3: "queryParamRuntimeValue",
        });
      });

      it("should prioritize additionalLogoutParams and additionalAuthorizeParams over additionalParams", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalParams: {
            queryParam: "queryParamValue",
          },
          additionalAuthorizeParams: {
            queryParam: "queryParamValueAuthorize",
          },
          additionalLogoutParams: {
            queryParam: "queryParamValueLogout",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);

        const additionalAuthorizeParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "authorize"
        );
        Object.keys(additionalAuthorizeParams).should.have.length(1);
        additionalAuthorizeParams.should.containEql({ queryParam: "queryParamValueAuthorize" });

        const additionalLogoutParams = samlObj.getAdditionalParams({} as express.Request, "logout");
        Object.keys(additionalLogoutParams).should.have.length(1);
        additionalLogoutParams.should.containEql({ queryParam: "queryParamValueLogout" });
      });

      it("should prioritize run-time params over all other params", function () {
        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          additionalParams: {
            queryParam: "queryParamValue",
          },
          additionalAuthorizeParams: {
            queryParam: "queryParamValueAuthorize",
          },
          additionalLogoutParams: {
            queryParam: "queryParamValueLogout",
          },
          cert: FAKE_CERT,
        };
        const samlObj = new SAML(samlConfig);
        const options = {
          additionalParams: {
            queryParam: "queryParamRuntimeValue",
          },
        };

        const additionalAuthorizeParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "authorize",
          options.additionalParams
        );
        Object.keys(additionalAuthorizeParams).should.have.length(1);
        additionalAuthorizeParams.should.containEql({ queryParam: "queryParamRuntimeValue" });

        const additionalLogoutParams = samlObj.getAdditionalParams(
          {} as express.Request,
          "logout",
          options.additionalParams
        );
        Object.keys(additionalLogoutParams).should.have.length(1);
        additionalLogoutParams.should.containEql({ queryParam: "queryParamRuntimeValue" });
      });

      it("should check the value of the option `racComparison`", function () {
        assert.throws(
          () => {
            new SAML({
              racComparison: "bad_value" as RacComparision,
              cert: FAKE_CERT,
            }).options;
          },
          { message: "racComparison must be one of ['exact', 'minimum', 'maximum', 'better']" }
        );

        const samlObjBadComparisonType = new SAML({
          cert: FAKE_CERT,
        });
        should.equal(
          samlObjBadComparisonType.options.racComparison,
          "exact",
          "the default value of the option `racComparison` must be exact"
        );

        const validComparisonTypes: RacComparision[] = ["exact", "minimum", "maximum", "better"];
        let samlObjValidComparisonType: SAML;
        validComparisonTypes.forEach(function (racComparison) {
          samlObjValidComparisonType = new SAML({ racComparison, cert: FAKE_CERT });
          should.equal(samlObjValidComparisonType.options.racComparison, racComparison);
        });
      });
    });

    describe("InResponseTo validation checks /", () => {
      let fakeClock: sinon.SinonFakeTimers;

      afterEach(function () {
        if (fakeClock) {
          fakeClock.restore();
        }
      });

      it("onelogin xml document with InResponseTo from request should validate", async () => {
        const requestId = "_a6fc46be84e1e3cf3c50";
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: TEST_CERT,
          validateInResponseTo: true,
        };
        const samlObj = new SAML(samlConfig);

        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:09Z"));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

        const { profile, loggedOut } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("ploer");
        const value = await samlObj.cacheProvider.getAsync(requestId);
        should.not.exist(value);
      });

      it("onelogin xml document without InResponseTo from request should fail", async () => {
        const requestId = "_a6fc46be84e1e3cf3c50";
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: TEST_CERT,
          validateInResponseTo: true,
        };
        const samlObj = new SAML(samlConfig);

        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:09Z"));
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: "InResponseTo is not valid",
        });
      });

      it("xml document with SubjectConfirmation InResponseTo from request should be valid", async () => {
        const requestId = "_dfab47d5d46374cd4b71";
        const xml =
          '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" InResponseTo="_dfab47d5d46374cd4b71" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>QecaVjMY/2M4VMJsakvX8uh2Mrg=</DigestValue></Reference></SignedInfo><SignatureValue>QTJ//ZHEQRe9/nA5qTkhECZc2u6M1dHzTkujKBedskLSRPL8LRBb4Yftla0zu848sYvLd3SXzEysYu/jrAjaVDevYZIAdyj/3HCw8pS0ZnQDaCgYuAkH4JmYxBfW1Sc9Kr0vbR58ihwWOZd4xHIn/b8xLs8WNsyTHix2etrLGznioLwTOBO3+SgjwSiSP9NUhrlOvolbuu/6xhLi37/L08JaBvOw3o0k4V8xS87SFczhm4f6wvQM5mP6sZAreoNcWZqQM7vIHFjL0/H9vTaLAN8+fQOc81xFtateTKwFQlJMUmdWKZ8L7ns0Uf1xASQjXtSAACbXI+PuVLjz8nnm3g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC7TCCAdmgAwIBAgIQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB1Rlc3RTVFMwHhcNMTQwNDE2MTIyMTEwWhcNMzkxMjMxMjM1OTU5WjASMRAwDgYDVQQDEwdUZXN0U1RTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhReamVYbeOWwrrAvHPvS9KKBwv4Tj7wOSGDXbNgfjhSvVyXsnpYRcuoJkvE8b9tCjFTbXCfbhnaVrpoXaWFtP1YvUIZvCJGdOOTXltMNDlNIaFmsIsomza8IyOHXe+3xHWVtxO8FG3qnteSkkVIQuAvBqpPfQtxrXCZOlbQZm7q69QIQ64JvLJfRwHN1EywMBVwbJgrV8gBdE3RITI76coSOK13OBTlGtB0kGKLDrF2JW+5mB+WnFR7GlXUj+V0R9WStBomVipJEwr6Q3fU0deKZ5lLw0+qJ0T6APInwN5TIN/AbFCHd51aaf3zEP+tZacQ9fbZqy9XBAtL2pCAJQIDAQABo0cwRTBDBgNVHQEEPDA6gBDECazhZ8Ar+ULXb0YTs5MvoRQwEjEQMA4GA1UEAxMHVGVzdFNUU4IQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAA4IBAQAioMSOU9QFw+yhVxGUNK0p/ghVsHnYdeOE3vSRhmFPsetBt8S35sI4QwnQNiuiEYqp++FabiHgePOiqq5oeY6ekJik1qbs7fgwnaQXsxxSucHvc4BU81x24aKy6jeJzxmFxo3mh6y/OI1peCMSH48iUzmhnoSulp0+oAs3gMEFI0ONbgAA/XoAHaVEsrPj10i3gkztoGdpH0DYUe9rABOJxX/3mNF+dCVJG7t7BoSlNAWlSDErKciNNax1nBskFqNWNIKzUKBIb+GVKkIB2QpATMQB6Oe7inUdT9kkZ/Q7oPBATZk+3mFsIoWr8QRFSqvToOhun7EY2/VtuiV1d932</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" InResponseTo="_dfab47d5d46374cd4b71" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert:
            "MIIC7TCCAdmgAwIBAgIQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB1Rlc3RTVFMwHhcNMTQwNDE2MTIyMTEwWhcNMzkxMjMxMjM1OTU5WjASMRAwDgYDVQQDEwdUZXN0U1RTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhReamVYbeOWwrrAvHPvS9KKBwv4Tj7wOSGDXbNgfjhSvVyXsnpYRcuoJkvE8b9tCjFTbXCfbhnaVrpoXaWFtP1YvUIZvCJGdOOTXltMNDlNIaFmsIsomza8IyOHXe+3xHWVtxO8FG3qnteSkkVIQuAvBqpPfQtxrXCZOlbQZm7q69QIQ64JvLJfRwHN1EywMBVwbJgrV8gBdE3RITI76coSOK13OBTlGtB0kGKLDrF2JW+5mB+WnFR7GlXUj+V0R9WStBomVipJEwr6Q3fU0deKZ5lLw0+qJ0T6APInwN5TIN/AbFCHd51aaf3zEP+tZacQ9fbZqy9XBAtL2pCAJQIDAQABo0cwRTBDBgNVHQEEPDA6gBDECazhZ8Ar+ULXb0YTs5MvoRQwEjEQMA4GA1UEAxMHVGVzdFNUU4IQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAA4IBAQAioMSOU9QFw+yhVxGUNK0p/ghVsHnYdeOE3vSRhmFPsetBt8S35sI4QwnQNiuiEYqp++FabiHgePOiqq5oeY6ekJik1qbs7fgwnaQXsxxSucHvc4BU81x24aKy6jeJzxmFxo3mh6y/OI1peCMSH48iUzmhnoSulp0+oAs3gMEFI0ONbgAA/XoAHaVEsrPj10i3gkztoGdpH0DYUe9rABOJxX/3mNF+dCVJG7t7BoSlNAWlSDErKciNNax1nBskFqNWNIKzUKBIb+GVKkIB2QpATMQB6Oe7inUdT9kkZ/Q7oPBATZk+3mFsIoWr8QRFSqvToOhun7EY2/VtuiV1d932",
          validateInResponseTo: true,
        };
        const samlObj = new SAML(samlConfig);

        fakeClock = sinon.useFakeTimers(Date.parse("2014-06-05T12:07:07.662Z"));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("UIS/jochen-work");
        const value = await samlObj.cacheProvider.getAsync(requestId);
        should.not.exist(value);
      });

      it("xml document with SubjectConfirmation and missing InResponseTo from request should not be valid", async () => {
        const requestId = "_dfab47d5d46374cd4b71";
        const xml =
          '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>c8xR7YMU8KAYbkV7Jx3WEBhIqso=</DigestValue></Reference></SignedInfo><SignatureValue>jPOrsXdG/YVyGrykXYUbgVK7iX+tNFjMJnOA2iFWOjjtWco9M5DT9tyUsYAag4o4oDUEJribGWhCYn6nvQ24zfW+eJYGwbxO0TSZ26J0iuhnxr+MMFmJVGjxArD70dea0kITssqCxJNKUwmTqteAQ73+qk91H9E9IDoOjMwQERoyD4sAtvfJErRrRontvg9xeQ0BFtyMzJZkwU24QqHvoHyw9/dVO8/NFPydwjaI9uZMu6/QUYKKvkbf6VUXXQUHIiZgX0GCudpB908BqWIcj0dWv8oKGGajQWp+d8Jlx/nxbUTAs8vL1f0dxW3LYCZsDExHmjRQTBhM0pQVMT+HlA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert:
            "MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/",
          validateInResponseTo: true,
        };
        const samlObj = new SAML(samlConfig);

        fakeClock = sinon.useFakeTimers(Date.parse("2014-06-05T12:07:07.662Z"));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

        try {
          const { profile } = await samlObj.validatePostResponseAsync(container);
          should.not.exist(profile);
        } catch (err) {
          err!.message!.should.eql("InResponseTo is missing from response");
        }
      });

      it("xml document with SubjectConfirmation and missing InResponseTo from request should be not problematic if not validated", async () => {
        const requestId = "_dfab47d5d46374cd4b71";
        const xml =
          '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>c8xR7YMU8KAYbkV7Jx3WEBhIqso=</DigestValue></Reference></SignedInfo><SignatureValue>jPOrsXdG/YVyGrykXYUbgVK7iX+tNFjMJnOA2iFWOjjtWco9M5DT9tyUsYAag4o4oDUEJribGWhCYn6nvQ24zfW+eJYGwbxO0TSZ26J0iuhnxr+MMFmJVGjxArD70dea0kITssqCxJNKUwmTqteAQ73+qk91H9E9IDoOjMwQERoyD4sAtvfJErRrRontvg9xeQ0BFtyMzJZkwU24QqHvoHyw9/dVO8/NFPydwjaI9uZMu6/QUYKKvkbf6VUXXQUHIiZgX0GCudpB908BqWIcj0dWv8oKGGajQWp+d8Jlx/nxbUTAs8vL1f0dxW3LYCZsDExHmjRQTBhM0pQVMT+HlA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert:
            "MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/",
          validateInResponseTo: false,
        };
        const samlObj = new SAML(samlConfig);

        fakeClock = sinon.useFakeTimers(Date.parse("2014-06-05T12:07:07.662Z"));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("UIS/jochen-work");
        const value = await samlObj.cacheProvider.getAsync(requestId);
        should.exist(value);
        value!.should.eql("2014-06-05T12:07:07.662Z");
      });

      it("xml document with multiple AttributeStatements should have all attributes present on profile", async () => {
        const requestId = "_dfab47d5d46374cd4b71";
        const xml =
          '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" InResponseTo="_dfab47d5d46374cd4b71" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" InResponseTo="_dfab47d5d46374cd4b71"/></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>qD+sVCaEdy1dTJoUQdo6o+tYsuU=</DigestValue></Reference></SignedInfo><SignatureValue>aLl+1yT7zdT4WnRXKh9cx7WWZnUi/NoxMJWhXP5d+Zu9A4/fjKApSywimU0MTTQxYpvZLjOZPsSwmvc1boJOlXveDsL7A3YWi/f7/zqlVWOfXLE8TVLqUE4jtLsJHFWIJXmh8CI0loqQNf6QcYi9BwCK82FhhXC+qWA5WCZIIWUUMxjxnPbunQ7mninEeW568wqyhb9pLV8QkThzZrZINCqxNvWyGuK/XGPx7ciD6ywbBkdOjlDbwRMaKQ9YeCzZGGzJwOe/NuCXj+oUyzfmzUCobIIR0HYLc4B5UplL7XIKQzpOA2lDDsLe6ZzdTv1qjxSm+dlVfo24onmiPlQUgA==</SignatureValue></Signature></samlp:Response>';
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert:
            "MIIDtTCCAp2gAwIBAgIJAKg4VeVcIDz1MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwODEzMDE1NDIwWhcNMTUwOTEyMDE1NDIwWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG3ouM7U+fXbJt69X1H6d4UNg/uRr06pFuU9RkfIwNC+yaXyptqB3ynXKsL7BFt4DCd0fflRvJAx3feJIDp16wN9GDVHcufWMYPhh2j5HcTW/j9JoIJzGhJyvO00YKBt+hHy83iN1SdChKv5y0iSyiPP5GnqFw+ayyHoM6hSO0PqBou1Xb0ZSIE+DHosBnvVna5w2AiPY4xrJl9yZHZ4Q7DfMiYTgstjETio4bX+6oLiBnYktn7DjdEslqhffVme4PuBxNojI+uCeg/sn4QVLd/iogMJfDWNuLD8326Mi/FE9cCRvFlvAiMSaebMI3zPaySsxTK7Zgj5TpEbmbHI9wIDAQABo4GnMIGkMB0GA1UdDgQWBBSVGgvoW4MhMuzBGce29PY8vSzHFzB1BgNVHSMEbjBsgBSVGgvoW4MhMuzBGce29PY8vSzHF6FJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKg4VeVcIDz1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJu1rqs+anD74dbdwgd3CnqnQsQDJiEXmBhG2leaGt3ve9b/9gKaJg2pyb2NyppDe1uLqh6nNXDuzg1oNZrPz5pJL/eCXPl7FhxhMUi04TtLf8LeNTCIWYZiFuO4pmhohHcv8kRvYR1+6SkLTC8j/TZerm7qvesSiTQFNapa1eNdVQ8nFwVkEtWl+JzKEM1BlRcn42sjJkijeFp7DpI7pU+PnYeiaXpRv5pJo8ogM1iFxN+SnfEs0EuQ7fhKIG9aHKi7bKZ7L6SyX7MDIGLeulEU6lf5D9BfXNmcMambiS0pXhL2QXajt96UBq8FT2KNXY8XNtR4y6MyyCzhaiZZcc8=",
          validateInResponseTo: true,
        };
        const samlObj = new SAML(samlConfig);

        fakeClock = sinon.useFakeTimers(Date.parse("2014-06-05T12:07:07.662Z"));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("UIS/jochen-work");
        (profile!["vz::identity"] as string).should.equal("UIS/jochen-work");
        (profile!["vz::subjecttype"] as string).should.equal("UIS user");
        (profile!["vz::account"] as string).should.equal("e9aba0c4-ece8-4b44-9526-d24418aa95dc");
        (profile!["vz::org"] as string).should.equal("testorg");
        (profile!["vz::name"] as string).should.equal("Test User");
        (profile!["net::ip"] as string).should.equal("::1");
        const value = await samlObj.cacheProvider.getAsync(requestId);
        should.not.exist(value);
      });

      describe("InResponseTo server cache expiration tests /", () => {
        it("should expire a cached request id after the time", async () => {
          const requestId = "_dfab47d5d46374cd4b71";

          const samlConfig = {
            validateInResponseTo: true,
            requestIdExpirationPeriodMs: 100,
            cert: FAKE_CERT,
          };
          const samlObj = new SAML(samlConfig);

          // Mock the SAML request being passed through Passport-SAML
          await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

          await (() => new Promise((resolve) => setTimeout(resolve, 300)))();
          const value = await samlObj.cacheProvider.getAsync(requestId);
          should.not.exist(value);
        });

        it("should expire many cached request ids after the time", async () => {
          const expiredRequestId1 = "_dfab47d5d46374cd4b71";
          const expiredRequestId2 = "_dfab47d5d46374cd4b72";
          const requestId = "_dfab47d5d46374cd4b73";

          const samlConfig = {
            validateInResponseTo: true,
            requestIdExpirationPeriodMs: 100,
            cert: FAKE_CERT,
          };
          const samlObj = new SAML(samlConfig);

          await samlObj.cacheProvider.saveAsync(expiredRequestId1, new Date().toISOString());
          await samlObj.cacheProvider.saveAsync(expiredRequestId2, new Date().toISOString());

          await new Promise((resolve) => setTimeout(resolve, 300));
          // Add one more that shouldn't expire
          await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

          const value1 = await samlObj.cacheProvider.getAsync(expiredRequestId1);
          should.not.exist(value1);
          const value2 = await samlObj.cacheProvider.getAsync(expiredRequestId2);
          should.not.exist(value2);
          const value3 = await samlObj.cacheProvider.getAsync(requestId);
          should.exist(value3);
          await (() => new Promise((resolve) => setTimeout(resolve, 300)))();
          const value4 = await samlObj.cacheProvider.getAsync(requestId);
          should.not.exist(value4);
        });
      });
    });

    describe("assertion condition checks /", function () {
      const samlConfig = {
        entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
        cert: TEST_CERT,
      };
      let fakeClock: sinon.SinonFakeTimers;

      beforeEach(function () {
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:09Z"));
      });

      afterEach(function () {
        fakeClock.restore();
      });

      it("onelogin xml document with current time after NotBefore time should validate", async () => {
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML(samlConfig);

        // Fake the current date to be within the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:09Z"));

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("ploer");
      });

      it("onelogin xml document with current time equal to NotBefore (plus default clock skew)  time should validate", async () => {
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML(samlConfig);

        // Fake the current date to be within the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:08Z"));

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("ploer");
      });

      it("onelogin xml document with current time before NotBefore time should fail", async () => {
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML(samlConfig);

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:13:07Z"));
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: "SAML assertion not yet valid",
        });
      });

      it("onelogin xml document with current time equal to NotOnOrAfter (minus default clock skew) time should fail", async () => {
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML(samlConfig);

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:19:08Z"));
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: "SAML assertion expired",
        });
      });

      it("onelogin xml document with current time after NotOnOrAfter time (minus default clock skew) should fail", async () => {
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };
        const samlObj = new SAML(samlConfig);

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:19:09Z"));
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: "SAML assertion expired",
        });
      });

      it("onelogin xml document with current time after NotOnOrAfter time with accepted clock skew equal to -1 should pass", async () => {
        const xml =
          '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          TEST_CERT +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          "</samlp:Response>";
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          cert: TEST_CERT,
          acceptedClockSkewMs: -1,
        };
        const samlObj = new SAML(samlConfig);

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse("2014-05-28T00:20:09Z"));

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("ploer");
      });

      it("onelogin xml document with audience and no AudienceRestriction should not pass", async () => {
        const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");
        const xml = `<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfx1e2f568f-ba3e-9d81-af54-ab41fdbc648e" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50">
  <saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx1e2f568f-ba3e-9d81-af54-ab41fdbc648e"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>EiaOqK9GBBENUFaN2AVlYOvlq8E=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>vUf14oqiSWa2xhU1hZBEF3Z9JcYsVzWq+B1vXg0vQfN8GEfmooRogtA3oLs2SKhtpcVwEPuIVf6hRnEL713STMBbYxhnk/om+zMor82bQgn+eR/n3g3AWFPbLGxHbYXK06X47Vo+RRm5H8xVb9FiECXYs6CUCtVksAnitDp0pFgB8G5FKx2OwKALg1LNsKItkzWfI7yaQPKyywFwGgDqXVJYiD1v1HKb3JEvpiL96vVOYSI1+7j/Jy2brYJfs4ADnuAKEXVDgYdtaIQrGa+0x2W9KInCWgR+H40nBTHecE5NGeE01/s0is8nVbmSVrdpBpw44t2xcnp+TzozTGTm2g==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAKg4VeVcIDz1MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwODEzMDE1NDIwWhcNMTUwOTEyMDE1NDIwWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG3ouM7U+fXbJt69X1H6d4UNg/uRr06pFuU9RkfIwNC+yaXyptqB3ynXKsL7BFt4DCd0fflRvJAx3feJIDp16wN9GDVHcufWMYPhh2j5HcTW/j9JoIJzGhJyvO00YKBt+hHy83iN1SdChKv5y0iSyiPP5GnqFw+ayyHoM6hSO0PqBou1Xb0ZSIE+DHosBnvVna5w2AiPY4xrJl9yZHZ4Q7DfMiYTgstjETio4bX+6oLiBnYktn7DjdEslqhffVme4PuBxNojI+uCeg/sn4QVLd/iogMJfDWNuLD8326Mi/FE9cCRvFlvAiMSaebMI3zPaySsxTK7Zgj5TpEbmbHI9wIDAQABo4GnMIGkMB0GA1UdDgQWBBSVGgvoW4MhMuzBGce29PY8vSzHFzB1BgNVHSMEbjBsgBSVGgvoW4MhMuzBGce29PY8vSzHF6FJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKg4VeVcIDz1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJu1rqs+anD74dbdwgd3CnqnQsQDJiEXmBhG2leaGt3ve9b/9gKaJg2pyb2NyppDe1uLqh6nNXDuzg1oNZrPz5pJL/eCXPl7FhxhMUi04TtLf8LeNTCIWYZiFuO4pmhohHcv8kRvYR1+6SkLTC8j/TZerm7qvesSiTQFNapa1eNdVQ8nFwVkEtWl+JzKEM1BlRcn42sjJkijeFp7DpI7pU+PnYeiaXpRv5pJo8ogM1iFxN+SnfEs0EuQ7fhKIG9aHKi7bKZ7L6SyX7MDIGLeulEU6lf5D9BfXNmcMambiS0pXhL2QXajt96UBq8FT2KNXY8XNtR4y6MyyCzhaiZZcc8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z">
    <saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"/>
    <saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`;
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          audience: "http://sp.example.com",
          acceptedClockSkewMs: -1,
          cert: signingCert,
        };
        const samlObj = new SAML(samlConfig);
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: "SAML assertion has no AudienceRestriction",
        });
      });

      it("onelogin xml document with audience not matching AudienceRestriction should not pass", async () => {
        const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");
        const xml = `<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfxeda919ac-e0ca-fff5-4987-efd3b459a1d5" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50">
  <saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxeda919ac-e0ca-fff5-4987-efd3b459a1d5"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>SYyNspaWBrl3SgQGlt8RysQRfXI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>km4aqMCXkupbpp/YR2+dOD2BbnGKO1MDVRMPKSzSx3BwsXhBBYlFNx1ht46zZDSQF60iAHd/vHGcJV8V7QNCeuIgfmTNkh2jtcF5ghRNfmvgpLRwRt1dT/UqApzo8kdRKXcUu0yxziPKFoE6EEvF/NR+YV/aAngEH3dCbOsN1u56zBOa4DZ7EMoWgwmPodaHOgNy4xazv5+Cb+mQM8YC1060EvipIrRU28BWIb3teUlfHL3L8AMlyCqjkw21dkbVOcHNy080oWW+MkjMGbt6r3y2iwpDfJMk5R63T5fXFDIStbVD7ss2BzqGccBykHomm/hU9GYWoO+0kW/reLiXiw==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAKg4VeVcIDz1MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwODEzMDE1NDIwWhcNMTUwOTEyMDE1NDIwWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG3ouM7U+fXbJt69X1H6d4UNg/uRr06pFuU9RkfIwNC+yaXyptqB3ynXKsL7BFt4DCd0fflRvJAx3feJIDp16wN9GDVHcufWMYPhh2j5HcTW/j9JoIJzGhJyvO00YKBt+hHy83iN1SdChKv5y0iSyiPP5GnqFw+ayyHoM6hSO0PqBou1Xb0ZSIE+DHosBnvVna5w2AiPY4xrJl9yZHZ4Q7DfMiYTgstjETio4bX+6oLiBnYktn7DjdEslqhffVme4PuBxNojI+uCeg/sn4QVLd/iogMJfDWNuLD8326Mi/FE9cCRvFlvAiMSaebMI3zPaySsxTK7Zgj5TpEbmbHI9wIDAQABo4GnMIGkMB0GA1UdDgQWBBSVGgvoW4MhMuzBGce29PY8vSzHFzB1BgNVHSMEbjBsgBSVGgvoW4MhMuzBGce29PY8vSzHF6FJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKg4VeVcIDz1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJu1rqs+anD74dbdwgd3CnqnQsQDJiEXmBhG2leaGt3ve9b/9gKaJg2pyb2NyppDe1uLqh6nNXDuzg1oNZrPz5pJL/eCXPl7FhxhMUi04TtLf8LeNTCIWYZiFuO4pmhohHcv8kRvYR1+6SkLTC8j/TZerm7qvesSiTQFNapa1eNdVQ8nFwVkEtWl+JzKEM1BlRcn42sjJkijeFp7DpI7pU+PnYeiaXpRv5pJo8ogM1iFxN+SnfEs0EuQ7fhKIG9aHKi7bKZ7L6SyX7MDIGLeulEU6lf5D9BfXNmcMambiS0pXhL2QXajt96UBq8FT2KNXY8XNtR4y6MyyCzhaiZZcc8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z">
    <saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`;
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          audience: "http://sp.example.com",
          acceptedClockSkewMs: -1,
          cert: signingCert,
        };
        const samlObj = new SAML(samlConfig);
        await assert.rejects(samlObj.validatePostResponseAsync(container), {
          message: "SAML assertion audience mismatch",
        });
      });

      it("onelogin xml document with audience matching AudienceRestriction should pass", async () => {
        const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");
        const xml = `<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfx9bf4fce3-7a3c-5530-22c9-d7c66cdaac4e" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50">
  <saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx9bf4fce3-7a3c-5530-22c9-d7c66cdaac4e"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>SWMNMbWptW3RzRXBEHv4kvu3rbU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LiyXwB09CavCEDR3SkjRzuoUn2Mruk8pBfWyN1K7zefjbtahezIljOYIIumZAsC8hrVndeG7Pk2rE6pL04vcRcASmPlmyytb0yYwyjmhEhTR6nmfBMS0a9mwvQE5/4+TecVW4yWUcMd7m12EhWz8+RcmHRnKWSCsVDxlF0zPUHgJc8n6Yr489mNcRFGKpaWtcH9vEvf689jxNgdqXjS5SvSBJClZd6ir0KFH799etbY5TORx3p0zR+okq7ZP4A9XVcnHWZw4e3KBJ04xQ31fDcr2Cgi3qkLEaaj5HkKAE4PWZ/5G75VHFM3xAZ9rsVL5mwQAJRXFgNbSYCWOUZ4NCg==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAKg4VeVcIDz1MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwODEzMDE1NDIwWhcNMTUwOTEyMDE1NDIwWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG3ouM7U+fXbJt69X1H6d4UNg/uRr06pFuU9RkfIwNC+yaXyptqB3ynXKsL7BFt4DCd0fflRvJAx3feJIDp16wN9GDVHcufWMYPhh2j5HcTW/j9JoIJzGhJyvO00YKBt+hHy83iN1SdChKv5y0iSyiPP5GnqFw+ayyHoM6hSO0PqBou1Xb0ZSIE+DHosBnvVna5w2AiPY4xrJl9yZHZ4Q7DfMiYTgstjETio4bX+6oLiBnYktn7DjdEslqhffVme4PuBxNojI+uCeg/sn4QVLd/iogMJfDWNuLD8326Mi/FE9cCRvFlvAiMSaebMI3zPaySsxTK7Zgj5TpEbmbHI9wIDAQABo4GnMIGkMB0GA1UdDgQWBBSVGgvoW4MhMuzBGce29PY8vSzHFzB1BgNVHSMEbjBsgBSVGgvoW4MhMuzBGce29PY8vSzHF6FJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKg4VeVcIDz1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJu1rqs+anD74dbdwgd3CnqnQsQDJiEXmBhG2leaGt3ve9b/9gKaJg2pyb2NyppDe1uLqh6nNXDuzg1oNZrPz5pJL/eCXPl7FhxhMUi04TtLf8LeNTCIWYZiFuO4pmhohHcv8kRvYR1+6SkLTC8j/TZerm7qvesSiTQFNapa1eNdVQ8nFwVkEtWl+JzKEM1BlRcn42sjJkijeFp7DpI7pU+PnYeiaXpRv5pJo8ogM1iFxN+SnfEs0EuQ7fhKIG9aHKi7bKZ7L6SyX7MDIGLeulEU6lf5D9BfXNmcMambiS0pXhL2QXajt96UBq8FT2KNXY8XNtR4y6MyyCzhaiZZcc8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z">
    <saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>`;
        const base64xml = Buffer.from(xml).toString("base64");
        const container = { SAMLResponse: base64xml };

        const samlConfig = {
          entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
          audience: "http://sp.example.com",
          acceptedClockSkewMs: -1,
          cert: signingCert,
        };
        const samlObj = new SAML(samlConfig);

        const { profile } = await samlObj.validatePostResponseAsync(container);
        profile!.nameID!.should.startWith("ploer");
      });
    });
  });
  describe("validatePostRequest()", function () {
    let samlObj: SAML;
    beforeEach(function () {
      samlObj = new SAML({
        cert: fs.readFileSync(__dirname + "/static/cert.pem", "ascii"),
      });
    });

    it("errors if bad xml", async function () {
      const body = {
        SAMLRequest: "asdf",
      };
      await assert.rejects(samlObj.validatePostRequestAsync(body), {
        message: /Non-whitespace before first tag/,
      });
    });
    it("errors if bad signature", async () => {
      const body = {
        SAMLRequest: fs.readFileSync(
          __dirname + "/static/logout_request_with_bad_signature.xml",
          "base64"
        ),
      };
      await assert.rejects(samlObj.validatePostRequestAsync(body), {
        message: "Invalid signature on documentElement",
      });
    });
    it("returns profile for valid signature", async () => {
      const body = {
        SAMLRequest: fs.readFileSync(
          __dirname + "/static/logout_request_with_good_signature.xml",
          "base64"
        ),
      };
      const { profile } = await samlObj.validatePostRequestAsync(body);
      profile!.should.eql({
        ID: "pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1",
        issuer: "http://sp.example.com/demo1/metadata.php",
        nameID: "ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7",
        nameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      });
    });
    it("returns profile for valid signature including session index", async () => {
      const body = {
        SAMLRequest: fs.readFileSync(
          __dirname + "/static/logout_request_with_session_index.xml",
          "base64"
        ),
      };
      const { profile } = await samlObj.validatePostRequestAsync(body);
      profile!.should.eql({
        ID: "pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1",
        issuer: "http://sp.example.com/demo1/metadata.php",
        nameID: "ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7",
        nameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        sessionIndex: "1",
      });
    });
    it("returns profile for valid signature with encrypted nameID", async () => {
      const samlObj = new SAML({
        cert: fs.readFileSync(__dirname + "/static/cert.pem", "ascii"),
        decryptionPvk: fs.readFileSync(__dirname + "/static/key.pem", "ascii"),
      });
      const body = {
        SAMLRequest: fs.readFileSync(
          __dirname + "/static/logout_request_with_encrypted_name_id.xml",
          "base64"
        ),
      };
      const { profile } = await samlObj.validatePostRequestAsync(body);
      profile!.should.eql({
        ID: "pfx00cb5227-d9d0-1d4b-bdb2-c7ad6c3c6906",
        issuer: "http://sp.example.com/demo1/metadata.php",
        nameID: "ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7",
        nameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        sessionIndex: "1",
      });
    });
  });
  it("validatePostRequest errors for encrypted nameID with wrong decryptionPvk", async () => {
    const samlObj = new SAML({
      cert: fs.readFileSync(__dirname + "/static/cert.pem", "ascii"),
      decryptionPvk: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "ascii"),
    });
    const body = {
      SAMLRequest: fs.readFileSync(
        __dirname + "/static/logout_request_with_encrypted_name_id.xml",
        "base64"
      ),
    };
    await assert.rejects(samlObj.validatePostRequestAsync(body), {
      message: "Encryption block is invalid.",
    });
  });
  it("errors if bad privateCert to requestToURL", async () => {
    const samlObj = new SAML({
      entryPoint: "foo",
      privateCert:
        "-----BEGIN CERTIFICATE-----\n" +
        "8mvhvrcCOiJ3mjgKNN1F31jOBJuZNmq0U7n9v+Z+3NfyU/0E9jkrnFvm5ks+p8kl\n" +
        "BjuBk9RAkazsU9l02XMS/VxOOIifxKC7R9bDtx0hjolYxgqxPIO5s4rmjj0rLzvo\n" +
        "vQTTTx/tB5e+hbdx922QSeTjP4DO4ms6cIexcH+ZEUOJ3wXiHToJW83SXLRtwPI9\n" +
        "JbWKeS9nWPnzcedbDNZkGtohW5vf32BHuvLsWcl6eFXRSkdX/7+rgpXmDRB7caQ+\n" +
        "2SXVY7ORily7LTKg1cFmuKHDzKTGFIp5/GU6dwIDAQABAoIBAArgFQ+Uk4UN4diY\n" +
        "gJWCAaQlTVmP0UEHZQt/NmJrc9ZVduuhOP0hH6gF53nREHz5UQb4nXB2Ksa3MtYD\n" +
        "Z1vhJcu/T7pvmib4q+Ij6oAmlyeL/xwVY3IUURMxX3tCdPItlk4PEFELKeqQOiIS\n" +
        "7B0DYxWfJbMle3c95w5ruYEr2A+fHCKVSlDpg7uPd9VQ6t7bGMZZvc9tDSC1qPXQ\n" +
        "Gd/WOMXxi+t/TpyVZ6tOcEekQzAMLmWElUUPx3TJ0ur0Zl2LZ7IvQEXXias4lUHV\n" +
        "fnH3akDCMmdhlJSVqUfplrh85zAOh6fLloZagphj/Kpgfw1TZ+njSDYqSLYE0NZ1\n" +
        "j+83feECgYEA2aNGgbc+t6QLrJJ63l9Mz541lVV3IUAxZ5ACqOnMkQVuLoa5IMwM\n" +
        "oENIo38ptfHQqjQ9x8/tEINFqOHnQuOJ/+1xP9f0Me+0clRDCqjGYqNYgmakKyD7\n" +
        "vey/q6kwHk679RVGiI1p+HdoA+CbEKWHJiRxE0RhAA3G3wGAq7kpJocCgYEAxp4/\n" +
        "tCft+eHVRivspfDN//axc2TR6qWP9E1ueGvbiXPXv0Puag0W9cER/df/s5jW4Rqg\n" +
        "CE8649HPUZ0FJT+YaeKgu2Sw9SMcGl4/uyHzg7KnXIeYyQZJPqQkKyXmIix8cw3+\n" +
        "HBGRtwX5nOy0DgFdaMiH0F08peNI9QHKKTBoWJECgYEAyymJ1ekzWMaAR1Zt8EvS\n" +
        "LjWoG4EuthFwjRZ4BSpLVk1Vb4VAKAeS+cAVfNpmG3xip6Ag0/ebe0CvtFk9QsmZ\n" +
        "txj2EP0M7div/9H8y2SF3OpS41fhhIlDtyXcPuivDHu/Jaf4sdwgwlrk9EmlN0Lu\n" +
        "CIMYMz4vtpclwGNss+EjMt0CgYEAqepD0Vm/iuCaVhfJsgSaFvnywSdlNfpBdtyv\n" +
        "PzH2dFa4IZZ55hwgoklznNgmlnyQh68BbVpqpO+fDtDnz//h4ePRYb84a96Hcj9j\n" +
        "AjJ/YxF5f/04xfEsw/wkPQ2FHYM1TDCSTWzyXcMs0gTl3H1qbfPvzF+XPMt+ZKwN\n" +
        "SMNy4SECgYB3ig6t+XVfNkw8oBOh0Gx37XKbmImXsA8ucDAX9KUbMIvD03XCEf34\n" +
        "jF3SNJh0SmHoT62vc+cJqPxMDP6E7Q1nZxsEyaAkKr2H4dSM4SlRm0VB+bS+jXsz\n" +
        "PCiRGSm8eupuxfix05LMMreo4mC7e3Ir4JhdCsXxAMZIvbNyXcvUMA==\n" +
        "-----END CERTIFICATE-----\n",
      cert: FAKE_CERT,
    });
    const request =
      '<?xml version=\\"1.0\\"?><samlp:AuthnRequest xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" ID=\\"_ea40a8ab177df048d645\\" Version=\\"2.0\\" IssueInstant=\\"2017-08-22T19:30:01.363Z\\" ProtocolBinding=\\"urn:oasis:names$tc:SAML:2.0:bindings:HTTP-POST\\" AssertionConsumerServiceURL=\\"https://example.com/login/callback\\" Destination=\\"https://www.example.com\\"><saml:Issuer xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">onelogin_saml</saml:Issuer><s$mlp:NameIDPolicy xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" Format=\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\" AllowCreate=\\"true\\"/><samlp:RequestedAuthnContext xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protoc$l\\" Comparison=\\"exact\\"><saml:AuthnContextClassRef xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp$AuthnRequest>';
    await assert.rejects(samlObj.requestToUrlAsync(request, null, "authorize", {}), {
      message: /no start line/,
    });
  });
  it("errors if bad privateKey to requestToURL", async () => {
    const samlObj = new SAML({
      entryPoint: "foo",
      privateKey:
        "-----BEGIN CERTIFICATE-----\n" +
        "8mvhvrcCOiJ3mjgKNN1F31jOBJuZNmq0U7n9v+Z+3NfyU/0E9jkrnFvm5ks+p8kl\n" +
        "BjuBk9RAkazsU9l02XMS/VxOOIifxKC7R9bDtx0hjolYxgqxPIO5s4rmjj0rLzvo\n" +
        "vQTTTx/tB5e+hbdx922QSeTjP4DO4ms6cIexcH+ZEUOJ3wXiHToJW83SXLRtwPI9\n" +
        "JbWKeS9nWPnzcedbDNZkGtohW5vf32BHuvLsWcl6eFXRSkdX/7+rgpXmDRB7caQ+\n" +
        "2SXVY7ORily7LTKg1cFmuKHDzKTGFIp5/GU6dwIDAQABAoIBAArgFQ+Uk4UN4diY\n" +
        "gJWCAaQlTVmP0UEHZQt/NmJrc9ZVduuhOP0hH6gF53nREHz5UQb4nXB2Ksa3MtYD\n" +
        "Z1vhJcu/T7pvmib4q+Ij6oAmlyeL/xwVY3IUURMxX3tCdPItlk4PEFELKeqQOiIS\n" +
        "7B0DYxWfJbMle3c95w5ruYEr2A+fHCKVSlDpg7uPd9VQ6t7bGMZZvc9tDSC1qPXQ\n" +
        "Gd/WOMXxi+t/TpyVZ6tOcEekQzAMLmWElUUPx3TJ0ur0Zl2LZ7IvQEXXias4lUHV\n" +
        "fnH3akDCMmdhlJSVqUfplrh85zAOh6fLloZagphj/Kpgfw1TZ+njSDYqSLYE0NZ1\n" +
        "j+83feECgYEA2aNGgbc+t6QLrJJ63l9Mz541lVV3IUAxZ5ACqOnMkQVuLoa5IMwM\n" +
        "oENIo38ptfHQqjQ9x8/tEINFqOHnQuOJ/+1xP9f0Me+0clRDCqjGYqNYgmakKyD7\n" +
        "vey/q6kwHk679RVGiI1p+HdoA+CbEKWHJiRxE0RhAA3G3wGAq7kpJocCgYEAxp4/\n" +
        "tCft+eHVRivspfDN//axc2TR6qWP9E1ueGvbiXPXv0Puag0W9cER/df/s5jW4Rqg\n" +
        "CE8649HPUZ0FJT+YaeKgu2Sw9SMcGl4/uyHzg7KnXIeYyQZJPqQkKyXmIix8cw3+\n" +
        "HBGRtwX5nOy0DgFdaMiH0F08peNI9QHKKTBoWJECgYEAyymJ1ekzWMaAR1Zt8EvS\n" +
        "LjWoG4EuthFwjRZ4BSpLVk1Vb4VAKAeS+cAVfNpmG3xip6Ag0/ebe0CvtFk9QsmZ\n" +
        "txj2EP0M7div/9H8y2SF3OpS41fhhIlDtyXcPuivDHu/Jaf4sdwgwlrk9EmlN0Lu\n" +
        "CIMYMz4vtpclwGNss+EjMt0CgYEAqepD0Vm/iuCaVhfJsgSaFvnywSdlNfpBdtyv\n" +
        "PzH2dFa4IZZ55hwgoklznNgmlnyQh68BbVpqpO+fDtDnz//h4ePRYb84a96Hcj9j\n" +
        "AjJ/YxF5f/04xfEsw/wkPQ2FHYM1TDCSTWzyXcMs0gTl3H1qbfPvzF+XPMt+ZKwN\n" +
        "SMNy4SECgYB3ig6t+XVfNkw8oBOh0Gx37XKbmImXsA8ucDAX9KUbMIvD03XCEf34\n" +
        "jF3SNJh0SmHoT62vc+cJqPxMDP6E7Q1nZxsEyaAkKr2H4dSM4SlRm0VB+bS+jXsz\n" +
        "PCiRGSm8eupuxfix05LMMreo4mC7e3Ir4JhdCsXxAMZIvbNyXcvUMA==\n" +
        "-----END CERTIFICATE-----\n",
      cert: FAKE_CERT,
    });
    const request =
      '<?xml version=\\"1.0\\"?><samlp:AuthnRequest xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" ID=\\"_ea40a8ab177df048d645\\" Version=\\"2.0\\" IssueInstant=\\"2017-08-22T19:30:01.363Z\\" ProtocolBinding=\\"urn:oasis:names$tc:SAML:2.0:bindings:HTTP-POST\\" AssertionConsumerServiceURL=\\"https://example.com/login/callback\\" Destination=\\"https://www.example.com\\"><saml:Issuer xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">onelogin_saml</saml:Issuer><s$mlp:NameIDPolicy xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" Format=\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\" AllowCreate=\\"true\\"/><samlp:RequestedAuthnContext xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protoc$l\\" Comparison=\\"exact\\"><saml:AuthnContextClassRef xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp$AuthnRequest>';
    await assert.rejects(samlObj.requestToUrlAsync(request, null, "authorize", {}), {
      message: /no start line/,
    });
  });
});

describe("validateRedirect()", function () {
  describe("idp slo", function () {
    let samlObj: SAML;
    let fakeClock: sinon.SinonFakeTimers;
    beforeEach(function () {
      samlObj = new SAML({
        cert: fs.readFileSync(__dirname + "/static/acme_tools_com.cert", "ascii"),
        idpIssuer: "http://localhost:20000/saml2/idp/metadata.php",
      });
      this.request = Object.assign(
        {},
        JSON.parse(fs.readFileSync(__dirname + "/static/idp_slo_redirect.json", "utf8"))
      );
      fakeClock = sinon.useFakeTimers(Date.parse("2018-04-11T14:08:00Z"));
    });
    afterEach(function () {
      fakeClock.restore();
    });
    it("errors if bad xml", async function () {
      const body = {
        SAMLRequest: "asdf",
      };
      await assert.rejects(samlObj.validateRedirectAsync(body, this.request.originalQuery));
    });
    it("errors if idpIssuer is set and issuer is wrong", async function () {
      samlObj.options.idpIssuer = "foo";
      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        {
          message:
            "Unknown SAML issuer. Expected: foo Received: http://localhost:20000/saml2/idp/metadata.php",
        }
      );
    });
    it("errors if request has expired", async function () {
      fakeClock.restore();
      fakeClock = sinon.useFakeTimers(Date.parse("2100-04-11T14:08:00Z"));

      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        { message: "SAML assertion expired" }
      );
    });
    it("errors if request has a bad signature", async function () {
      this.request.Signature = "foo";
      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        { message: "Invalid query signature" }
      );
    });
    it("returns profile for valid signature including session index", async function () {
      const { profile } = await samlObj.validateRedirectAsync(
        this.request,
        this.request.originalQuery
      );
      profile!.should.eql({
        ID: "_8f0effde308adfb6ae7f1e29b414957fc320f5636f",
        issuer: "http://localhost:20000/saml2/idp/metadata.php",
        nameID: "stavros@workable.com",
        nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        sessionIndex: "_00bf7b2d5d9d3c970217eecefb1194bef3362a618e",
      });
    });
  });
  describe("sp slo", function () {
    let samlObj: SAML;

    beforeEach(function () {
      samlObj = new SAML({
        cert: fs.readFileSync(__dirname + "/static/acme_tools_com.cert", "ascii"),
        idpIssuer: "http://localhost:20000/saml2/idp/metadata.php",
        validateInResponseTo: true,
      });
      this.request = Object.assign(
        {},
        JSON.parse(fs.readFileSync(__dirname + "/static/sp_slo_redirect.json", "utf8"))
      );
    });
    afterEach(async function () {
      await samlObj.cacheProvider.removeAsync("_79db1e7ad12ca1d63e5b");
    });
    it("errors if bad xml", async function () {
      const body = {
        SAMLRequest: "asdf",
      };
      await assert.rejects(samlObj.validateRedirectAsync(body, null));
    });
    it("errors if idpIssuer is set and wrong issuer", async function () {
      samlObj.options.idpIssuer = "foo";
      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        {
          message:
            "Unknown SAML issuer. Expected: foo Received: http://localhost:20000/saml2/idp/metadata.php",
        }
      );
    });
    it("errors if unsuccessful", async function () {
      this.request = JSON.parse(
        fs.readFileSync(__dirname + "/static/sp_slo_redirect_failure.json", "utf8")
      );
      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        { message: "Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester" }
      );
    });
    it("errors if InResponseTo is not found", async function () {
      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        { message: "InResponseTo is not valid" }
      );
    });
    it("errors if bad signature", async function () {
      await samlObj.cacheProvider.saveAsync("_79db1e7ad12ca1d63e5b", new Date().toISOString());
      this.request.Signature = "foo";
      await assert.rejects(
        samlObj.validateRedirectAsync(this.request, this.request.originalQuery),
        { message: "Invalid query signature" }
      );
    });

    it("returns true for valid signature", async function () {
      await samlObj.cacheProvider.saveAsync("_79db1e7ad12ca1d63e5b", new Date().toISOString());
      const { loggedOut } = await samlObj.validateRedirectAsync(
        this.request,
        this.request.originalQuery
      );
      loggedOut!.should.eql(true);
    });

    it("accepts cert without header and footer line", async function () {
      samlObj.options.cert = fs.readFileSync(
        __dirname + "/static/acme_tools_com_without_header_and_footer.cert",
        "ascii"
      );
      await samlObj.cacheProvider.saveAsync("_79db1e7ad12ca1d63e5b", new Date().toISOString());
      const { loggedOut } = await samlObj.validateRedirectAsync(
        this.request,
        this.request.originalQuery
      );
      loggedOut!.should.eql(true);
    });
  });
});
