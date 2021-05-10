"use strict";
import * as xmlenc from "xml-encryption";
import * as fs from "fs";
import * as util from "util";
import * as should from "should";
import assert = require("assert");

export const encrytpXml = util.promisify(xmlenc.encrypt);
export const decryptXml = util.promisify(xmlenc.decrypt);

describe("xml /", async function () {
  const rsa_pub = fs.readFileSync(__dirname + "/../static/testshib encryption pub.pem");
  const pem = fs.readFileSync(__dirname + "/../static/testshib encryption cert.pem");
  const key = fs.readFileSync(__dirname + "/../static/testshib encryption pvk.pem");

  it("should decrypt aes128-cbc/rsa-oaep-mgf1p", async function () {
    const encryptOptions: xmlenc.EncryptOptions = {
      rsa_pub,
      pem,
      encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    };

    const decryptOptions: xmlenc.DecryptOptions = {
      key,
      disallowDecryptionWithInsecureAlgorithm: true,
    };

    const originalPayload = "XML payload";
    const encryptedPayload = await encrytpXml(originalPayload, encryptOptions);
    const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

    should(originalPayload).equal(decryptedPayload);
  });

  it("should decrypt aes256-cbc/rsa-oaep-mgf1p", async function () {
    const encryptOptions: xmlenc.EncryptOptions = {
      rsa_pub,
      pem,
      encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    };

    const decryptOptions: xmlenc.DecryptOptions = {
      key,
      disallowDecryptionWithInsecureAlgorithm: true,
    };

    const originalPayload = "XML payload";
    const encryptedPayload = await encrytpXml(originalPayload, encryptOptions);
    const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

    should(originalPayload).equal(decryptedPayload);
  });

  it("should decrypt aes128-gcm/rsa-oaep-mgf1p", async function () {
    const encryptOptions: xmlenc.EncryptOptions = {
      rsa_pub,
      pem,
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    };

    const decryptOptions: xmlenc.DecryptOptions = {
      key,
      disallowDecryptionWithInsecureAlgorithm: true,
    };

    const originalPayload = "XML payload";
    const encryptedPayload = await encrytpXml(originalPayload, encryptOptions);
    const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

    should(originalPayload).equal(decryptedPayload);
  });

  it("should decrypt aes256-gcm/rsa-oaep-mgf1p", async function () {
    const encryptOptions: xmlenc.EncryptOptions = {
      rsa_pub,
      pem,
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    };

    const decryptOptions: xmlenc.DecryptOptions = {
      key,
      disallowDecryptionWithInsecureAlgorithm: true,
    };

    const originalPayload = "XML payload";
    const encryptedPayload = await encrytpXml(originalPayload, encryptOptions);
    const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

    should(originalPayload).equal(decryptedPayload);
  });

  it("should not decrypt tripledes-cbc/rsa-oaep-mgf1p", async function () {
    const encryptOptions: xmlenc.EncryptOptions = {
      rsa_pub,
      pem,
      encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      warnInsecureAlgorithm: false,
    };

    const decryptOptions: xmlenc.DecryptOptions = {
      key,
      disallowDecryptionWithInsecureAlgorithm: true,
    };

    const originalPayload = "XML payload";
    const encryptedPayload = await encrytpXml(originalPayload, encryptOptions);
    const decryptedPayload = await assert.rejects(decryptXml(encryptedPayload, decryptOptions));

    should(decryptedPayload).be.undefined();
  });

  it("should not decrypt aes256-gcm/rsa-1_5", async function () {
    const encryptOptions: xmlenc.EncryptOptions = {
      rsa_pub,
      pem,
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
      warnInsecureAlgorithm: false,
    };

    const decryptOptions: xmlenc.DecryptOptions = {
      key,
      disallowDecryptionWithInsecureAlgorithm: true,
    };

    const originalPayload = "XML payload";
    const encryptedPayload = await encrytpXml(originalPayload, encryptOptions);
    const decryptedPayload = await assert.rejects(decryptXml(encryptedPayload, decryptOptions));

    should(decryptedPayload).be.undefined();
  });
});
