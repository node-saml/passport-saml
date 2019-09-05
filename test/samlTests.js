'use strict';

var SAML = require('../lib/passport-saml/saml.js').SAML;
var should = require('should');
var url = require('url');

describe('SAML.js', function () {
  describe('get Urls', function () {
    var saml, req, options;
    beforeEach(function () {
      saml = new SAML({
        entryPoint: 'https://exampleidp.com/path?key=value',
        logoutUrl: 'https://exampleidp.com/path?key=value'
      });
      req = {
        protocol: 'https',
        headers: {
          host: 'examplesp.com'
        },
        user: {
          nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
          nameID: 'nameID'
        },
        samlLogoutRequest: {
          ID: 123
        }
      };
      options = {
        additionalParams: {
          additionalKey: 'additionalValue'
        }
      };
    });

    describe('getCallbackUrl', function () {
      describe('when callbackUrl and host/path not specified', function () {
        it('returns callbackUrl based on request headers', function () {
          var callbackUrl = saml.getCallbackUrl(req);
          callbackUrl.should.equal('https://examplesp.com/saml/consume')
        });
      });

      describe('when protocol, host, path specified', function () {
        beforeEach(function () {
          saml = new SAML({
            entryPoint: 'https://exampleidp.com/path?key=value',
            logoutUrl: 'https://exampleidp.com/path?key=value',
            protocol: 'test-protocol://',
            host: 'test-host',
            path: '/test-path'
          });
        });

        it('returns callbackUrl', function () {
          var callbackUrl = saml.getCallbackUrl(req);
          callbackUrl.should.equal('test-protocol://test-host/test-path')
        });
      });

      describe('when callbackUrl specified', function () {
        beforeEach(function () {
          saml = new SAML({
            entryPoint: 'https://exampleidp.com/path?key=value',
            logoutUrl: 'https://exampleidp.com/path?key=value',
            callbackUrl: 'http://fake-callback.com/url'
          });
        });

        it('returns callbackUrl', function () {
          var callbackUrl = saml.getCallbackUrl(req);
          callbackUrl.should.equal('http://fake-callback.com/url')
        });
      });
    });

    describe('getAuthorizeUrl', function () {
      it('calls callback with right host', function (done) {
        saml.getAuthorizeUrl(req, {}, function (err, target) {
          try {
            url.parse(target).host.should.equal('exampleidp.com');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with right protocol', function (done) {
        saml.getAuthorizeUrl(req, {}, function (err, target) {
          try {
            url.parse(target).protocol.should.equal('https:');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with right path', function (done) {
        saml.getAuthorizeUrl(req, {}, function (err, target) {
          try {
            url.parse(target).pathname.should.equal('/path');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with original query string', function (done) {
        saml.getAuthorizeUrl(req, {}, function (err, target) {
          try {
            url.parse(target, true).query['key'].should.equal('value');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with additional run-time params in query string', function (done) {
        saml.getAuthorizeUrl(req, options, function (err, target) {
          try {
            Object.keys(url.parse(target, true).query).should.have.length(3);
            url.parse(target, true).query['key'].should.equal('value');
            url.parse(target, true).query['SAMLRequest'].should.not.be.empty();
            url.parse(target, true).query['additionalKey'].should.equal('additionalValue');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it('calls callback with saml request object', function (done) {
        saml.getAuthorizeUrl(req, {}, function (err, target) {
          try {
            should(url.parse(target, true).query).have.property('SAMLRequest');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    describe('getLogoutUrl', function () {
      it('calls callback with right host', function (done) {
        saml.getLogoutUrl(req, {}, function (err, target) {
          try {
            url.parse(target).host.should.equal('exampleidp.com');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with right protocol', function (done) {
        saml.getLogoutUrl(req, {}, function (err, target) {
          try {
            url.parse(target).protocol.should.equal('https:');
            done();
          } catch(err2) {
            done(err2);
          }
        });
      });
      it('calls callback with right path', function (done) {
        saml.getLogoutUrl(req, {}, function (err, target) {
          try {
            url.parse(target).pathname.should.equal('/path');
            done();
          } catch(err2) {
            done(err2);
          }
        });
      });
      it('calls callback with original query string', function (done) {
        saml.getLogoutUrl(req, {}, function (err, target) {
          try {
            url.parse(target, true).query['key'].should.equal('value');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with additional run-time params in query string', function (done) {
        saml.getLogoutUrl(req, options, function (err, target) {
          try {
            Object.keys(url.parse(target, true).query).should.have.length(3);
            url.parse(target, true).query['key'].should.equal('value');
            url.parse(target, true).query['SAMLRequest'].should.not.be.empty();
            url.parse(target, true).query['additionalKey'].should.equal('additionalValue');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it('calls callback with saml request object', function (done) {
        saml.getLogoutUrl(req, {}, function (err, target) {
          try {
            should(url.parse(target, true).query).have.property('SAMLRequest');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    describe('getLogoutResponseUrl', function () {
      it('calls callback with right host', function (done) {
        saml.getLogoutResponseUrl(req, {}, function (err, target) {
          try {
            url.parse(target).host.should.equal('exampleidp.com');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with right protocol', function (done) {
        saml.getLogoutResponseUrl(req, {}, function (err, target) {
          try {
            url.parse(target).protocol.should.equal('https:');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with right path', function (done) {
        saml.getLogoutResponseUrl(req, {}, function (err, target) {
          try {
            url.parse(target).pathname.should.equal('/path');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with original query string', function (done) {
        saml.getLogoutResponseUrl(req, {}, function (err, target) {
          try {
            url.parse(target, true).query['key'].should.equal('value');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      it('calls callback with additional run-time params in query string', function (done) {
        saml.getLogoutResponseUrl(req, options, function (err, target) {
          try {
            Object.keys(url.parse(target, true).query).should.have.length(3);
            url.parse(target, true).query['key'].should.equal('value');
            url.parse(target, true).query['SAMLResponse'].should.not.be.empty();
            url.parse(target, true).query['additionalKey'].should.equal('additionalValue');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it('calls callback with saml response object', function (done) {
        saml.getLogoutResponseUrl(req, {}, function (err, target) {
          try {
            should(url.parse(target, true).query).have.property('SAMLResponse');
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });
  });
});
