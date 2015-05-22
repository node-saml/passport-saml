'use strict';

var SAML = require('../lib/passport-saml/saml.js').SAML;
var should = require('should');
var url = require('url');

describe('SAML.js', function() {
  describe('getAuthorizeUrl', function() {
    var saml, req;
    beforeEach(function() {
      saml = new SAML({
        entryPoint: 'https://exampleidp.com/path?key=value'
      });
      req = {
        protocol: 'https',
        headers: {
          host: 'examplesp.com'
        }
      }
    });
    it('calls callback with right host', function(done) {
      saml.getAuthorizeUrl(req, function(err, target) {
        url.parse(target).host.should.equal('exampleidp.com');
        done();
      });
    });
    it('calls callback with right protocol', function(done) {
      saml.getAuthorizeUrl(req, function(err, target) {
        url.parse(target).protocol.should.equal('https:');
        done();
      });
    })
    it('calls callback with right path', function(done) {
      saml.getAuthorizeUrl(req, function(err, target) {
        url.parse(target).pathname.should.equal('/path');
        done();
      });
    })
    it('calls callback with original query string', function(done) {
      saml.getAuthorizeUrl(req, function(err, target) {
        url.parse(target, true).query['key'].should.equal('value');
        done();
      });
    })
    // NOTE: This test only tests existence of the assertion, not the correctness
    it('calls callback with saml request object', function(done) {
      saml.getAuthorizeUrl(req, function(err, target) {
        url.parse(target, true).query.should.have.property('SAMLRequest');
        done();
      });
    });
  });
});
