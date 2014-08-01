'use strict';
var should = require( 'should' );
var SAML = require( '../lib/saml.js' );
var sinon = require('sinon');
var MemcacheServer = require('memcaching/test/integration/memcacheserver.js');
var MemcacheClient = require('memcaching');
var MemcacheCacheProvider = require('../lib/memcache-cache-provider.js').CacheProvider;
var InMemoryCacheProvider = require('../lib/inmemory-cache-provider.js').CacheProvider;

var _cacheProvidersToTest = {
  MemcacheCacheProvider: MemcacheCacheProvider,
  InMemoryCacheProvider: InMemoryCacheProvider
};

var _runTestsWithCacheProvider = function(cacheProviderName) {
  var cacheProvider = _cacheProvidersToTest[cacheProviderName];
  describe('InResponseTo validation checks with ' + cacheProviderName + ' cache provider /', function () {
    var fakeClock = null;

    var newCacheProvider = function (expirationPeriod) {
      switch (cacheProvider) {
        case MemcacheCacheProvider:
          return new cacheProvider(memcacheClient, {
            keyExpirationPeriodMs: expirationPeriod
          });
        case InMemoryCacheProvider:
          return new cacheProvider({ keyExpirationPeriodMs: expirationPeriod });
        default:
          throw new Error("Unknown provider in newCacheProvider method.");
      }
    };

    if (cacheProvider === MemcacheCacheProvider) {
      // If we're not on travis, then try to start a memcache server.
      if (!process.env.TRAVIS) {
        var memcacheServer = new MemcacheServer();
      }
      var memcachePort = memcacheServer ? memcacheServer.port : 11211;
      var memcacheClient = new MemcacheClient({ unref: false });
      memcacheClient.addServer('127.0.0.1:' + memcachePort);
    }

    afterEach(function () {
      if (fakeClock) {
        fakeClock.restore();
        fakeClock = null;
      }
    });

    it('onelogin xml document with InResponseTo from request should validate', function (done) {
      var requestId = '_a6fc46be84e1e3cf3c50';
      var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEFzCCAv+gAwIBAgIUFJsUjPM7AmWvNtEvULSHlTTMiLQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDkwHhcNMTQwNTEzMTgwNjEyWhcNMTkwNTE0MTgwNjEyWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU3Vic3BhY2UxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA0MjM0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKrAzJdY9FzFLt5blArJfPzgi87EnFGlTfcV5T1TUDwLBlDkY/0ZGKnMOpf3D7ie2C4pPFOImOogcM5kpDDL7qxTXZ1ewXVyjBdMu29NG2C6NzWeQTUMUji01EcHkC8o+Pts8ANiNOYcjxEeyhEyzJKgEizblYzMMKzdrOET6QuqWo3C83K+5+5dsjDn1ooKGRwj3HvgsYcFrQl9NojgQFjoobwsiE/7A+OJhLpBcy/nSVgnoJaMfrO+JsnukZPztbntLvOl56+Vra0N8n5NAYhaSayPiv/ayhjVgjfXd1tjMVTOiDknUOwizZuJ1Y3QH94vUtBgp0WBpBSs/xMyTs8CAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRQO4WpM5fWwxib49WTuJkfYDbxODCBlQYDVR0jBIGNMIGKgBRQO4WpM5fWwxib49WTuJkfYDbxOKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDmCFBSbFIzzOwJlrzbRL1C0h5U0zIi0MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEACdDAAoaZFCEY5pmfwbKuKrXtO5iE8lWtiCPjCZEUuT6bXRNcqrdnuV/EAfX9WQoXjalPi0eM78zKmbvRGSTUHwWw49RHjFfeJUKvHNeNnFgTXDjEPNhMvh69kHm453lFRmB+kk6yjtXRZaQEwS8Uuo2Ot+krgNbl6oTBZJ0AHH1MtZECDloms1Km7zsK8wAi5i8TVIKkVr5b2VlhrLgFMvzZ5ViAxIMGB6w47yY4QGQB/5Q8ya9hBs9vkn+wubA+yr4j14JXZ7blVKDSTYva65Ea+PqHyrp+Wnmnbw2ObS7iWexiTy1jD3G0R2avDBFjM8Fj5DbfufsE1b0U10RTtg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          '</samlp:Response>';
      var base64xml = new Buffer(xml).toString('base64');
      var container = { SAMLResponse: base64xml };

      var samlConfig = {
        entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        cert: 'MIIEFzCCAv+gAwIBAgIUFJsUjPM7AmWvNtEvULSHlTTMiLQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDkwHhcNMTQwNTEzMTgwNjEyWhcNMTkwNTE0MTgwNjEyWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU3Vic3BhY2UxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA0MjM0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKrAzJdY9FzFLt5blArJfPzgi87EnFGlTfcV5T1TUDwLBlDkY/0ZGKnMOpf3D7ie2C4pPFOImOogcM5kpDDL7qxTXZ1ewXVyjBdMu29NG2C6NzWeQTUMUji01EcHkC8o+Pts8ANiNOYcjxEeyhEyzJKgEizblYzMMKzdrOET6QuqWo3C83K+5+5dsjDn1ooKGRwj3HvgsYcFrQl9NojgQFjoobwsiE/7A+OJhLpBcy/nSVgnoJaMfrO+JsnukZPztbntLvOl56+Vra0N8n5NAYhaSayPiv/ayhjVgjfXd1tjMVTOiDknUOwizZuJ1Y3QH94vUtBgp0WBpBSs/xMyTs8CAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRQO4WpM5fWwxib49WTuJkfYDbxODCBlQYDVR0jBIGNMIGKgBRQO4WpM5fWwxib49WTuJkfYDbxOKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDmCFBSbFIzzOwJlrzbRL1C0h5U0zIi0MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEACdDAAoaZFCEY5pmfwbKuKrXtO5iE8lWtiCPjCZEUuT6bXRNcqrdnuV/EAfX9WQoXjalPi0eM78zKmbvRGSTUHwWw49RHjFfeJUKvHNeNnFgTXDjEPNhMvh69kHm453lFRmB+kk6yjtXRZaQEwS8Uuo2Ot+krgNbl6oTBZJ0AHH1MtZECDloms1Km7zsK8wAi5i8TVIKkVr5b2VlhrLgFMvzZ5ViAxIMGB6w47yY4QGQB/5Q8ya9hBs9vkn+wubA+yr4j14JXZ7blVKDSTYva65Ea+PqHyrp+Wnmnbw2ObS7iWexiTy1jD3G0R2avDBFjM8Fj5DbfufsE1b0U10RTtg==',
        validateInResponseTo: true,
        cacheProvider: newCacheProvider()
      };
      var samlObj = new SAML(samlConfig);

      fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));

      // Mock the SAML request being passed through Passport-SAML
      samlObj.cacheProvider.save(requestId, new Date().toISOString(), function () {
      });

      samlObj.validatePostResponse(container, function (err, profile, logout) {
        should.not.exist(err);
        profile.nameID.should.startWith('ploer');
        samlObj.cacheProvider.get(requestId, function (err, value) {
          should.not.exist(value);
          done();
        });

      });
    });

    it('onelogin xml document without InResponseTo from request should fail', function (done) {
      var requestId = '_a6fc46be84e1e3cf3c50';
      var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEFzCCAv+gAwIBAgIUFJsUjPM7AmWvNtEvULSHlTTMiLQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDkwHhcNMTQwNTEzMTgwNjEyWhcNMTkwNTE0MTgwNjEyWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU3Vic3BhY2UxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA0MjM0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKrAzJdY9FzFLt5blArJfPzgi87EnFGlTfcV5T1TUDwLBlDkY/0ZGKnMOpf3D7ie2C4pPFOImOogcM5kpDDL7qxTXZ1ewXVyjBdMu29NG2C6NzWeQTUMUji01EcHkC8o+Pts8ANiNOYcjxEeyhEyzJKgEizblYzMMKzdrOET6QuqWo3C83K+5+5dsjDn1ooKGRwj3HvgsYcFrQl9NojgQFjoobwsiE/7A+OJhLpBcy/nSVgnoJaMfrO+JsnukZPztbntLvOl56+Vra0N8n5NAYhaSayPiv/ayhjVgjfXd1tjMVTOiDknUOwizZuJ1Y3QH94vUtBgp0WBpBSs/xMyTs8CAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRQO4WpM5fWwxib49WTuJkfYDbxODCBlQYDVR0jBIGNMIGKgBRQO4WpM5fWwxib49WTuJkfYDbxOKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDmCFBSbFIzzOwJlrzbRL1C0h5U0zIi0MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEACdDAAoaZFCEY5pmfwbKuKrXtO5iE8lWtiCPjCZEUuT6bXRNcqrdnuV/EAfX9WQoXjalPi0eM78zKmbvRGSTUHwWw49RHjFfeJUKvHNeNnFgTXDjEPNhMvh69kHm453lFRmB+kk6yjtXRZaQEwS8Uuo2Ot+krgNbl6oTBZJ0AHH1MtZECDloms1Km7zsK8wAi5i8TVIKkVr5b2VlhrLgFMvzZ5ViAxIMGB6w47yY4QGQB/5Q8ya9hBs9vkn+wubA+yr4j14JXZ7blVKDSTYva65Ea+PqHyrp+Wnmnbw2ObS7iWexiTy1jD3G0R2avDBFjM8Fj5DbfufsE1b0U10RTtg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          '</samlp:Response>';
      var base64xml = new Buffer(xml).toString('base64');
      var container = { SAMLResponse: base64xml };

      var samlConfig = {
        entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        cert: 'MIIEFzCCAv+gAwIBAgIUFJsUjPM7AmWvNtEvULSHlTTMiLQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDkwHhcNMTQwNTEzMTgwNjEyWhcNMTkwNTE0MTgwNjEyWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU3Vic3BhY2UxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA0MjM0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKrAzJdY9FzFLt5blArJfPzgi87EnFGlTfcV5T1TUDwLBlDkY/0ZGKnMOpf3D7ie2C4pPFOImOogcM5kpDDL7qxTXZ1ewXVyjBdMu29NG2C6NzWeQTUMUji01EcHkC8o+Pts8ANiNOYcjxEeyhEyzJKgEizblYzMMKzdrOET6QuqWo3C83K+5+5dsjDn1ooKGRwj3HvgsYcFrQl9NojgQFjoobwsiE/7A+OJhLpBcy/nSVgnoJaMfrO+JsnukZPztbntLvOl56+Vra0N8n5NAYhaSayPiv/ayhjVgjfXd1tjMVTOiDknUOwizZuJ1Y3QH94vUtBgp0WBpBSs/xMyTs8CAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRQO4WpM5fWwxib49WTuJkfYDbxODCBlQYDVR0jBIGNMIGKgBRQO4WpM5fWwxib49WTuJkfYDbxOKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDmCFBSbFIzzOwJlrzbRL1C0h5U0zIi0MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEACdDAAoaZFCEY5pmfwbKuKrXtO5iE8lWtiCPjCZEUuT6bXRNcqrdnuV/EAfX9WQoXjalPi0eM78zKmbvRGSTUHwWw49RHjFfeJUKvHNeNnFgTXDjEPNhMvh69kHm453lFRmB+kk6yjtXRZaQEwS8Uuo2Ot+krgNbl6oTBZJ0AHH1MtZECDloms1Km7zsK8wAi5i8TVIKkVr5b2VlhrLgFMvzZ5ViAxIMGB6w47yY4QGQB/5Q8ya9hBs9vkn+wubA+yr4j14JXZ7blVKDSTYva65Ea+PqHyrp+Wnmnbw2ObS7iWexiTy1jD3G0R2avDBFjM8Fj5DbfufsE1b0U10RTtg==',
        validateInResponseTo: true,
        cacheProvider: newCacheProvider()
      };
      var samlObj = new SAML(samlConfig);

      fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));

      samlObj.validatePostResponse(container, function (err, profile, logout) {
        should.exist(err);
        err.message.should.match('InResponseTo is not valid');
        done();
      });
    });

    it('xml document with SubjectConfirmation InResponseTo from request should be valid', function (done) {
      var requestId = '_dfab47d5d46374cd4b71';
      var xml = '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" InResponseTo="_dfab47d5d46374cd4b71" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>QecaVjMY/2M4VMJsakvX8uh2Mrg=</DigestValue></Reference></SignedInfo><SignatureValue>QTJ//ZHEQRe9/nA5qTkhECZc2u6M1dHzTkujKBedskLSRPL8LRBb4Yftla0zu848sYvLd3SXzEysYu/jrAjaVDevYZIAdyj/3HCw8pS0ZnQDaCgYuAkH4JmYxBfW1Sc9Kr0vbR58ihwWOZd4xHIn/b8xLs8WNsyTHix2etrLGznioLwTOBO3+SgjwSiSP9NUhrlOvolbuu/6xhLi37/L08JaBvOw3o0k4V8xS87SFczhm4f6wvQM5mP6sZAreoNcWZqQM7vIHFjL0/H9vTaLAN8+fQOc81xFtateTKwFQlJMUmdWKZ8L7ns0Uf1xASQjXtSAACbXI+PuVLjz8nnm3g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC7TCCAdmgAwIBAgIQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB1Rlc3RTVFMwHhcNMTQwNDE2MTIyMTEwWhcNMzkxMjMxMjM1OTU5WjASMRAwDgYDVQQDEwdUZXN0U1RTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhReamVYbeOWwrrAvHPvS9KKBwv4Tj7wOSGDXbNgfjhSvVyXsnpYRcuoJkvE8b9tCjFTbXCfbhnaVrpoXaWFtP1YvUIZvCJGdOOTXltMNDlNIaFmsIsomza8IyOHXe+3xHWVtxO8FG3qnteSkkVIQuAvBqpPfQtxrXCZOlbQZm7q69QIQ64JvLJfRwHN1EywMBVwbJgrV8gBdE3RITI76coSOK13OBTlGtB0kGKLDrF2JW+5mB+WnFR7GlXUj+V0R9WStBomVipJEwr6Q3fU0deKZ5lLw0+qJ0T6APInwN5TIN/AbFCHd51aaf3zEP+tZacQ9fbZqy9XBAtL2pCAJQIDAQABo0cwRTBDBgNVHQEEPDA6gBDECazhZ8Ar+ULXb0YTs5MvoRQwEjEQMA4GA1UEAxMHVGVzdFNUU4IQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAA4IBAQAioMSOU9QFw+yhVxGUNK0p/ghVsHnYdeOE3vSRhmFPsetBt8S35sI4QwnQNiuiEYqp++FabiHgePOiqq5oeY6ekJik1qbs7fgwnaQXsxxSucHvc4BU81x24aKy6jeJzxmFxo3mh6y/OI1peCMSH48iUzmhnoSulp0+oAs3gMEFI0ONbgAA/XoAHaVEsrPj10i3gkztoGdpH0DYUe9rABOJxX/3mNF+dCVJG7t7BoSlNAWlSDErKciNNax1nBskFqNWNIKzUKBIb+GVKkIB2QpATMQB6Oe7inUdT9kkZ/Q7oPBATZk+3mFsIoWr8QRFSqvToOhun7EY2/VtuiV1d932</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" InResponseTo="_dfab47d5d46374cd4b71" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      var base64xml = new Buffer(xml).toString('base64');
      var container = { SAMLResponse: base64xml };

      var samlConfig = {
        entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        cert: 'MIIC7TCCAdmgAwIBAgIQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB1Rlc3RTVFMwHhcNMTQwNDE2MTIyMTEwWhcNMzkxMjMxMjM1OTU5WjASMRAwDgYDVQQDEwdUZXN0U1RTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhReamVYbeOWwrrAvHPvS9KKBwv4Tj7wOSGDXbNgfjhSvVyXsnpYRcuoJkvE8b9tCjFTbXCfbhnaVrpoXaWFtP1YvUIZvCJGdOOTXltMNDlNIaFmsIsomza8IyOHXe+3xHWVtxO8FG3qnteSkkVIQuAvBqpPfQtxrXCZOlbQZm7q69QIQ64JvLJfRwHN1EywMBVwbJgrV8gBdE3RITI76coSOK13OBTlGtB0kGKLDrF2JW+5mB+WnFR7GlXUj+V0R9WStBomVipJEwr6Q3fU0deKZ5lLw0+qJ0T6APInwN5TIN/AbFCHd51aaf3zEP+tZacQ9fbZqy9XBAtL2pCAJQIDAQABo0cwRTBDBgNVHQEEPDA6gBDECazhZ8Ar+ULXb0YTs5MvoRQwEjEQMA4GA1UEAxMHVGVzdFNUU4IQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAA4IBAQAioMSOU9QFw+yhVxGUNK0p/ghVsHnYdeOE3vSRhmFPsetBt8S35sI4QwnQNiuiEYqp++FabiHgePOiqq5oeY6ekJik1qbs7fgwnaQXsxxSucHvc4BU81x24aKy6jeJzxmFxo3mh6y/OI1peCMSH48iUzmhnoSulp0+oAs3gMEFI0ONbgAA/XoAHaVEsrPj10i3gkztoGdpH0DYUe9rABOJxX/3mNF+dCVJG7t7BoSlNAWlSDErKciNNax1nBskFqNWNIKzUKBIb+GVKkIB2QpATMQB6Oe7inUdT9kkZ/Q7oPBATZk+3mFsIoWr8QRFSqvToOhun7EY2/VtuiV1d932',
        validateInResponseTo: true,
        cacheProvider: newCacheProvider()
      };
      var samlObj = new SAML(samlConfig);

      fakeClock = sinon.useFakeTimers(Date.parse('2014-06-05T12:07:07.662Z'));

      // Mock the SAML request being passed through Passport-SAML
      samlObj.cacheProvider.save(requestId, new Date().toISOString(), function () {
      });

      samlObj.validatePostResponse(container, function (err, profile, logout) {
        should.not.exist(err);
        profile.nameID.should.startWith('UIS/jochen-work');
        samlObj.cacheProvider.get(requestId, function (err, value) {
          should.not.exist(value);
          done();
        });
      });
    });

    describe('InResponseTo server cache expiration tests /', function () {
      it('should expire a cached request id after the time', function (done) {
        this.timeout(6000);

        var requestId = '_dfab47d5d46374cd4b71';

        var samlConfig = {
          requestIdExpirationPeriodMs: 1000,
          validateInResponseTo: true,
          cacheProvider: newCacheProvider(1000)
        };
        var samlObj = new SAML(samlConfig);

        // Mock the SAML request being passed through Passport-SAML
        samlObj.cacheProvider.save(requestId, new Date().toISOString(), function () {
        });

        setTimeout(function () {
          samlObj.cacheProvider.get(requestId, function (err, value) {
            should.not.exist(value);
            done();
          });
        }, 2000);
      });

      it('should expire many cached request ids after the time', function (done) {
        this.timeout(6000);

        var expiredRequestId1 = '_dfab47d5d46374cd4b71';
        var expiredRequestId2 = '_dfab47d5d46374cd4b72';
        var requestId = '_dfab47d5d46374cd4b73';

        var samlConfig = {
          requestIdExpirationPeriodMs: 1000,
          validateInResponseTo: true,
          cacheProvider: newCacheProvider(1000)
        };
        var samlObj = new SAML(samlConfig);

        samlObj.cacheProvider.save(expiredRequestId1, new Date().toISOString(), function () {
        });
        samlObj.cacheProvider.save(expiredRequestId2, new Date().toISOString(), function () {
        });

        setTimeout(function () {
          // Add one more that shouldn't expire
          samlObj.cacheProvider.save(requestId, new Date().toISOString(), function () {
          });

          samlObj.cacheProvider.get(expiredRequestId1, function (err, value) {
            should.not.exist(value);
          });
          samlObj.cacheProvider.get(expiredRequestId2, function (err, value) {
            should.not.exist(value);
          });
          samlObj.cacheProvider.get(requestId, function (err, value) {
            should.exist(value);
          });

          // Let the expiration timer run again and we should have no more cached
          setTimeout(function () {
            samlObj.cacheProvider.get(requestId, function (err, value) {
              should.not.exist(value);

              if (cacheProvider == MemcacheCacheProvider) {
                memcacheClient.end();
                if (!process.env.TRAVIS) {
                  memcacheServer.end();
                }
              }
              done();
            });
          }, 2000)
        }, 2000);
      });
    });
  });
};

var runTestsWithAllCacheProviders = function() {
  for (var cacheProviderName in _cacheProvidersToTest) {
    _runTestsWithCacheProvider(cacheProviderName);
  }
};

module.exports = {
  runTestsWithAllCacheProviders: runTestsWithAllCacheProviders
};