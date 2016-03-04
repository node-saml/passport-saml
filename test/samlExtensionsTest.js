'use strict';

var SAML = require('../lib/passport-saml/saml.js').SAML;
var should = require('should');
var url = require('url');
var xmldom = require('xmldom');

describe('SAML.js Extensions', function() {

    var saml, req;
    beforeEach(function() {
        saml = new SAML({
            entryPoint: 'https://exampleidp.com/path?key=value',

            extensions: [
                {
                    xmlns: {
                        name: 'extra1',
                        urn: 'www:urn1:com'
                    },
                    values: {
                        'ExtraSAML': 'Some value',
                        'ExtraSAML2': 'Some other value'
                    }
                },
                {
                    xmlns: {
                        name: 'extra2',
                        urn: 'http://www.urn2.complex.com'
                    },
                    cdata:true,
                    values: {
                        'ExtraSAML': '<xml>test</xml>',
                        'ExtraSAML2': 'http://google.com?key=value&asd=123#test'
                    }
                }
            ]

        });
        req = {
            protocol: 'https',
            headers: {
                host: 'examplesp.com'
            }
        }
    });

    it('makes xml with "Extensions"', function(done) {
        saml.generateAuthorizeRequest(req, true, function(err, xml) {

            should.not.exist(err);

            var doc = new xmldom.DOMParser().parseFromString(xml);
            var root = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest').item(0);

            var extensions = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Extensions');
            should.exist(extensions);

            extensions = extensions.item(0);
            should.exist(extensions);

            should.exist(extensions.childNodes);
            extensions.childNodes.length.should.be.equal(4);

            //extra1:ExtraSAML
            var item = extensions.childNodes.item(0)

            item.nodeName.should.be.equal('extra1:ExtraSAML');
            item.childNodes.length.should.be.equal(1);

            done();
        });
    });


});