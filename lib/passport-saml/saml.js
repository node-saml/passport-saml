const zlib = require('zlib')
const xml2js = require('xml2js')
const xmlCrypto = require('xml-crypto')
const crypto = require('crypto')
const xmldom = require('xmldom')
const url = require('url')
const querystring = require('querystring')
const xmlbuilder = require('xmlbuilder')
const xmlenc = require('xml-encryption')
const { xpath } = xmlCrypto
const { CacheProvider } = require('./inmemory-cache-provider.js')
const Q = require('q')

const processValidlySignedPostRequest = (self, doc, callback) => {
  var request = doc.LogoutRequest
  if (request) {
    var profile = {}
    if (request.$.ID) {
        profile.ID = request.$.ID
    } else {
      return callback(new Error('Missing SAML LogoutRequest ID'))
    }
    var issuer = request.Issuer
    if (issuer) {
      profile.issuer = issuer[0]
    } else {
      return callback(new Error('Missing SAML issuer'))
    }

    var nameID = request.NameID
    if (nameID) {
      profile.nameID = nameID[0]._ || nameID[0]

      if (nameID[0].$ && nameID[0].$.Format) {
        profile.nameIDFormat = nameID[0].$.Format
      }
    } else {
      return callback(new Error('Missing SAML NameID'))
    }
    var sessionIndex = request.SessionIndex
    if (sessionIndex) {
      profile.sessionIndex = sessionIndex[0]
    }

    callback(null, profile, true)
    return
  }

  return callback(new Error('Unknown SAML request message'))
}

class SAML {

  constructor(options) {
    this.options = this.initialize(options)
    this.cacheProvider = this.options.cacheProvider  
  }

  initialize(options = {}) {
    let configuration = Object.assign({
      path: '/saml/consume',
      host: 'localhost',
      issuer: 'onelogin_saml',
      identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      authnContext: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      acceptedClockSkewMs: 0, // default to no skew
      validateInResponseTo: false,
      requestIdExpirationPeriodMs: 28800000, // 8 hours
      logoutUrl: (options.entryPoint || ''), // Default to Entry Point
      signatureAlgorithm: 'sha1', // sha1, sha256, or sha512
    }, options)
    
    if (!configuration.cacheProvider) {
      configuration.cacheProvider = new CacheProvider({
        keyExpirationPeriodMs: configuration.requestIdExpirationPeriodMs
      })
    }

    return configuration
  }

  getProtocol(req) {
    return this.options.protocol || (req.protocol || 'http').concat('://')
  }

  getCallbackUrl(req) {
    // Post-auth destination
    return this.options.callbackUrl ? this.options.callbackUrl : `${this.getProtocol(req)}${req.headers ? req.headers.host : this.options.host}${this.options.path}`
  }

  generateUniqueID() {
    return crypto.randomBytes(10).toString('hex')
  }

  generateInstant() {
    return new Date().toISOString()
  }

  signRequest(samlMessage) {
    var signer
    var samlMessageToSign = {}

    switch (this.options.signatureAlgorithm) {
      
      case 'sha256':
        samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        signer = crypto.createSign('RSA-SHA256')
        break

      case 'sha512':
        samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
        signer = crypto.createSign('RSA-SHA512')
        break

      default:
        samlMessage.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
        signer = crypto.createSign('RSA-SHA1')
        break

    }

    if (samlMessage.SAMLRequest) {
      samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest
    }

    if (samlMessage.SAMLResponse) {
      samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse
    }

    if (samlMessage.RelayState) {
      samlMessageToSign.RelayState = samlMessage.RelayState
    }

    if (samlMessage.SigAlg) {
      samlMessageToSign.SigAlg = samlMessage.SigAlg
    }

    signer.update(querystring.stringify(samlMessageToSign))
    samlMessage.Signature = signer.sign(this.options.privateCert, 'base64')
  }

  generateAuthorizeRequest(req, isPassive, callback) {
    var self = this
    var id = `_${self.generateUniqueID()}`
    var instant = self.generateInstant()
    var forceAuthn = (self.options.forceAuthn || false)

    Q.fcall(() => self.options.validateInResponseTo ? Q.ninvoke(self.cacheProvider, 'save', id, instant) : Q())
    .then(function(){
      var request = {
        'samlp:AuthnRequest': {
          '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
          '@ID': id,
          '@Version': '2.0',
          '@IssueInstant': instant,
          '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          '@AssertionConsumerServiceURL': self.getCallbackUrl(req),
          '@Destination': self.options.entryPoint,
          'saml:Issuer' : {
            '@xmlns:saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': self.options.issuer
          }
        }
      }

      if (isPassive) {
        request['samlp:AuthnRequest']['@IsPassive'] = true
      }

      if (forceAuthn) {
        request['samlp:AuthnRequest']['@ForceAuthn'] = true
      }

      if (self.options.identifierFormat) {
        request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
          '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
          '@Format': self.options.identifierFormat,
          '@AllowCreate': 'true'
        }
      }

      if (!self.options.disableRequestedAuthnContext) {
        request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
          '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
          '@Comparison': 'exact',
          'saml:AuthnContextClassRef': {
            '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': self.options.authnContext
          }
        }
      }

      if (self.options.attributeConsumingServiceIndex) {
        request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] = self.options.attributeConsumingServiceIndex
      }

      if (self.options.providerName) {
        request['samlp:AuthnRequest']['@ProviderName'] = self.options.providerName
      }

      callback(null, xmlbuilder.create(request).end())
    })
    .fail(callback)
    .done()
  }

  generateLogoutRequest(req) {
    var id = `_${this.generateUniqueID()}`
    var instant = this.generateInstant()

    var request = {
      'samlp:LogoutRequest' : {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': this.options.logoutUrl,
        'saml:Issuer' : {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': this.options.issuer
        },
        'saml:NameID' : {
          '@Format': req.user.nameIDFormat,
          '#text': req.user.nameID
        }
      }
    }

    if (req.user.nameQualifier !== undefined) {
      request['samlp:LogoutRequest']['saml:NameID']['@NameQualifier'] = req.user.nameQualifier
    }

    if (req.user.spNameQualifier !== undefined) {
      request['samlp:LogoutRequest']['saml:NameID']['@SPNameQualifier'] = req.user.spNameQualifier
    }

    if (req.user.sessionIndex) {
      request['samlp:LogoutRequest']['saml2p:SessionIndex'] = {
        '@xmlns:saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '#text': req.user.sessionIndex
      }
    }

    return xmlbuilder.create(request).end()
  }

  generateLogoutResponse(req, logoutRequest) {
    var id = `_${this.generateUniqueID()}`
    var instant = this.generateInstant()

    var request = {
      'samlp:LogoutResponse' : {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': this.options.logoutUrl,
        '@InResponseTo': logoutRequest.ID,
        'saml:Issuer' : {
          '#text': this.options.issuer
        },
        'samlp:Status': {
          'samlp:StatusCode': {
            '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
          }
        }
      }
    }

    return xmlbuilder.create(request).end()
  }

  requestToUrl(request, response, operation, additionalParameters, callback) {
    var self = this

    if (self.options.skipRequestCompression) {
      requestToUrlHelper(null, new Buffer(request || response, 'utf8'))
    } else {
      zlib.deflateRaw(request || response, requestToUrlHelper)
    }

    function requestToUrlHelper(err, buffer) {
      if (err) {
        return callback(err)
      }

      var base64 = buffer.toString('base64')
      var target = url.parse(self.options.entryPoint, true)

      if (operation === 'logout') {
        if (self.options.logoutUrl) {
          target = url.parse(self.options.logoutUrl, true)
        }
      } else if (operation !== 'authorize') {
          return callback(new Error(`Unknown operation: ${operation}`))
      }

      var samlMessage = request ? { SAMLRequest: base64 } : { SAMLResponse: base64 }

      Object.keys(additionalParameters).forEach(k => {
        samlMessage[k] = additionalParameters[k]
      })

      if (self.options.privateCert) {
        try {
          // sets .SigAlg and .Signature
          self.signRequest(samlMessage)
        } catch (ex) {
          return callback(ex)
        }
      }
      Object.keys(samlMessage).forEach(k => {
        target.query[k] = samlMessage[k]
      })

      // Delete 'search' to for pulling query string from 'query'
      // https://nodejs.org/api/url.html#url_url_format_urlobj
      delete target.search

      callback(null, url.format(target))
    }
  }

  getAdditionalParams(req, operation) {
    var additionalParams = {}

    var RelayState = (req.query && req.query.RelayState || req.body && req.body.RelayState)
    if (RelayState) {
      additionalParams.RelayState = RelayState
    }

    var optionsAdditionalParams = this.options.additionalParams || {}
    Object.keys(optionsAdditionalParams).forEach(k => {
      additionalParams[k] = optionsAdditionalParams[k]
    })

    var optionsAdditionalParamsForThisOperation = {}

    if (operation == "authorize") {
      optionsAdditionalParamsForThisOperation = this.options.additionalAuthorizeParams || {}
    }

    if (operation == "logout") {
      optionsAdditionalParamsForThisOperation = this.options.additionalLogoutParams || {}
    }

    Object.keys(optionsAdditionalParamsForThisOperation).forEach(k => {
      additionalParams[k] = optionsAdditionalParamsForThisOperation[k]
    })

    return additionalParams
  }

  getAuthorizeUrl(req, callback) {
    var self = this

    this.generateAuthorizeRequest(req, this.options.passive, (err, request) => {
      if (err) {
        return callback(err)
      }
      var operation = 'authorize'
      self.requestToUrl(request, null, operation, self.getAdditionalParams(req, operation), callback)
    })
  }

  getAuthorizeForm(req, callback) {
    var self = this

    // The quoteattr() function is used in a context, where the result will not
    // be evaluated by javascript but must be interpreted by an XML or HTML
    // parser, and it must absolutely avoid breaking the syntax of an element
    // attribute.
    const quoteattr = (s, preserveCR) => {
      preserveCR = preserveCR ? '&#13' : '\n'

      return ('' + s)           // Forces the conversion to string.
        .replace(/&/g, '&amp')  // This MUST be the 1st replacement.
        .replace(/'/g, '&apos') // The 4 other predefined entities, required.
        .replace(/"/g, '&quot')
        .replace(/</g, '&lt')
        .replace(/>/g, '&gt')
         // Add other replacements here for HTML only
         // Or for XML, only if the named entities are defined in its DTD.
        .replace(/\r\n/g, preserveCR) // Must be before the next replacement.
        .replace(/[\r\n]/g, preserveCR)
    }

    const getAuthorizeFormHelper = (err, buffer) => {
      if (err) {
        return callback(err)
      }

      var operation = 'authorize'
      var additionalParameters = self.getAdditionalParams(req, operation)
      var samlMessage = {
        SAMLRequest: buffer.toString('base64')
      }

      Object.keys(additionalParameters).forEach(function(k) {
        samlMessage[k] = additionalParameters[k] || ''
      })

      var formInputs = Object.keys(samlMessage).map(k =>
        `<input type="hidden" name="${k}" value="${quoteattr(samlMessage[k])}" />`
      ).join('\r\n')

      callback(null, [
        '<!DOCTYPE html>',
        '<html>',
        '<head>',
        '<meta charset="utf-8">',
        '<meta http-equiv="x-ua-compatible" content="ie=edge">',
        '</head>',
        '<body onload="document.forms[0].submit()">',
        '<noscript>',
        '<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>',
        '</noscript>',
        `<form method="post" action="${encodeURI(self.options.entryPoint)}">`,
        formInputs,
        '<input type="submit" value="Submit" />',
        '</form>',
        '<script>document.forms[0].style.display="none"</script>', // Hide the form if JavaScript is enabled
        '</body>',
        '</html>'
      ].join('\r\n'))
    }

    self.generateAuthorizeRequest(req, self.options.passive, function(err, request) {
      if (err) {
        return callback(err)
      }

      if (self.options.skipRequestCompression) {
        getAuthorizeFormHelper(null, new Buffer(request, 'utf8'))
        return
      }
      
      zlib.deflateRaw(request, getAuthorizeFormHelper)
    })
  }

  getLogoutUrl(req, callback) {
    var request = this.generateLogoutRequest(req)
    var operation = 'logout'
    this.requestToUrl(request, null, operation, this.getAdditionalParams(req, operation), callback)
  }

  getLogoutResponseUrl(req, callback) {
    var response = this.generateLogoutResponse(req, req.samlLogoutRequest)
    var operation = 'logout'
    this.requestToUrl(null, response, operation, this.getAdditionalParams(req, operation), callback)
  }

  certToPEM(cert) {
    cert = cert.match(/.{1,64}/g).join('\n')

    if (cert.indexOf('-BEGIN CERTIFICATE-') === -1) {
      cert = `-----BEGIN CERTIFICATE-----\n${cert}`
    }

    if (cert.indexOf('-END CERTIFICATE-') === -1) {
      cert = `${cert}\n-----END CERTIFICATE-----\n`
    }

    return cert
  }

  certsToCheck() {
    return this.options.cert ? typeof(this.options.cert) === 'function' ?
      Q.nfcall(this.options.cert).then(certs => Q(Array.isArray(certs) ? certs : [certs])) :
      Q(Array.isArray(this.options.cert) ? this.options.cert : [this.options.cert]) :
      Q()
  }

  // This function checks that the |currentNode| in the |fullXml| document
  // contains exactly 1 valid signature of the |currentNode|.
  //
  // See https://github.com/bergie/passport-saml/issues/19 for references to
  // some of the attack vectors against SAML signature verification.
  validateSignature(fullXml, currentNode, certs) {
    var self = this
    var xpathSigQuery = ".//*[local-name(.)='Signature' and " +
                        "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
    var signatures = xpath(currentNode, xpathSigQuery)
    // This function is expecting to validate exactly one signature, so if we
    // find more or fewer than that, reject.
    if (signatures.length != 1) {
      return false
    }

    var signature = signatures[0]

    return certs.some(certToCheck =>
      self.validateSignatureForCert(signature, certToCheck, fullXml, currentNode)
    )
  }

  // This function checks that the |signature| is signed with a given |cert|.
  validateSignatureForCert(signature, cert, fullXml, currentNode) {
    var self = this
    var sig = new xmlCrypto.SignedXml()
    sig.keyInfoProvider = {
      getKeyInfo: key => "<X509Data></X509Data>",
      getKey: keyInfo => self.certToPEM(cert),
    }
    sig.loadSignature(signature)
    // We expect each signature to contain exactly one reference to the top
    // level of the xml we are validating, so if we see anything else, reject.
    if (sig.references.length != 1) {
      return false
    }

    var refUri = sig.references[0].uri
    var refId = (refUri[0] === '#') ? refUri.substring(1) : refUri

    // If we can't find the reference at the top level, reject
    var idAttribute = currentNode.getAttribute('ID') ? 'ID' : 'Id'
    if (currentNode.getAttribute(idAttribute) != refId) {
      return false
    }

    // If we find any extra referenced nodes, reject. (xml-crypto only verifies
    // one digest, so multiple candidate references is bad news)
    var totalReferencedNodes = xpath(currentNode.ownerDocument, `//*[@${idAttribute}='${refId}']`)
    
    return (totalReferencedNodes.length <= 1) && sig.checkSignature(fullXml)
  }

  validatePostResponse(container, callback) {
    var self = this

    let xml, doc, inResponseTo

    Q.fcall(function(){
      xml = new Buffer(container.SAMLResponse, 'base64').toString('utf8')
      doc = new xmldom.DOMParser({}).parseFromString(xml)

      if (!doc.hasOwnProperty('documentElement')) {
        throw new Error('SAMLResponse is not valid base64-encoded XML')
      }

      inResponseTo = xpath(doc, "/*[local-name()='Response']/@InResponseTo")

      if (inResponseTo) {
        inResponseTo = inResponseTo.length ? inResponseTo[0].nodeValue : null
      }

      if (self.options.validateInResponseTo) {
        if (inResponseTo) {
          return Q.ninvoke(self.cacheProvider, 'get', inResponseTo)
            .then(result => {
              if (!result) {
                throw new Error('InResponseTo is not valid')
              }
              return Q()
            })
        }
      } else {
        return Q()
      }
    })
    .then(self.certsToCheck.bind(self))
    .then(function(certs) {
      // Check if this document has a valid top-level signature
      var validSignature = false
      if (self.options.cert && self.validateSignature(xml, doc.documentElement, certs)) {
        validSignature = true
      }

      var assertions = xpath(doc, "/*[local-name()='Response']/*[local-name()='Assertion']")
      var encryptedAssertions = xpath(doc,
        "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']")

      if (assertions.length + encryptedAssertions.length > 1) {
        // There's no reason I know of that we want to handle multiple assertions, and it seems like a
        //   potential risk vector for signature scope issues, so treat this as an invalid signature
        throw new Error('Invalid signature')
      }

      if (assertions.length == 1) {
        if (self.options.cert &&
            !validSignature &&
            !self.validateSignature(xml, assertions[0], certs)) {
          throw new Error('Invalid signature')
        }
        return self.processValidlySignedAssertion(assertions[0].toString(), inResponseTo, callback)
      }

      if (encryptedAssertions.length == 1) {
        if (!self.options.decryptionPvk) {
          throw new Error('No decryption key for encrypted SAML response')
        }

        var encryptedAssertionXml = encryptedAssertions[0].toString()

        var xmlencOptions = { key: self.options.decryptionPvk }
        return Q.ninvoke(xmlenc, 'decrypt', encryptedAssertionXml, xmlencOptions)
          .then(decryptedXml => {
            var decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml)
            var decryptedAssertions = xpath(decryptedDoc, "/*[local-name()='Assertion']")
            if (decryptedAssertions.length != 1)
              throw new Error('Invalid EncryptedAssertion content')

            if (self.options.cert &&
                !validSignature &&
                !self.validateSignature(decryptedXml, decryptedAssertions[0], certs)) {
              throw new Error('Invalid signature')
            }

            self.processValidlySignedAssertion(decryptedAssertions[0].toString(), inResponseTo, callback)
          })
      }

      // If there's no assertion, fall back on xml2js response parsing for the
      // status &
      //   LogoutResponse code.

      var parserConfig = {
        explicitRoot: true,
        explicitCharkey: true,
        tagNameProcessors: [xml2js.processors.stripPrefix]
      }

      var parser = new xml2js.Parser(parserConfig)
      return Q.ninvoke( parser, 'parseString', xml)
        .then(doc => {
          var response = doc.Response
          if (response) {
            var assertion = response.Assertion
            if (!assertion) {
              var status = response.Status
              if (status) {
                var statusCode = status[0].StatusCode
                if (statusCode && statusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder") {
                  var nestedStatusCode = statusCode[0].StatusCode
                  if (nestedStatusCode && nestedStatusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive") {
                    if (self.options.cert && !validSignature) {
                      throw new Error('Invalid signature')
                    }
                    return callback(null, null, false)
                  }
                }

                // Note that we're not requiring a valid signature before this logic -- since we are
                //   throwing an error in any case, and some providers don't sign error results,
                //   let's go ahead and give the potentially more helpful error.
                if (statusCode && statusCode[0].$.Value) {
                  var msgType = statusCode[0].$.Value.match(/[^:]*$/)[0]
                  if (msgType != 'Success') {
                    var msg = 'unspecified'
                    if (status[0].StatusMessage) {
                      msg = status[0].StatusMessage[0]._
                    } else if (statusCode[0].StatusCode) {
                      msg = statusCode[0].StatusCode[0].$.Value.match(/[^:]*$/)[0]
                    }
                    var error = new Error('SAML provider returned ' + msgType + ' error: ' + msg)
                    var builderOpts = {
                      rootName: 'Status',
                      headless: true
                    }
                    error.statusXml = new xml2js.Builder(builderOpts).buildObject(status[0])
                    throw error
                  }
                }
              }
              throw new Error('Missing SAML assertion')
            }
            return
          }

          if (self.options.cert && !validSignature) {
            throw new Error('Invalid signature')
          }

          if (!doc.LogoutResponse) {
            throw new Error('Unknown SAML response message')
          }

          return callback(null, null, true)
        })
    })
    .fail(callback)
    .done()
  }

  processValidlySignedAssertion(xml, inResponseTo, callback) {
    var self = this
    var msg
    var parserConfig = {
      explicitRoot: true,
      tagNameProcessors: [xml2js.processors.stripPrefix],
    }
    var nowMs = new Date().getTime()
    var profile = {}
    var assertion
    var parser = new xml2js.Parser(parserConfig)
    Q.ninvoke(parser, 'parseString', xml)
    .then(function(doc) {
      assertion = doc.Assertion

      var issuer = assertion.Issuer
      if (issuer) {
        profile.issuer = issuer[0]
      }

      var authnStatement = assertion.AuthnStatement
      if (authnStatement) {
        if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
          profile.sessionIndex = authnStatement[0].$.SessionIndex
        }
      }

      var subject = assertion.Subject
      var subjectConfirmation, confirmData
      if (subject) {
        var nameID = subject[0].NameID
        if (nameID) {
          profile.nameID = nameID[0]._ || nameID[0]

          if (nameID[0].$ && nameID[0].$.Format) {
            profile.nameIDFormat = nameID[0].$.Format
            profile.nameQualifier = nameID[0].$.NameQualifier
            profile.spNameQualifier = nameID[0].$.SPNameQualifier
          }
        }

        subjectConfirmation = subject[0].SubjectConfirmation ?
                              subject[0].SubjectConfirmation[0] : null
        confirmData = subjectConfirmation && subjectConfirmation.SubjectConfirmationData ?
                      subjectConfirmation.SubjectConfirmationData[0] : null
        if (subject[0].SubjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
          msg = 'Unable to process multiple SubjectConfirmations in SAML assertion'
          throw new Error(msg)
        }

        if (subjectConfirmation) {
          if (confirmData && confirmData.$) {
            var subjectNotBefore = confirmData.$.NotBefore
            var subjectNotOnOrAfter = confirmData.$.NotOnOrAfter

            var subjErr = self.checkTimestampsValidityError(
                            nowMs, subjectNotBefore, subjectNotOnOrAfter)
            if (subjErr) {
              throw subjErr
            }
          }
        }
      }

      // Test to see that if we have a SubjectConfirmation InResponseTo that it matches
      // the 'InResponseTo' attribute set in the Response
      if (self.options.validateInResponseTo) {
        if (subjectConfirmation) {
          if (confirmData && confirmData.$) {
            var subjectInResponseTo = confirmData.$.InResponseTo
            if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
              return Q.ninvoke(self.cacheProvider, 'remove', inResponseTo)
                .then(() => { throw new Error('InResponseTo is not valid') })
            } else if (subjectInResponseTo) {
              var foundValidInResponseTo = false
              return Q.ninvoke(self.cacheProvider, 'get', subjectInResponseTo)
                .then(function(result){
                  if (result) {
                    var createdAt = new Date(result)
                    if (nowMs < createdAt.getTime() + self.options.requestIdExpirationPeriodMs) {
                      foundValidInResponseTo = true
                    }
                  }
                  return Q.ninvoke(self.cacheProvider, 'remove', inResponseTo )
                })
                .then(function(){
                  if (!foundValidInResponseTo) {
                    throw new Error('InResponseTo is not valid')
                  }
                  return Q()
                })
            }
          }
        } else {
          return Q.ninvoke(self.cacheProvider, 'remove', inResponseTo)
        }
      } else {
        return Q()
      }
    })
    .then(function() {
      var conditions = assertion.Conditions ? assertion.Conditions[0] : null
      if (assertion.Conditions && assertion.Conditions.length > 1) {
        msg = 'Unable to process multiple conditions in SAML assertion'
        throw new Error(msg)
      }
      if(conditions && conditions.$) {
        var conErr = self.checkTimestampsValidityError(
                      nowMs, conditions.$.NotBefore, conditions.$.NotOnOrAfter)
        if (conErr) {
          throw conErr
        }
      }

      var attributeStatement = assertion.AttributeStatement
      if (attributeStatement) {
        var attributes = [].concat.apply([], attributeStatement
          .filter(attr => Array.isArray(attr.Attribute))
          .map(attr => attr.Attribute))

        const attrValueMapper = value => (typeof value === 'string' ? value : value._)

        if (attributes) {
          attributes.forEach(attribute => {
           if (!attribute.hasOwnProperty('AttributeValue')) {
              // if attributes has no AttributeValue child, continue
              return
            }
            var value = attribute.AttributeValue
            profile[attribute.$.Name] = (value.length === 1) ? attrValueMapper(value[0]) : value.map(attrValueMapper)
          })
        }
      }

      if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
        // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
        profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3']
      }

      if (!profile.email && profile.mail) {
        profile.email = profile.mail
      }

      profile.getAssertionXml = () => xml

      callback(null, profile, false)
    })
    .fail(callback)
    .done()
  }

  checkTimestampsValidityError(nowMs, notBefore, notOnOrAfter) {
    if (this.options.acceptedClockSkewMs == -1) {
      return null
    }

    if (notBefore) {
      var notBeforeMs = Date.parse(notBefore)
      if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs) {
        return new Error('SAML assertion not yet valid')
      }
    }

    if (notOnOrAfter) {
      var notOnOrAfterMs = Date.parse(notOnOrAfter)
      if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs) {
        return new Error('SAML assertion expired')
      }
    }

    return null
  }

  validatePostRequest(container, callback) {
    var self = this
    var xml = new Buffer(container.SAMLRequest, 'base64').toString('utf8')
    var dom = new xmldom.DOMParser().parseFromString(xml)

    new xml2js.Parser({
      explicitRoot: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    }).parseString(xml, function(err, doc) {
      if (err) {
        return callback(err)
      }

      self.certsToCheck()
      .then(function(certs) {
        // Check if this document has a valid top-level signature
        if (self.options.cert && !self.validateSignature(xml, dom.documentElement, certs)) {
          return callback(new Error('Invalid signature'))
        }

        processValidlySignedPostRequest(self, doc, callback)
      })
      .fail(callback)
    })
  }

  generateServiceProviderMetadata(decryptionCert) {
    var metadata = {
      'EntityDescriptor' : {
        '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
        '@entityID': this.options.issuer,
        '@ID': this.options.issuer.replace(/\W/g, '_'),
        'SPSSODescriptor' : {
          '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        },
      }
    }

    if (this.options.decryptionPvk) {
      if (!decryptionCert) {
        throw new Error(
          "Missing decryptionCert while generating metadata for decrypting service provider")
      }

      decryptionCert = decryptionCert.replace( /-+BEGIN CERTIFICATE-+\r?\n?/, '' )
      decryptionCert = decryptionCert.replace( /-+END CERTIFICATE-+\r?\n?/, '' )
      decryptionCert = decryptionCert.replace( /\r\n/g, '\n' )

      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = {
        'ds:KeyInfo' : {
          'ds:X509Data' : {
            'ds:X509Certificate': {
              '#text': decryptionCert
            }
          }
        },
        'EncryptionMethod' : [
          // this should be the set that the xmlenc library supports
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' },
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' },
          { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' }
        ]
      }
    }

    if (this.options.logoutCallbackUrl) {
      metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
        '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@Location': this.options.logoutCallbackUrl
      }
    }

    metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = this.options.identifierFormat
    metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
      '@index': '1',
      '@isDefault': 'true',
      '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Location': this.getCallbackUrl({})
    }

    return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' })
  }
}

exports.SAML = SAML