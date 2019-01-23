'use strict';
const should                = require('should');
const assert                = require('assert');
const SAML                  = require('../lib/passport-saml/index.js').SAML;
const testData              = require('./suomifiGeneratedTestData.js');
const InMemoryCacheProvider = require('../lib/passport-saml/inmemory-cache-provider.js').CacheProvider;

describe( 'suomifi additions for passport-saml /', function() {

  const VALID_AUTH_REQUEST_ID = 'IN_RESPONSE_TO_ID';
  const VALID_NAME_ID = '__NAME_ID__';
  const VALID_SSN = '__nationalIdentificationNumber__';
  const VALID_AUDIENCE = 'https://localhost/sp1';

  const SSN_ATTRIBUTE_NAME = 'urn:oid:1.2.246.21';

  /**
   * Function is used to verify that data/values defined in suomifiGeneratedTestData exists when referenced
   * in these testcases. I.e. that values are not undefined (due e.g. some modifications / renaming fields in
   * script which generates testdata).
   *
   * @param {*} value
   * @return {*}
   * @throws AssertionError if {@param value} is not truthy
   */
  function assertTruthy(value) {
    assert.ok(
      value,
      'Value must not be falsy. ' +
      'Test case could return false positivie/negative if/when test parameter ' +
      'does not exist in test data anymore');
    return value
  }

  /**
   * Generate cache provider which shall contain value for {@param id}
   *
   * @param id value of authentication request id (i.e. from SP point of view in response to id)
   * @return {CacheProvider}
   */
  function generateCacheProviderWithInstant(id) {

    const cacheProvider = new InMemoryCacheProvider(
      {keyExpirationPeriodMs: (10 * 1000)}
    );

    cacheProvider.save(id, new Date().toISOString(), (err, result) => {
      if (err) {
        throw new Error(JSON.stringify(err))
      }
      should.exist(result);
    });

    return cacheProvider;
  }

  /**
   *
   * @return {
   *   {
   *     entryPoint: string,
   *     cert: *,
   *     decryptionPvk: *,
   *     audience: string,
   *     cacheProvider: CacheProvider,
   *     validateInResponseTo: boolean,
   *     suomifiAdditions: {
   *       disableEncryptedOnlyAssertionsPolicyEnforcementForUnitTestPurposes: boolean,
   *       disableValidateInResponseEnforcementForUnitTestingPurposes: boolean,
   *       disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes: boolean,
   *       disableAssertionSignatureVerificationEnforcementForUnitTestPurposes: boolean,
   *       disableAudienceCheckEnforcementForUnitTestPurposes: boolean,
   *     }
   *   }
   * } configuration which has valid IdP certificae, valid SP key, valid, entrypoint, valid audience and valid
   * inresponseto check configuration
   */
  function createBaselineSAMLConfiguration() {
    return {
      entryPoint: 'https://localhost/saml-sp/callback',
      cert: assertTruthy(testData.IDP_CERT),
      decryptionPvk: assertTruthy(testData.SP_KEY),
      audience: assertTruthy(VALID_AUDIENCE),
      cacheProvider: assertTruthy(
        generateCacheProviderWithInstant(
          assertTruthy(VALID_AUTH_REQUEST_ID)
        )
      ),
      validateInResponseTo: true,
      // NOTE: all additional checks are enabled (i.e. not disabled) by default because most of the test cases in this
      //       file tests specifically situations when passport-saml is configured with these additional
      //       tests are enabled (i.e there are only few test cases which must be tested with one or more
      //       of these checks disabled in order to "reach" relevant part of the code/system under test)
      suomifiAdditions: {
        disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes: false,
        disableValidateInResponseEnforcementForUnitTestingPurposes: false,
        disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes: false,
        disableAssertionSignatureVerificationEnforcementForUnitTestPurposes: false,
        disableAudienceCheckEnforcementForUnitTestPurposes: false
      }
    }
  }

  describe('saml.js / ', function () {

    describe("validate basic functionality /", function () {

      // "valid login response" means a SAML login response which has been signed (top level signature), has one
      // encrypted assertion and assertion is signed

      it('must consume valid login response', function (done) {
        const samlConfig = createBaselineSAMLConfiguration();
        const base64xml = new Buffer(
          assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.not.exist(err);
          should.exist(profile);
          profile.nameID.should.exactly(VALID_NAME_ID);
          profile[SSN_ATTRIBUTE_NAME].should.exactly(VALID_SSN);
          done();
        });
      });

      it('must not consume valid login response with incorrect audience', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();

        // configure audience to be anything but the value inside login response
        samlConfig.audience = VALID_AUDIENCE + 'incorrect_audience';

        const base64xml = new Buffer(
          assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('SAML assertion audience mismatch');
          done();
        });
      });

      it('must not consume valid login response with incorrect in_response_to value', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();

        // setup cacheprovider wich does not have valid auth request stored
        // i.e. remove existing in response value from cache
        samlConfig.cacheProvider.remove(VALID_AUTH_REQUEST_ID, (err, result) => {
          should.not.exist(err);
          should.exist(result);
          result.should.match(VALID_AUTH_REQUEST_ID);
        });

        const base64xml = new Buffer(
          assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('InResponseTo is not valid');
          done();
        });
      });

      it('must not consume login response with encrypted and plaintext assertions (i.e. >1 assertions)', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();

        // NOTE: message has encrypted and unencrypted assertions
        const base64xml = new Buffer(
          assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_ALONG_WITH_PLAIN_TEXT_ASSERTION_LOGIN_RESPONSE)
        ).toString('base64');

        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          // NOTE: unfortunately passport-saml's current error message for encrypted and plain text assertions
          // case in same login response is not very "intuitive"
          err.message.should.match('Invalid signature: multiple assertions');
          done();
        });
      });

      it('must not consume unsigned message with unsigned UNencrypted login response', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();

        const base64xml = new Buffer(
          assertTruthy(testData.UNSIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');

        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('Invalid top level signature');
          done();
        });
      });

      it('must not consume unsigned message with unsigned ENcrypted login response', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();

        const base64xml = new Buffer(
          assertTruthy(testData.UNSIGNED_MESSAGE_UNSIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');

        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('Invalid top level signature');
          done();
        });
      });

      it('must not consume valid login response if message is signed with unknown IdP cert', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();
        // switch IdP cert to something that is not used to sign message in order to test this case
        samlConfig.cert = assertTruthy(testData.INDVALID_IDP_CERT);

        const base64xml = new Buffer(
          assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('Invalid top level signature');
          done();
        });
      });

      // NOTE: this case tests baseline passport-saml functionality which is that if
      // 1) top level signature doesn't exist it (passport-saml) proceeds forwards
      // 2) if it encounters assertion (and if IdP certificate is configured) it checks whether
      //    assertions signature match
      //
      // i.e. this case test that if suomifi "enforce top level signature checking" is turned off
      // that passport-saml shall spot modified assertion (and that assertions signature is verified even though
      // top/message level signature was not verified)
      it('must not consume unsigned login response with signed assertion if assertion\'s signature doesn\'t match (i.e. if assertion content is modified)', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();
        // In order to test this particular case few suomifi additional checks must be disabled
        samlConfig.suomifiAdditions.disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes = true;
        samlConfig.suomifiAdditions.disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes = true;

        const base64xml = new Buffer(
          // NOTE: modify content of signed assertion
          assertTruthy(testData.UNSIGNED_MESSAGE_SIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
            .replace(VALID_SSN, 'modified_ssn' + VALID_SSN + 'modified_ssn')
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('Invalid assertion signature');
          done();
        });
      });

      // NOTE: this test requires that few suomifi additional checks are disabled
      it('must not consume unsigned login response with unsigned assertion when IdP cert is configured', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();
        // in order to test this particular case few suomifi additional checks must be disabled
        samlConfig.suomifiAdditions.disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes = true;
        samlConfig.suomifiAdditions.disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes = true;

        const base64xml = new Buffer(
          assertTruthy(testData.UNSIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          // NOTE: baseline passport-saml works so that if top level message signature is invalid / not available
          // it (baseline passport-saml) doesn't stop there. It proceeds forward and if assertion is spotted
          // it tries to verify assertions signature (if IdP cert is configured)...thus expected error message
          // from baseline passport-saml in this particular case is "Invalid assertion signature"
          err.message.should.match('Invalid assertion signature');
          done();
        });
      });

      it('must remove InResponseTo value if response validation fails', function (done) {

        const samlConfig = createBaselineSAMLConfiguration();
        samlConfig.cert = [];

        const base64xml = Buffer.from(
          assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
        ).toString('base64');
        const container = {SAMLResponse: base64xml};
        const samlObj = new SAML(samlConfig);
        samlObj.validatePostResponse(container, function (err, profile) {
          should.exist(err);
          should.not.exist(profile);
          err.message.should.match('Invalid top level signature');
          samlObj.validatePostResponse(container, function (err, profile) {
            err.message.should.match('InResponseTo is not valid');
            done();
          });
        });
      });
    });

    describe("validate suomifi additions checks /", function () {

      describe('validate PostResponseTopLevelSignatureValidationEnforcement /', function () {

        // NOTE: baseline passport-saml (0.32.1) would consider this as "soft error" (i.e. it would not raise
        // e.g. exception if message level signature cannot be validated)
        it('must not consume signed login response if message content is modified and top level signature doesn\'t match', function (done) {
          const samlConfig = createBaselineSAMLConfiguration();
          const base64xml = new Buffer(
            // NOTE: modify conent of signed message in order to to test that (in this case) top level signature
            // checking works
            assertTruthy(
              testData.SIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE
            ).replace(VALID_SSN, 'modified_ssn' + VALID_SSN + 'modified_ssn')
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            // NOTE: baseline passport-saml would not throw error with following message (it would proceed to check
            // whether assertion's signature would match ... and if not it would throw Error with "Invalid signature"
            // message.
            err.message.should.match('Invalid top level signature');
            done();
          });
        });

        it( 'must not consume valid signed login response if cert config parameter is undefined', function() {
          const samlConfig = createBaselineSAMLConfiguration();
          // set IdP cert to undefined
          samlConfig.cert = undefined;

          should(function() {
            new SAML( samlConfig );
          }).throw('Invalid property: cert must not be empty');
        });

        it( 'must not consume valid signed login response if cert config parameter is null', function() {
          const samlConfig = createBaselineSAMLConfiguration();
          // set IdP cert to null
          samlConfig.cert = null;

          should(function() {
            new SAML( samlConfig );
          }).throw('Invalid property: cert must not be empty');
        });

        it('must not consume valid signed login response if cert config parameter is empty array', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();
          // set IdP cert to empty array
          samlConfig.cert = [];

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            // NOTE: baseline passport-saml would NOT throw exception if cert is not configured
            err.message.should.match('Invalid top level signature');
            done();
          });
        });

        it('must not consume valid unsigned unencrypted login responses even if cert config parameter is empty array', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();
          // set IdP cert to empty array
          samlConfig.cert = [];

          const base64xml = new Buffer(
            assertTruthy(testData.UNSIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            // NOTE: baseline passport-saml would NOT throw exception if cert is not configured
            err.message.should.match('Invalid top level signature');
            done();
          });
        });

      });

      describe('validate ValidateInResponseEnforcement /', function () {

        it('must not consume login response if ValidateInResponse is not configured and used', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();
          // NOTE: set validateInResponseTo undefined to test this case
          samlConfig.validateInResponseTo = undefined;

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            err.message.should.match('validateInResponseTo feature is not configured on');
            done();
          });
        });

      });

      describe('validate AudienceCheckEnforcement /', function () {

        it('must not consume login response if audience check is not configured and used', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();
          // NOTE: set audience to undefined to test this case
          samlConfig.audience = undefined;

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            err.message.should.match('options.audience was not configured');
            done();
          });
        });

      });

      describe('validate EncryptedAssertionsOnlyPolicyEnforcement /', function () {

        it('must not consume signed login messages with unencrypted (signed) assertion', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();

          // NOTE: top level message signature validity enforcement is turned of in this particular test case because
          // current baseline passport-saml's top level/message level signature validation does not work
          // correctly when message has two signatures available/visible during top/message level signature validation.
          //
          // I.e. because this test case has message which
          //   1) has message level signature
          //   2) does not have encrypted assertion
          //   3) has signed assertion
          // and because baseline passport-saml (0.32.1)'s validateSignature function has xpathSigQuery which
          // shall return both signatures (even though those signatures do not cover same content), validateSignature
          // function implementation shall consider this situation as error and returns false. See:
          //
          // https://github.com/bergie/passport-saml/blob/3165135d75e96550e2cd9d4edd6e310cb8261972/lib/passport-saml/saml.js#L575
          // https://github.com/bergie/passport-saml/blob/3165135d75e96550e2cd9d4edd6e310cb8261972/lib/passport-saml/saml.js#L490
          // https://github.com/bergie/passport-saml/blob/3165135d75e96550e2cd9d4edd6e310cb8261972/lib/passport-saml/saml.js#L492-L498
          // ( 3165135d75e96550e2cd9d4edd6e310cb8261972 == 0.32.1 )
          //
          // As visible in this block:
          // https://github.com/bergie/passport-saml/blob/3165135d75e96550e2cd9d4edd6e310cb8261972/lib/passport-saml/saml.js#L575-L577
          // baseline passport-saml basically ignores situation where it was unable to verify message level signature.
          // I.e. it considers this situation as "soft error" (i.e. does not set validSignature flag to true) and
          // proceeds to process content of the message. If content happens to contain assertion it tries to verify
          // assertion's signature (unless message level signature was not considered valid), see
          // https://github.com/bergie/passport-saml/blob/3165135d75e96550e2cd9d4edd6e310cb8261972/lib/passport-saml/saml.js#L591-592
          // https://github.com/bergie/passport-saml/blob/3165135d75e96550e2cd9d4edd6e310cb8261972/lib/passport-saml/saml.js#L613-L614
          //
          // BUT because one of the suomifi's additional checks / enforcements is that message's (top level) signature
          // MUST be valid, passport-saml's default behaviour is/was modified so that if message's signature check failed
          // (i.e. validSignature flag is false after messages signature check code block) regardless of the reason reason
          // (i.e. e.g. if validateSignature did not return true) whole message is discarded.
          //
          // So..."message which is signed and has unencrypted signed assertion" would normally (i.e. without any
          // policy changes) pass through message level signature check (even though signature's validity was not
          // checked) and content of that message (in this case unencrypted signed assertion) would be handled.
          //
          // BUT since one of the suomifi additions is that assertions must always be encrypted and because this
          // particular test case is about testing this particular policy (i.e. encrypted assertions only)
          // disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes is set to true
          // so that this test case is able to verify that message which contain unencrypted assertion causes
          // expected error.
          samlConfig.suomifiAdditions.disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes = true;

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_SIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            err.message.should.match('Unencrypted assertion(s) are not allowed');
            done();
          });
        });

        it('must not consume signed login messages with unencrypted (unsigned) assertion', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            err.message.should.match('Unencrypted assertion(s) are not allowed');
            done();
          });
        });
      });

      describe('validate AssertionSignatureVerificationEnforcement /', function () {

        it('must not consume signed login messages with encrypted unsigned assertion', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_USIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            err.message.should.match('Invalid assertion signature');
            done();
          });
        });

        it('must not consume signed login messages with unencrypted unsigned assertion', function (done) {

          const samlConfig = createBaselineSAMLConfiguration();
          // NOTE: in order to test AssertionSignatureVerificationEnforcement with messages that have unencrypted
          // assertions one suomifi additional enforcement must be disabled
          samlConfig.suomifiAdditions.disableEncryptedAssertionsOnlyPolicyEnforcementForUnitTestPurposes = true;

          const base64xml = new Buffer(
            assertTruthy(testData.SIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE)
          ).toString('base64');
          const container = {SAMLResponse: base64xml};
          const samlObj = new SAML(samlConfig);
          samlObj.validatePostResponse(container, function (err, profile) {
            should.exist(err);
            should.not.exist(profile);
            err.message.should.match('Invalid assertion signature');
            done();
          });
        });
      });

    });
  });
});
