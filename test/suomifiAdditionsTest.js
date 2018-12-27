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
   *       disableValidateInResponseEnforcingForUnitTestingPurposes: boolean,
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
        disablePostResponseTopLevelSignatureValidationEnforcementForUnitTestPurposes: false
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

      it('must not consume unsigned message with unsigned UNencrypted login responses', function (done) {

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

      it('must not consume unsigned message with unsigned ENcrypted login responses', function (done) {

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

    });
  });
});