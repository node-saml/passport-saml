const saml = require('./lib/passport-saml/saml');
const InMemoryCacheProvider = require('./lib/passport-saml/inmemory-cache-provider').CacheProvider;
const SamlStrategy = require('./lib/passport-saml/strategy');

class MultiSamlStrategy extends SamlStrategy {
  constructor(options, verify) {
    if (!options || typeof options.getSamlOptions != 'function') {
      throw new Error('Please provide a getSamlOptions function');
    }

    if(!options.requestIdExpirationPeriodMs){
      options.requestIdExpirationPeriodMs = 28800000;  // 8 hours
    }

    if(!options.cacheProvider){
        options.cacheProvider = new InMemoryCacheProvider(
            {keyExpirationPeriodMs: options.requestIdExpirationPeriodMs });
    }

    super(options, verify);
    this._options = options;
  }

  authenticate(req, options) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }

      this._saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      super.authenticate(req, options);
    });
  }

  logout(req, callback) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      this._saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      super.logout(req, callback);
    });
  }

  generateServiceProviderMetadata(req, decryptionCert, signingCert, callback) {
    if (typeof callback !== 'function') {
      throw new Error("Metadata can't be provided synchronously for MultiSamlStrategy.");
    }

    return this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      this._saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      return callback(null, super.generateServiceProviderMetadata(decryptionCert, signingCert ));
    });
  }
}

module.exports = MultiSamlStrategy;
