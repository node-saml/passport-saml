import util from 'util';
import * as saml from './saml';
import {CacheProvider as InMemoryCacheProvider} from './inmemory-cache-provider';
import SamlStrategy from './strategy';

function MultiSamlStrategy (options, verify) {
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

  SamlStrategy.call(this, options, verify);
  this._options = options;
}

util.inherits(MultiSamlStrategy, SamlStrategy);

MultiSamlStrategy.prototype.authenticate = function (req, options) {
  this._options.getSamlOptions(req, (err, samlOptions) => {
    if (err) {
      return this.error(err);
    }

    const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
    const strategy = Object.assign({}, this, {_saml: samlService});
    Object.setPrototypeOf(strategy, this);
    this.constructor.super_.prototype.authenticate.call(strategy, req, options);
  });
};

MultiSamlStrategy.prototype.logout = function (req, callback) {
  this._options.getSamlOptions(req, (err, samlOptions) => {
    if (err) {
      return callback(err);
    }

    const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
    const strategy = Object.assign({}, this, {_saml: samlService});
    Object.setPrototypeOf(strategy, this);
    this.constructor.super_.prototype.logout.call(strategy, req, callback);
  });
};

MultiSamlStrategy.prototype.generateServiceProviderMetadata = function( req, decryptionCert, signingCert, callback ) {
  if (typeof callback !== 'function') {
    throw new Error("Metadata can't be provided synchronously for MultiSamlStrategy.");
  }

  return this._options.getSamlOptions(req, (err, samlOptions) => {
    if (err) {
      return callback(err);
    }

    const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
    const strategy = Object.assign({}, this, {_saml: samlService});
    Object.setPrototypeOf(strategy, this);
    return callback(null, this.constructor.super_.prototype.generateServiceProviderMetadata.call(strategy, decryptionCert, signingCert));
  });
};

module.exports = MultiSamlStrategy;
