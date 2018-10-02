var util = require('util');
var saml = require('./lib/passport-saml/saml');
var SamlStrategy = require('./lib/passport-saml/strategy');

function MultiSamlStrategy (options, verify) {
  if (!options || typeof options.getSamlOptions != 'function') {
    throw new Error('Please provide a getSamlOptions function');
  }

  SamlStrategy.call(this, options, verify);
  this._getSamlOptions = options.getSamlOptions;
}

util.inherits(MultiSamlStrategy, SamlStrategy);

MultiSamlStrategy.prototype.authenticate = function (req, options) {
  var self = this;

  this._getSamlOptions(req, function (err, samlOptions) {
    if (err) {
      return self.error(err);
    }

    self._saml = new saml.SAML(samlOptions);
    self.constructor.super_.prototype.authenticate.call(self, req, options);
  });
};

MultiSamlStrategy.prototype.logout = function (req, options) {
  var self = this;

  this._getSamlOptions(req, function (err, samlOptions) {
    if (err) {
      return self.error(err);
    }

    self._saml = new saml.SAML(samlOptions);
    self.constructor.super_.prototype.logout.call(self, req, options);
  });
};

module.exports = MultiSamlStrategy;
