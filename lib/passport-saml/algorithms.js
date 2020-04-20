var crypto = require('crypto');

exports.getSigningAlgorithm = function getSigningAlgorithm (shortName) {
  switch(shortName) {
    case 'sha256':
      return 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case 'sha512':
      return 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    default:
      return 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  }
};

exports.getDigestAlgorithm = function getDigestAlgorithm (shortName) {
  switch(shortName) {
    case 'sha256':
      return 'http://www.w3.org/2001/04/xmlenc#sha256';
    case 'sha512':
      return 'http://www.w3.org/2001/04/xmlenc#sha512';
    default:
      return 'http://www.w3.org/2000/09/xmldsig#sha1';
  }
};

exports.getSigner = function getSigner (shortName) {
  switch(shortName) {
    case 'sha256':
      return crypto.createSign('RSA-SHA256');
    case 'sha512':
      return crypto.createSign('RSA-SHA512');
    default:
      return crypto.createSign('RSA-SHA1');
  }
};