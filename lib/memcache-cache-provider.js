/**
 * Memcache cache provider.  To be used to store state of requests that needs
 * to be validated/checked when a response is received.
 *
 * Note that this has only been tested with the `memcaching` node module.
 *
 * @param memcacheClient
 * @param options
 * @constructor
 */
var CacheProvider = function (memcacheClient, options) {
    _throwIfMemcacheClientIsMissingMethods(memcacheClient);
    this.memcacheClient = memcacheClient;

    if (!options) {
        options = {};
    }

    if(!options.prefix) {
        options.prefix = "saml";
    }

    if(!options.keyExpirationPeriodMs){
        options.keyExpirationPeriodMs = 28800000;  // 8 hours
    }

    // Memcache uses seconds, not millseconds, as its expiration time.
    options.keyExpirationPeriodS = Math.ceil(
            options.keyExpirationPeriodMs / 1000
    );

    this.options = options;
};

/**
 * Throws if the cache provider does not have the methods we require.
 *
 * Note that this is not a thorough check, since the methods could have
 * different arguments than we expect.
 */
var _throwIfMemcacheClientIsMissingMethods = function(memcacheClient){
    var has_expected_methods = ["set", "get", "remove"].every(function(method) {
      return memcacheClient[method] instanceof Function;
    });
    if (!has_expected_methods){
      throw new Error("Unsupported memcache client!");
    }
};

/**
 * Store an item in the cache, using the specified key and value. Set expiration
 * time as indicated in the options.
 *
 * @param id
 * @param value
 */
CacheProvider.prototype.save = function(key, value, callback){
    this.memcacheClient.set(
        this.options.prefix + key,
        value,
        this.options.keyExpirationPeriodS,
        /*flags=*/0,
        callback);
};


/**
 * Returns the value of the specified key in the cache
 * @param id
 * @returns {boolean}
 */
CacheProvider.prototype.get = function(key, callback){
    this.memcacheClient.get(this.options.prefix + key, function(err, result) {
      // If there's no error, then we want to return the value of the result.
      if (!err && result) {
        result = result[0];
      }
      callback(err, result);
    });
};


/**
 * Removes an item from the cache if it exists
 * @param key
 */
CacheProvider.prototype.remove = function(key, callback){
    this.memcacheClient.remove(this.options.prefix + key, callback);
};

exports.CacheProvider = CacheProvider;
