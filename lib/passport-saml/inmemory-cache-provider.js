/**
 * Simple in memory cache provider.  To be used to store state of requests that needs
 * to be validated/checked when a response is received.
 *
 * This is the default implementation of a cache provider used by Passport-SAML.  For
 * multiple server instances/load balanced scenarios (I.e. the SAML request could have
 * been generated from a different server/process handling the SAML response) this
 * implementation will NOT be sufficient.
 *
 * The caller should provide their own implementation for a cache provider as defined
 * in the config options for Passport-SAML.
 * @param options
 * @constructor
 */
var CacheProvider = function (options) {

    var self = this;
    this.cacheKeys = {};

    if (!options) {
        options = {};
    }

    if(!options.keyExpirationPeriodMs){
        options.keyExpirationPeriodMs = 28800000;  // 8 hours
    }

    this.options = options;

    // Expire old cache keys
    setInterval(function(){

        var nowMs = new Date().getTime();
        var keys = Object.keys(self.cacheKeys);
        keys.forEach(function(key){
            if(nowMs >= new Date(self.cacheKeys[key].createdAt).getTime() + self.options.keyExpirationPeriodMs){
                self.remove(key);
            }
        });
    }, this.options.keyExpirationPeriodMs);

};


/**
 * Store an item in the cache, using the specified key and value.
 * Internally will keep track of the time the item was added to the cache
 * @param id
 * @param value
 */
CacheProvider.prototype.save = function(key, value){
    if(!this.cacheKeys[key])
    {
        this.cacheKeys[key] = {
            createdAt: new Date().getTime(),
            value: value
        };
    }
};


/**
 * Returns the value of the specified key in the cache
 * @param id
 * @returns {boolean}
 */
CacheProvider.prototype.get = function(key){
    if(this.cacheKeys[key]){
        return this.cacheKeys[key].value;
    }

    return null;
};


/**
 * Removes an item from the cache if it exists
 * @param key
 */
CacheProvider.prototype.remove = function(key){
    if(this.cacheKeys[key])
    {
        delete this.cacheKeys[key];
    }
};

exports.CacheProvider = CacheProvider;
