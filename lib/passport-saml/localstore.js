var LRU = require("lru-cache");


// Items that are put in this cache will expire after 5 minutes (the shib default.)
var cache = LRU({
    'maxAge': 5 * 60 * 1000
});

// Implement the three methods that are required for the anti-reply store.
// This store is only useful if you only have 1 app server.
exports.LocalStore = {
    'get': function(id, callback) {
        callback(null, cache.get(id));
    },
    'set': function(id, value, callback) {
        cache.set(id, value);
        callback(null);
    },
    'del' : function(id, callback) {
        cache.del(id);
        callback(null);
    }
};
