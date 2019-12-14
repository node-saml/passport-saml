/**
 * A collection of Q-flavored helper functions implemented with native promises
 */

/* global Promise */

/**
 * Calls a function and casts the returned value to a promise
 * @param {function():any} fn
 * @returns {Promise<any>}
 */
function fcall(fn) {
  try {
    var result = fn();
    return Promise.resolve(result);
  } catch (err) {
    return Promise.reject(err);
  }
}

/**
 * Calls a node-callback style function with provided arguments
 * and casts the return value to a promise
 * @returns {Promise<any>}
 */
function nfcall() {
  var args = Array.prototype.slice.call(arguments);
  var method = args[0];
  var methodArgs = args.slice(1);
  return new Promise(function (resolve, reject) {
    var callback = function (err, res) {
      if (err) {
        return reject(err);
      }
      resolve(res);
    };

    return method.apply(null, methodArgs.concat(callback));
  });
}

/**
 * Calls a node-callback style function bound to the provided object with provided arguments
 * and casts the return value to a promise
 * @returns {Promise<any>}
 */
function ninvoke() {
  var target = arguments[0];
  var methodName = arguments[1];
  var args = Array.prototype.slice.call(arguments, 2);
  var bound = target[methodName].bind(target);
  return nfcall.apply(null, [bound].concat(args));
}

exports.fcall = fcall;
exports.nfcall = nfcall;
exports.ninvoke = ninvoke;
