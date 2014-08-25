var binding = require('bindings')('rawcipher');

exports.createCipher = function createCipher(alg, key, iv) {
  return new binding.Cipher(alg, key, iv);
};

exports.createDecipher = function createDecipher(alg, key, iv) {
  return new binding.Decipher(alg, key, iv);
};
