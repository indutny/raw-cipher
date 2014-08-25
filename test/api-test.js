var assert = require('assert');
var rawcipher = require('../');

describe('raw-cipher', function() {
  it('should encrypt/decrypt data', function() {
    var key = new Buffer(32);
    key.fill('K');
    var iv = new Buffer(16);
    iv.fill('I');

    var c = rawcipher.createCipher('aes-256-cbc', key, iv);
    var d = rawcipher.createDecipher('aes-256-cbc', key, iv);

    var sizes = [ 16, 32, 64, 128 ];

    var size;
    while (size = sizes.shift()) {
      var chunk = new Buffer(size);
      for (var i = 0; i < chunk.length; i++)
        chunk[i] = (7 + 11 * i) & 0xff;

      // Run few iterations
      for (var i = 0; i < 16; i++) {
        for (var j = 0; j < chunk.length; j++)
          chunk[j] = (7 + 11 * chunk[j]) & 0xff;

        var enc = new Buffer(chunk.length);
        c.write(enc, chunk);
        var dec = new Buffer(chunk.length);
        d.write(dec, enc);

        assert.equal(chunk.toString('hex'), dec.toString('hex'));
      }
    }
  });
});
