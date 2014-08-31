var assert = require('assert');
var prf = require('../');

describe('PRF', function() {
  it('should generate data with SHA1 PRF', function() {
    var out = new Buffer(54);

    prf.generate(out,
                 'sha1',
                 new Buffer('secret key'),
                 new Buffer('seed1'),
                 new Buffer('seed2'));

    assert.equal(
      out.toString('hex'),
      'd471667498bb6f11a606fd87a618c43499d867dc8295e041ba42001f28625af2' +
      '00b1e2c5329322650e2133e78e1679b35c6cd906b3aa');
  });

  it('should generate data with MD5 PRF', function() {
    var out = new Buffer(54);

    prf.generate(out,
                 'md5',
                 new Buffer('secret key'),
                 new Buffer('seed1'),
                 new Buffer('seed2'));

    assert.equal(
      out.toString('hex'),
      '9408236c96e99feba4ce5beedac3ab9a17a071f83999ba38f045a0c259edb1c4' +
      '5362bdee5037357bba12a7cedebe075921ec853f959f');
  });

  it('should generate data with MD5/SHA1 PRF', function() {
    var out = new Buffer(54);

    prf.generate(out,
                 'md5/sha1',
                 new Buffer('secret key'),
                 new Buffer('seed1'),
                 new Buffer('seed2'));

    assert.equal(
      out.toString('hex'),
      'b675ac71c6ee825319a8734fe16785eab7a8990cf4a4c3d7ad67cdfb1290c048' +
      'dd23cdb47bebfbc26cd0ad5dd3b00fae513ad069cdd4');
  });
});
