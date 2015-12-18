var Crypto = require('crypto');
var Q = require('q');
var config = require('nconf');

config
  .argv()
  .env();

var TokenGenerator = {
  secret: null,
  init: function() {
    return Q.Promise(function(resolve, reject) {
      if(!config.get('shared')) {
        reject('Usage: node app.js --shared="Shared secret"');
        return;
      }
      TokenGenerator.secret = TokenGenerator.bufferizeSecret(config.get('shared'));
      resolve();
    });
  },
  generateKey: function() {
    return Q.Promise(function(resolve, reject) {

      var timeOffset = 0;
      var time = Math.floor(Date.now() / 1000) + (timeOffset || 0);

      var buffer = new Buffer(8);
      buffer.writeUInt32BE(0, 0); // This will stop working in 2038!
      buffer.writeUInt32BE(Math.floor(time / 30), 4);

      var hmac = Crypto.createHmac('sha1', TokenGenerator.secret);
      hmac = hmac.update(buffer).digest();

      var start = hmac[19] & 0x0F;
      hmac = hmac.slice(start, start + 4);

      var fullcode = hmac.readUInt32BE(0) & 0x7fffffff;
      var chars = '23456789BCDFGHJKMNPQRTVWXY';

      var code = '';
      for(var i = 0; i < 5; i++) {
        code += chars.charAt(fullcode % chars.length);
        fullcode /= chars.length;
      }
      console.log('Mobile token : ' + code);
      resolve();
    });
  },
  bufferizeSecret: function(secret) {
  	if(typeof secret === 'string') {
  		if(secret.match(/[0-9a-f]{40}/i)) {
  			return new Buffer(secret, 'hex');
  		} else {
  			return new Buffer(secret, 'base64');
  		}
  	}
  	return secret;
  }
};

TokenGenerator.init()
.then(TokenGenerator.generateKey)
.fail(function(reason) {
    console.log(reason);
    });