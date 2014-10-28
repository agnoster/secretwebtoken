var crypto = require('crypto')

var Transform = {
  msgpack: function() {
    var msgpack = require('msgpack')
    return {
      encode: function(data) {
        return msgpack.pack(data)
      },
      decode: function(buffer) {
        return msgpack.unpack(buffer)
      }
    }
  },
  json: function() {
    return {
      encode: function(data) {
        return new Buffer(JSON.stringify(data), 'utf8')
      },
      decode: function(buffer) {
        return JSON.parse(buffer.toString('utf8'))
      }
    }
  },
  base64url: function() {
    var base64url = require('base64url')
    return {
      encode: function(buffer) {
        return base64url(buffer)
      },
      decode: function(string) {
        return base64url.toBuffer(string)
      }
    }
  },
  base32: function() {
    var base32 = require('base32')
    return {
      encode: function(buffer) {
        return base32.encode(buffer)
      },
      decode: function(string) {
        return base32.decode(string)
      }
    }
  },
  buffer: function(encoding) {
    return {
      encode: function(buffer) {
        return buffer.toString(encoding)
      },
      decode: function(string) {
        return new Buffer(string, encoding)
      }
    }
  },
  hmac: function(algorithm, key) {
    var bytes = {
      sha256: 32,
      md5: 16,
      sha1: 20
    }[algorithm]
    if (!bytes) {
      throw "Do not know how many bytes of signature to reserve for " + algorithm
    }
    return {
      _sign: function(payload) {
        var hmac = crypto.createHmac(algorithm, key)
        hmac.update(payload)
        return hmac.digest()
      },
      encode: function(payload) {
        var signature = this._sign(payload)
        return Buffer.concat([ signature, payload ])
      },
      decode: function(buffer) {
        var signature = buffer.slice(0, bytes)
        var payload = buffer.slice(bytes)
        var expected_signature = this._sign(payload)
        if (signature.toString('binary') !== expected_signature.toString('binary')) {
          throw "Signature mismatch"
        }
        return payload
      }
    }
  },
  cipher: function(algorithm, key) {
    return {
      encode: function(buffer) {
        var cipher = crypto.createCipher(algorithm, key)
        cipher.end(buffer)
        return cipher.read()
      },

      decode: function(buffer) {
        var decipher = crypto.createDecipher(algorithm, key)
        decipher.end(buffer)
        return decipher.read()
      }
    }
  },
  salt: function(bytes) {
    return {
      encode: function(buffer) {
        return Buffer.concat([ crypto.randomBytes(bytes), buffer ])
      },
      decode: function(buffer) {
        return buffer.slice(bytes)
      }
    }
  },
  compose: function(transforms) {
    return {
      encode: function(data) {
        for (i = 0; i < transforms.length; i++)
          data = transforms[i].encode(data)
        return data
      },

      decode: function(data) {
        for (i = transforms.length - 1; i >= 0; i--)
          data = transforms[i].decode(data)
        return data
      }
    }
  }
}

module.exports = Transform
