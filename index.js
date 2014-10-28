var util = require('util')
var Transform =require('./transform.js')

function optionsWithDefaults(options, defaults) {
  return util._extend(util._extend({}, defaults), options)
}

function SecretWebToken(options) {
  var key = options.key
  if (!Buffer.isBuffer(key)) {
    key = new Buffer(key)
  }

  options = optionsWithDefaults(options, SecretWebToken.default_options)

  var transforms = []

  if (options.serializer in Transform) {
    transforms.push(Transform[options.serializer]())
  }

  if (options.salt) {
    transforms.push(Transform.salt(options.salt))
  }

  if (options.cipher) {
    transforms.push(Transform.cipher(options.cipher, key))
  }

  if (options.hmac) {
    transforms.push(Transform.hmac(options.hmac, key))
  }

  if (options.encoding in Transform) {
    transforms.push(Transform[options.encoding]())
  } else {
    transforms.push(Transform.buffer(options.encoding))
  }

  return Transform.compose(transforms)
}

SecretWebToken.default_options = {
  salt: 2,
  hmac: 'sha256',
  cipher: 'aes256',
  encoding: 'base64url',
  serializer: 'json'
}

module.exports = SecretWebToken
