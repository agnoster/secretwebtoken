var SecretWebToken = require('./')
var assert = require('assert')

var key = Buffer('d001fb4750d920e28cb62e17bbeb1562b6796128a261c9bbdf4a41ae380a0ca6', 'hex')
var tokenizer = SecretWebToken({
  key: key
})

var data = {
  message: "Hello World",
  exp: Math.floor(Date.now() / 1000) + 5 * 60
}

console.log("Original:", data)

token = tokenizer.encode(data)

console.log("Encoded:", token)

decoded = tokenizer.decode(token)

console.log("Decoded:", decoded)

assert.deepEqual(data, decoded)
