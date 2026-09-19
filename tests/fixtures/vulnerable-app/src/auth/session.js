const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Vulnerable: decode without verify.
function readToken(token) {
  return jwt.decode(token);
}

// Vulnerable: non-cryptographic PRNG for a session token.
function newSessionToken() {
  return Math.random().toString(36).slice(2);
}

// Vulnerable: deprecated cipher factory.
function encrypt(value) {
  return crypto.createCipher('aes-256-cbc', 'hardcoded-key');
}

module.exports = { readToken, newSessionToken, encrypt };
