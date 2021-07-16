/* eslint-disable camelcase */
const sodium = require('sodium-native')
const assert = require('nanoassert')

const DHLEN = sodium.crypto_scalarmult_ed25519_BYTES
const PKLEN = sodium.crypto_scalarmult_ed25519_BYTES
const SKLEN = sodium.crypto_sign_SECRETKEYBYTES
const ALG = 'Ed25519'

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  ALG,
  generateKeyPair,
  dh
}

function generateKeyPair (privKey) {
  const keyPair = {}

  keyPair.secretKey = Buffer.alloc(SKLEN)
  keyPair.publicKey = Buffer.alloc(PKLEN)

  if (privKey) {
    sodium.crypto_sign_seed_keypair(keyPair.publicKey, keyPair.secretKey, privKey.subarray(0, 32))
  } else {
    sodium.crypto_sign_keypair(keyPair.publicKey, keyPair.secretKey)
  }

  return keyPair
}

function dh (pk, lsk) {
  assert(lsk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  const output = Buffer.alloc(DHLEN)

  // libsodium stores seed not actual scalar
  const sk = Buffer.alloc(64)
  sodium.crypto_hash_sha512(sk, lsk.subarray(0, 32))
  sk[0] &= 248
  sk[31] &= 127
  sk[31] |= 64

  sodium.crypto_scalarmult_ed25519(
    output,
    sk.subarray(0, 32),
    pk
  )

  return output
}
