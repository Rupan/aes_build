#!/usr/bin/python3

import aes

# These CTR test vectors are from NIST special publication 800-38a

# CTR-AES128: Encryption

ctx = aes.build_encryption_context(
    bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
)
counter = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')

# Block #1

data = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
aes.ctr_encrypt(data, counter, ctx)
assert data == bytes.fromhex('874d6191b620e3261bef6864990db6ce')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff00')

# Block #2

data = bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51')
aes.ctr_encrypt(data, counter, ctx)
assert data == bytes.fromhex('9806f66b7970fdff8617187bb9fffdff')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff01')

# Block #3

data = bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef')
aes.ctr_encrypt(data, counter, ctx)
assert data == bytes.fromhex('5ae4df3edbd5d35e5b4f09020db03eab')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff02')

# Block #4

data = bytes.fromhex('f69f2445df4f9b17ad2b417be66c3710')
aes.ctr_encrypt(data, counter, ctx)
assert data == bytes.fromhex('1e031dda2fbe03d1792170a0f3009cee')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff03')

# CTR-AES128: Decryption

ctx = aes.build_encryption_context(
    bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
)
counter = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')

# Block #1

data = bytes.fromhex('874d6191b620e3261bef6864990db6ce')
aes.ctr_decrypt(data, counter, ctx)
assert data == bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff00')

# Block #2

data = bytes.fromhex('9806f66b7970fdff8617187bb9fffdff')
aes.ctr_decrypt(data, counter, ctx)
assert data == bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff01')

# Block #3

data = bytes.fromhex('5ae4df3edbd5d35e5b4f09020db03eab')
aes.ctr_decrypt(data, counter, ctx)
assert data == bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff02')

# Block #4

data = bytes.fromhex('1e031dda2fbe03d1792170a0f3009cee')
aes.ctr_decrypt(data, counter, ctx)
assert data == bytes.fromhex('f69f2445df4f9b17ad2b417be66c3710')
assert counter == bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdff03')
