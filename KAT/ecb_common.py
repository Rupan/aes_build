import aes
from collections import namedtuple


ECB_ENCRYPT = namedtuple("ECB_ENCRYPT", ["count", "key", "plaintext", "ciphertext"])
ECB_DECRYPT = namedtuple("ECB_DECRYPT", ["count", "key", "ciphertext", "plaintext"])


def test_ecb_encrypt(enc_tests):
    for test in enc_tests:
        ctx = aes.build_context(bytes.fromhex(test.key), "encryption")
        encrypted = aes.ecb_encrypt(bytes.fromhex(test.plaintext), ctx)
        if encrypted.hex() == test.ciphertext:
            print("Encryption test {} ... PASS".format(test.count))
        else:
            print("Encryption test {} ... FAIL".format(test.count))


def test_ecb_decrypt(dec_tests):
    for test in dec_tests:
        ctx = aes.build_context(bytes.fromhex(test.key), "decryption")
        decrypted = aes.ecb_decrypt(bytes.fromhex(test.ciphertext), ctx)
        if decrypted.hex() == test.plaintext:
            print("Decryption test {} ... PASS".format(test.count))
        else:
            print("Decryption test {} ... FAIL".format(test.count))
