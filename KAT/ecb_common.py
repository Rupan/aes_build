import aes
from collections import namedtuple


ECB_ENCRYPT = namedtuple("ECB_ENCRYPT", ["count", "key", "plaintext", "ciphertext"])
ECB_DECRYPT = namedtuple("ECB_DECRYPT", ["count", "key", "ciphertext", "plaintext"])


def test_ecb_encrypt(enc_tests):
    for test in enc_tests:
        ctx = aes.build_encryption_context(bytes.fromhex(test.key))
        buffer = bytes.fromhex(test.plaintext)
        aes.ecb_encrypt(buffer, ctx)
        if buffer.hex() == test.ciphertext:
            print("Encryption test {} ... PASS".format(test.count))
        else:
            print("Encryption test {} ... FAIL".format(test.count))


def test_ecb_decrypt(dec_tests):
    for test in dec_tests:
        ctx = aes.build_decryption_context(bytes.fromhex(test.key))
        buffer = bytes.fromhex(test.ciphertext)
        aes.ecb_decrypt(buffer, ctx)
        if buffer.hex() == test.plaintext:
            print("Decryption test {} ... PASS".format(test.count))
        else:
            print("Decryption test {} ... FAIL".format(test.count))
