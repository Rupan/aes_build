#!/usr/bin/python3
from ecb_common import ECB_ENCRYPT, ECB_DECRYPT, test_ecb_encrypt, test_ecb_decrypt

enc = [
    ECB_ENCRYPT(
        count="0",
        key="000000000000000000000000000000000000000000000000",
        plaintext="1b077a6af4b7f98229de786d7516b639",
        ciphertext="275cfc0413d8ccb70513c3859b1d0f72",
    ),
    ECB_ENCRYPT(
        count="1",
        key="000000000000000000000000000000000000000000000000",
        plaintext="9c2d8842e5f48f57648205d39a239af1",
        ciphertext="c9b8135ff1b5adc413dfd053b21bd96d",
    ),
    ECB_ENCRYPT(
        count="2",
        key="000000000000000000000000000000000000000000000000",
        plaintext="bff52510095f518ecca60af4205444bb",
        ciphertext="4a3650c3371ce2eb35e389a171427440",
    ),
    ECB_ENCRYPT(
        count="3",
        key="000000000000000000000000000000000000000000000000",
        plaintext="51719783d3185a535bd75adc65071ce1",
        ciphertext="4f354592ff7c8847d2d0870ca9481b7c",
    ),
    ECB_ENCRYPT(
        count="4",
        key="000000000000000000000000000000000000000000000000",
        plaintext="26aa49dcfe7629a8901a69a9914e6dfd",
        ciphertext="d5e08bf9a182e857cf40b3a36ee248cc",
    ),
    ECB_ENCRYPT(
        count="5",
        key="000000000000000000000000000000000000000000000000",
        plaintext="941a4773058224e1ef66d10e0a6ee782",
        ciphertext="067cd9d3749207791841562507fa9626",
    ),
]
dec = [
    ECB_DECRYPT(
        count="0",
        key="000000000000000000000000000000000000000000000000",
        ciphertext="275cfc0413d8ccb70513c3859b1d0f72",
        plaintext="1b077a6af4b7f98229de786d7516b639",
    ),
    ECB_DECRYPT(
        count="1",
        key="000000000000000000000000000000000000000000000000",
        ciphertext="c9b8135ff1b5adc413dfd053b21bd96d",
        plaintext="9c2d8842e5f48f57648205d39a239af1",
    ),
    ECB_DECRYPT(
        count="2",
        key="000000000000000000000000000000000000000000000000",
        ciphertext="4a3650c3371ce2eb35e389a171427440",
        plaintext="bff52510095f518ecca60af4205444bb",
    ),
    ECB_DECRYPT(
        count="3",
        key="000000000000000000000000000000000000000000000000",
        ciphertext="4f354592ff7c8847d2d0870ca9481b7c",
        plaintext="51719783d3185a535bd75adc65071ce1",
    ),
    ECB_DECRYPT(
        count="4",
        key="000000000000000000000000000000000000000000000000",
        ciphertext="d5e08bf9a182e857cf40b3a36ee248cc",
        plaintext="26aa49dcfe7629a8901a69a9914e6dfd",
    ),
    ECB_DECRYPT(
        count="5",
        key="000000000000000000000000000000000000000000000000",
        ciphertext="067cd9d3749207791841562507fa9626",
        plaintext="941a4773058224e1ef66d10e0a6ee782",
    ),
]


if __name__ == '__main__':
    test_ecb_encrypt(enc)
    test_ecb_decrypt(dec)
