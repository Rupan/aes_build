#!/usr/bin/python3
from ecb_common import ECB_ENCRYPT, ECB_DECRYPT, test_ecb_encrypt, test_ecb_decrypt

enc = [
    ECB_ENCRYPT(
        count="0",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        plaintext="014730f80ac625fe84f026c60bfd547d",
        ciphertext="5c9d844ed46f9885085e5d6a4f94c7d7",
    ),
    ECB_ENCRYPT(
        count="1",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        plaintext="0b24af36193ce4665f2825d7b4749c98",
        ciphertext="a9ff75bd7cf6613d3731c77c3b6d0c04",
    ),
    ECB_ENCRYPT(
        count="2",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        plaintext="761c1fe41a18acf20d241650611d90f1",
        ciphertext="623a52fcea5d443e48d9181ab32c7421",
    ),
    ECB_ENCRYPT(
        count="3",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        plaintext="8a560769d605868ad80d819bdba03771",
        ciphertext="38f2c7ae10612415d27ca190d27da8b4",
    ),
    ECB_ENCRYPT(
        count="4",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        plaintext="91fbef2d15a97816060bee1feaa49afe",
        ciphertext="1bc704f1bce135ceb810341b216d7abe",
    ),
]
dec = [
    ECB_DECRYPT(
        count="0",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        ciphertext="5c9d844ed46f9885085e5d6a4f94c7d7",
        plaintext="014730f80ac625fe84f026c60bfd547d",
    ),
    ECB_DECRYPT(
        count="1",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        ciphertext="a9ff75bd7cf6613d3731c77c3b6d0c04",
        plaintext="0b24af36193ce4665f2825d7b4749c98",
    ),
    ECB_DECRYPT(
        count="2",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        ciphertext="623a52fcea5d443e48d9181ab32c7421",
        plaintext="761c1fe41a18acf20d241650611d90f1",
    ),
    ECB_DECRYPT(
        count="3",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        ciphertext="38f2c7ae10612415d27ca190d27da8b4",
        plaintext="8a560769d605868ad80d819bdba03771",
    ),
    ECB_DECRYPT(
        count="4",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        ciphertext="1bc704f1bce135ceb810341b216d7abe",
        plaintext="91fbef2d15a97816060bee1feaa49afe",
    ),
]


if __name__ == '__main__':
    test_ecb_encrypt(enc)
    test_ecb_decrypt(dec)
