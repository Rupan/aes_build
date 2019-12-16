#!/usr/bin/python3
from ecb_common import ECB_ENCRYPT, ECB_DECRYPT, test_ecb_encrypt, test_ecb_decrypt

enc = [
    ECB_ENCRYPT(
        count="0",
        key="00000000000000000000000000000000",
        plaintext="f34481ec3cc627bacd5dc3fb08f273e6",
        ciphertext="0336763e966d92595a567cc9ce537f5e",
    ),
    ECB_ENCRYPT(
        count="1",
        key="00000000000000000000000000000000",
        plaintext="9798c4640bad75c7c3227db910174e72",
        ciphertext="a9a1631bf4996954ebc093957b234589",
    ),
    ECB_ENCRYPT(
        count="2",
        key="00000000000000000000000000000000",
        plaintext="96ab5c2ff612d9dfaae8c31f30c42168",
        ciphertext="ff4f8391a6a40ca5b25d23bedd44a597",
    ),
    ECB_ENCRYPT(
        count="3",
        key="00000000000000000000000000000000",
        plaintext="6a118a874519e64e9963798a503f1d35",
        ciphertext="dc43be40be0e53712f7e2bf5ca707209",
    ),
    ECB_ENCRYPT(
        count="4",
        key="00000000000000000000000000000000",
        plaintext="cb9fceec81286ca3e989bd979b0cb284",
        ciphertext="92beedab1895a94faa69b632e5cc47ce",
    ),
    ECB_ENCRYPT(
        count="5",
        key="00000000000000000000000000000000",
        plaintext="b26aeb1874e47ca8358ff22378f09144",
        ciphertext="459264f4798f6a78bacb89c15ed3d601",
    ),
    ECB_ENCRYPT(
        count="6",
        key="00000000000000000000000000000000",
        plaintext="58c8e00b2631686d54eab84b91f0aca1",
        ciphertext="08a4e2efec8a8e3312ca7460b9040bbf",
    ),
]
dec = [
    ECB_DECRYPT(
        count="0",
        key="00000000000000000000000000000000",
        ciphertext="0336763e966d92595a567cc9ce537f5e",
        plaintext="f34481ec3cc627bacd5dc3fb08f273e6",
    ),
    ECB_DECRYPT(
        count="1",
        key="00000000000000000000000000000000",
        ciphertext="a9a1631bf4996954ebc093957b234589",
        plaintext="9798c4640bad75c7c3227db910174e72",
    ),
    ECB_DECRYPT(
        count="2",
        key="00000000000000000000000000000000",
        ciphertext="ff4f8391a6a40ca5b25d23bedd44a597",
        plaintext="96ab5c2ff612d9dfaae8c31f30c42168",
    ),
    ECB_DECRYPT(
        count="3",
        key="00000000000000000000000000000000",
        ciphertext="dc43be40be0e53712f7e2bf5ca707209",
        plaintext="6a118a874519e64e9963798a503f1d35",
    ),
    ECB_DECRYPT(
        count="4",
        key="00000000000000000000000000000000",
        ciphertext="92beedab1895a94faa69b632e5cc47ce",
        plaintext="cb9fceec81286ca3e989bd979b0cb284",
    ),
    ECB_DECRYPT(
        count="5",
        key="00000000000000000000000000000000",
        ciphertext="459264f4798f6a78bacb89c15ed3d601",
        plaintext="b26aeb1874e47ca8358ff22378f09144",
    ),
    ECB_DECRYPT(
        count="6",
        key="00000000000000000000000000000000",
        ciphertext="08a4e2efec8a8e3312ca7460b9040bbf",
        plaintext="58c8e00b2631686d54eab84b91f0aca1",
    ),
]


if __name__ == '__main__':
    test_ecb_encrypt(enc)
    test_ecb_decrypt(dec)