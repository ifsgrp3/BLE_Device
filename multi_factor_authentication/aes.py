
from Crypto.Cipher import AES
import binascii
import os

# A random key
#key = binascii.unhexlify('000102030405060708090A0B0C0D0E0F')
#text = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')
s1 = 1234567890123456
s2 = 1111222233334444
s3 = s1 ^ s2
text = (b's3')
key = (b"1111222233334444")
iv = (b"1111222233334444")
text = binascii.unhexlify('000302050704050a0a03020107000102')
text2 = (b"5w4lj9nek0dpz1o73assgsx4pg6pj73ztjr8wz5bkzk3qtcj5miexhqajka7re4c")

encryptor = AES.new(key, AES.MODE_ECB)
decryptor = AES.new(key, AES.MODE_ECB)

ciphertext = encryptor.encrypt(text)
print(ciphertext)
print(binascii.hexlify(ciphertext).upper())
plaintext = decryptor.decrypt(ciphertext)
print(plaintext)
print(binascii.hexlify(plaintext).upper())