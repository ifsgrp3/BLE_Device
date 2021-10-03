
from Crypto.Cipher import AES
import binascii
import os

# A random key
#key = binascii.unhexlify('000102030405060708090A0B0C0D0E0F')
#text = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')

key = (b"1111222233334444")
text = (b"1234567890123456")
text2 = (b"5w4lj9nek0dpz1o73assgsx4pg6pj73ztjr8wz5bkzk3qtcj5miexhqajka7re4c")

encryptor = AES.new(key, AES.MODE_ECB)
decryptor = AES.new(key, AES.MODE_ECB)

ciphertext = encryptor.encrypt(text)
print(ciphertext)
print(binascii.hexlify(ciphertext).upper())
plaintext = decryptor.decrypt(ciphertext)
print(plaintext)
print(binascii.hexlify(plaintext).upper())