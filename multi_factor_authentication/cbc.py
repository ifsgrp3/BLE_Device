from Crypto.Cipher import AES
import binascii
import os

# A random key
#key = binascii.unhexlify('000102030405060708090A0B0C0D0E0F')
#iv = binascii.unhexlify('000102030405060708090A0B0C0D0E0F')
#key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'

key = (b"1111222233334444")
iv = (b"1111222233334444")
text = (b"1234567890123456")

#print(key)

encryptor = AES.new(key, AES.MODE_CBC, iv)
decryptor = AES.new(key, AES.MODE_CBC, iv)

#text = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')

ciphertext = encryptor.encrypt(text)
print(ciphertext)
print(binascii.hexlify(ciphertext).upper())
plaintext = decryptor.decrypt(ciphertext)
print(plaintext)
print(binascii.hexlify(plaintext).upper())