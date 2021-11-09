from time import sleep
import os
import binascii
from Crypto.Cipher import AES
from adafruit_ble import BLERadio
from adafruit_ble.services.gmsservice import GMS
from adafruit_ble.advertising import Advertisement
from adafruit_ble.advertising.standard import ProvideServicesAdvertisement

ble = BLERadio()
found = set()
device_name_prefix = "ble_device"
authentication_code = b"JmOANYLinV80i7fy"

# AES-CBC decryption
def aes_decryption(ciphertext, iv):
    key = (b"1111222233334444")
    ciphertext = binascii.unhexlify(ciphertext)
    iv = binascii.unhexlify(iv)
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(ciphertext)
    return plaintext.decode("utf-8")

# AES-ECB encryption
def aes_encryption(plaintext):
    key = (b"1111222233334444")
    encryptor = AES.new(key, AES.MODE_ECB)
    plaintext = plaintext.encode("utf-8")
    ciphertext = encryptor.encrypt(plaintext)
    return binascii.hexlify(ciphertext).upper()
    
# Start scanning and detecting dongles
# print("\nSearching for MFA devices...\n")
for advertisement in ble.start_scan(Advertisement, timeout=5):
    device_name = advertisement.complete_name
 
    if device_name and device_name not in found:
        if device_name.startswith(device_name_prefix):
            # Add dongle to found list 
            found.add(device_name)
            # print("MFA device found: " + device_name)
            # print("Connected to " + device_name)
            # print("Receiving transmission...")
            # Establish connection with dongle
            GMS_connection = ble.connect(advertisement)
            # Tranmission with dongle
            if GMS_connection and GMS_connection.connected:
                GMS_transmission = GMS_connection[GMS]
                # Send over authentication code to dongle
                GMS_transmission.write(authentication_code)
                # Receive serial number and iv from dongle
                try:
                    ciphertext = GMS_transmission.read(64).decode("utf-8")
                    ciphertext += GMS_transmission.read(64).decode("utf-8")
                    iv = GMS_transmission.read(32).decode("utf-8")
                    # print("Encrypted serial number: " + ciphertext)
                except:
                   print("Transmission failed")
                # Decrypt serial number with given iv and key
                try: 
                    ble_serial_num = aes_decryption(ciphertext, iv)
                    # print("Serial number: " + ble_serial_num + "\n")
                    print(ble_serial_num + "," + iv)
                except:
                    print("Error when decrypting serial number")
                GMS_connection.disconnect()
                
ble.stop_scan()            