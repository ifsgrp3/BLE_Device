# Connect to a GMS echo service

from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import ProvideServicesAdvertisement
from adafruit_ble.services.gmsservice import GMS
from time import sleep

ble = BLERadio()

GMS_connection = None

while True:
    if not GMS_connection:
        print("Trying to connect...")
        for adv in ble.start_scan(ProvideServicesAdvertisement):
            if GMS in adv.services:
                GMS_connection = ble.connect(adv)
                if GMS_connection and GMS_connection.connected:
                    GMS_service = GMS_connection[GMS]
                    s = "Sent MSG"
                    GMS_service.write(s.encode("utf-8"))
                    print(GMS_service.readline().decode("utf-8"))
                GMS_connection.disconnect()
        ble.stop_scan()


