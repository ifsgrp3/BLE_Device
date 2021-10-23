import time
import adafruit_ble
from adafruit_ble.advertising.standard import SolicitServicesAdvertisement
from adafruit_ble.services.standard import CurrentTimeService

radio = adafruit_ble.BLERadio()
a = SolicitServicesAdvertisement()
a.complete_name = "ble_device_1"
a.solicited_services.append(CurrentTimeService)
radio.start_advertising(a)

while not radio.connected:
    pass

print("connected")

while radio.connected:
    for connection in radio.connections:
        if not connection.paired:
            connection.pair()
            print("paired")
        cts = connection[CurrentTimeService]
        print(cts.current_time)
    time.sleep(1)

print("disconnected")