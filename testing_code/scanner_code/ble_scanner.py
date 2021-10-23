from adafruit_ble import BLERadio
from adafruit_ble.advertising import Advertisement
from adafruit_ble.advertising.standard import ProvideServicesAdvertisement
from adafruit_ble.services.nordic import UARTService

ble = BLERadio()
uart = UARTService()
print("scanning")
found = set()
scan_responses = set()
# By providing Advertisement as well we include everything, not just specific advertisements.
# for entry in ble.start_scan(ProvideServicesAdvertisement, Advertisement, timeout=20):
for entry in ble.start_scan(timeout=20):
    addr = entry.address
    if entry.scan_response and addr not in scan_responses:
        scan_responses.add(addr)
    elif not entry.scan_response and addr not in found:
        found.add(addr)
    else:
        continue
    if (entry.complete_name.startswith("ble_device")):
        print(entry.complete_name)
        ble.connect(entry.name, timeout=5.0)
        print("scan done")
        break
    #print(entry)
    #print(addr, entry)
    #print("\t" + repr(entry))
    #print()

print("scan done")