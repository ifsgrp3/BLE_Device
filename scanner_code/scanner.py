from adafruit_ble import BLERadio

radio = BLERadio()
print("Scanning...")
found = set()
for entry in radio.start_scan(timeout=20, minimum_rssi=-80):
    addr = entry.address
    if addr not in found:
        print("======= New device ========")
        print("   ", end = '')
        print(entry.complete_name)
        print("      ", end = '')
        print(entry.address)
        print("      ", end = '')
        print(repr(entry))
    found.add(addr)

print("Scan Complete.")
