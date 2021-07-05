# Raccoon BLE Sniffer Config

# Output format
# pick one of the following logging formats by uncommenting the format line

# PKLG format minimics HCI data to/from a Bluetooth Controller. It can be opened with Wireshark and Apple's PacketLogger
# format  = 'pklg'

# PCAP format uses Bluetooth BLE Trace format defined by libbt/Ubertooth for use with CrackLE. It can be opened with Wireshark
# format = 'crackle'

# PCAP format uses Bluetooth BLE Trace format defined by Nordic. It can be opened with Wireshark.
format = 'pcap'


# Available Sniffer devices
# List of detected serial ports, please uncomment your Raccoon BLE Sniffer devices
sniffers = [
#   { 'port':'/dev/cu.Bluetooth-Incoming-Port', 'baud':1000000, 'rtscts':1 },  # n/a - n/a}
#   { 'port':'/dev/cu.SunghyunKimBeatsSolo3-S', 'baud':1000000, 'rtscts':1 },  # n/a - n/a}
#   { 'port':'/dev/cu.SunghyunKimBeatsSolo3-W', 'baud':1000000, 'rtscts':1 },  # n/a - n/a}
   { 'port':'/dev/ttyACM0', 'baud':1000000, 'rtscts':1 },  # raccoon nrf52840 dongle - USB VID:PID=1915:520F SER=000000000000 LOCATION=20-3.3}

]

