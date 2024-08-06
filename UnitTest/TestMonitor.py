from sys import path, platform
slash = "\\" if platform == "win32" else "/"
path.append((path[0])[:path[0].rindex(slash)])

from os import walk, getcwd
from threading import Thread
from time import sleep
from datetime import datetime

from Monitor import Monitor

slash = "\\" if platform == "win32" else "/"
path.append((path[0])[:path[0].rindex(slash)])

interface = "wi-fi" if platform == "win32" else "wlan0"

monitor = Monitor(interface, src_ip={"192.1*8.1.*"}, dst_ip={"255.255.255.255"}, country={"us"})
monitor.capture_packets()

parse_thread = Thread(target=monitor.parse_data, daemon=False)
parse_thread.start()

NUM_OF_FILES = len(next(walk(getcwd()))[2])
while len(next(walk(getcwd()))[2]) < NUM_OF_FILES:
	pass

try:
	monitor.stop_capture()
except:
	pass

sleep(10) # give time for get more files to be loaded
files: list[str] = next(walk(getcwd()))[2]

for file in files:
	if str(datetime.year) not in file:
		continue

	data = open(file, "r").read().lower()

	if ("192.168.1." not in data):
		if ("255.255.255.255" not in data):
			assert ("us" in data), "Expected either 192.168.1.*, 255.255.255.255, or us in data, but not found"

print("Monitor passed")