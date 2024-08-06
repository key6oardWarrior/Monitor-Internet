from sys import platform
from datetime import datetime
from os import getcwd, linesep
from os.path import join, exists
from re import findall

from pyshark import LiveCapture
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import LayerFieldsContainer
from pyshark.packet.layers.json_layer import JsonLayer
from whois import whois
from whois.parser import WhoisNet

# lists of all the possible layer field names
'''
dst_field_names = \
[
	'dst', 'dst_resolved', 'dst_oui', 'dst_oui_resolved', 'addr',
	'addr_resolved', 'addr_oui', 'addr_oui_resolved', 'dst_lg', 'lg', 'dst_ig',
	'ig', 'src', 'src_resolved', 'src_oui', 'src_oui_resolved', 'src_lg',
	'src_ig', 'type'
]

ip_info_field_names = \
[
	'version', 'ip_version', 'tclass', 'tclass_dscp', 'tclass_ecn', 'flow',
	'plen', 'nxt', 'hlim', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host'
]

data_layer_field_names = \
[
	'srcport', 'dstport', 'port', 'stream', 'completeness', 'completeness_rst',
	'completeness_fin', 'completeness_data', 'completeness_ack',
	'completeness_syn_ack', 'completeness_syn', 'completeness_str', 'len',
	'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags',
	'flags_res', 'flags_ae', 'flags_cwr', 'flags_ece', 'flags_urg',
	'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', 'flags_fin',
	'flags_str', 'window_size_value', 'window_size', 'window_size_scalefactor',
	'checksum', 'checksum_status', 'urgent_pointer', '', 'time_relative',
	'time_delta', 'analysis', 'analysis_bytes_in_flight',
	'analysis_push_bytes_sent', 'payload'
]

app_layer_field_names = \
[
	'record', 'record_content_type', 'record_version', 'record_length',
	'app_data', 'app_data_proto'
]
'''

class Monitor:
	__capture: LiveCapture
	__search_for: dict[str, set[str]] = {
		"country": set(),
		"src ip": set(),
		"dst ip": set(),
		"src port": set(),
		"dst port": set(),
		"transport protocol": set(),
		"app protocol": set()
	}
	__ip_has_reg_expression = False
	__file_location: str = None

	def __init__(self, interface: str=None, country: set[str]=set(),
			src_ip: set[str]=set(), dst_ip: set[str]=set(),
			src_port: set[str]=set(), dst_port: set[str]=set(),
			transport_proto: set[str]=set(),
			app_proto: set[str]=set(),
			file_location: str = None
		) -> None:
		'''
		# Params:
		interface (optional) - what internet interface is used for connection.
		Default is "wi-fi" for Windows and "wlan0" for linux\n
		country (optional) - which countries to search for\n
		src_ip (optional) - which source ip address to search for\n
		dst_ip (optional) - which destination ip address to search for\n
		src_port (optional) - which source port to search for\n
		dst_port (optional) - which destination port to search for\n
		transport_proto (optional) - which transport protocol to search for\n
		app_proto (optional) - which app protocol to search for\n
		file_location (optional) = What file location to save packet data to
		'''
		if interface == None:
			interface = "wi-fi" if platform == "win32" else "wlan0"

		self.__search_for["country"] = country
		self.__search_for["src ip"] = src_ip
		self.__search_for["dst ip"] = dst_ip
		self.__search_for["src port"] = src_port
		self.__search_for["dst port"] = dst_port
		self.__search_for["transport portocol"] = transport_proto
		self.__search_for["app protocol"] = app_proto

		for ip in self.__search_for["src ip"]:
			if ("*" in ip):
				self.__ip_has_reg_expression = True

		if self.__ip_has_reg_expression == False:
			for ip in self.__search_for["dst ip"]:
				if ("*" in ip):
					self.__ip_has_reg_expression = True

		self.__capture = LiveCapture(interface=interface, use_json=True)
		
		if file_location:
			self.__file_location = file_location
		else:
			self.__file_location = getcwd()

	def capture_packets(self) -> None:
		'''
		Start capturing packets
		'''
		self.__capture.sniff(timeout=1)

	def __has_field_names(self, layer: JsonLayer, field_name1: str, field_name2: str) -> bool:
		'''
		Does the layer have both field names

		# Params:
		layer - The JsonLayer that may contain field_name1 and or field_name2\n
		field_name1 - First name to search for\n
		field_name2 - Second name to search for

		# Returns:
		True only if field_name1 and field_name2 are both found else False
		'''
		return ((layer.has_field(field_name1)) and (layer.has_field(field_name2)))

	def __save_all_data(self, packet: Packet, dst: LayerFieldsContainer=None, whois_results: WhoisNet=None) -> None:
		'''
		Save all packet and whois data

		# Params:
		packet - The packet that will be saved to a file\n
		dst (optional) - Used to preform whois lookup\n
		whois_results (optional) - whois data about dst

		# Raises:
		ValueError - Both optional arguments cannot be None
		'''
		file_name: str = join(self.__file_location, str(datetime.now()).replace(":", "_") + ".txt")
		file = None

		if exists(file_name):
			file = open(file_name, "a")
		else:
			file = open(file_name, "w")

		for layer in packet.layers:
			layer: JsonLayer
			file.write(f"Layer {layer.layer_name}:{linesep}")

			for field_line in layer._get_all_field_lines():
				if ":" in field_line:
					field_name, field_line = field_line.split(":", 1)
					file.write(field_name + ":")
					file.write(field_line)

		if((dst) and (whois_results == None)):
			file.write(f"{linesep}Whois Look Up:{linesep}" + str(whois(dst)))
		elif((dst == None) and (whois_results)):
			file.write(f"{linesep}Whois Look Up:{linesep}" + str(whois_results))
		else:
			raise ValueError("Both optional arguments cannot be None")

		file.close()

	def __is_expression_found(self, addr: LayerFieldsContainer, ip_set: str) -> bool:
		'''
		Check if a user's ip address search expression can be found in the ip_set

		# Params:
		addr - IP fields container\n
		ip_set - The set of all ip address to be on the look out for

		# Returns:
		True if the expression is found else False

		# Raises:
		ValueError - If the addr passed was formated incorrectly\n
		ValueError - If the addr passed is not an IPv4 address
		'''
		if "192.168" not in addr[:8]:
			raise ValueError("The ip address field MUST at least start with 192.168")

		if addr.count(".") != 3:
			raise ValueError("That ip address field does not contain an IPv4 address")

		for ip_addr in self.__search_for[ip_set]:
			addresses: list[str] = ip_addr.split("*")
			search_string = "["

			ii = 0
			while ii < addresses.count(""):
				addresses.remove("")
				ii += 1

			for address in addresses:
				search_string += r"\b" + address + r"\b|"

			search_string = search_string[:-3]
			search_string += "]"
			print(findall(search_string, addr))
			if len(findall(search_string, addr)) > 0:
				return True
			
		return False

	def parse_data(self) -> None:
		'''
		Parse data that is collected from pyshark
		'''
		for packet in self.__capture:
			packet: Packet

			ip_layer: JsonLayer = packet.layers[1]

			if ip_layer.layer_name.lower() != "ip":
				continue

			transport_layer: JsonLayer = packet.layers[1]
			app_layer_protocol: JsonLayer = packet.layers[2] if len(packet.layers) <= 3 else packet.layers[3]

			if self.__has_field_names(ip_layer, "src", "dst"):
				src: LayerFieldsContainer = ip_layer.get_field("src")
				dst: LayerFieldsContainer = ip_layer.get_field("dst")
				is_local_addr = ("192.168" in src)

				if is_local_addr:
					if self.__ip_has_reg_expression:
						if self.__is_expression_found(src, "src ip"):
							self.__save_all_data(packet, dst)
							continue
					elif src in self.__search_for:
						self.__save_all_data(packet, dst)
						continue

					if dst in self.__search_for:
						self.__save_all_data(packet, dst)
						continue

					if transport_layer.layer_name in self.__search_for["transport protocol"]:
						self.__save_all_data(packet, dst)
						continue

					if app_layer_protocol.layer_name in self.__search_for["app protocol"]:
						self.__save_all_data(packet, dst)
						continue

					if self.__has_field_names(transport_layer, "srcport", "dstport"):
						if transport_layer.get_field("srcport") in self.__search_for["src port"]:
							self.__save_all_data(packet, dst)
							continue

						if transport_layer.get_field("dstport") in self.__search_for["dst port"]:
							self.__save_all_data(packet, dst)
							continue

					whois_results: WhoisNet = None
					if((ip_layer.has_field("version")) and (ip_layer.get_field("version") == "4")):
						whois_results: WhoisNet = whois(dst)
						if "country" in whois_results.keys():
							if whois_results.get("country") in self.__search_for:
								self.__save_all_data(packet, whois_results=whois_results)

	def stop_capture(self) -> None:
		self.__capture.close()
