from sys import argv

from Monitor import Monitor

def get_arguments(start: int) -> set[str]:
	'''
	Get all the arguments for a given arg in argv

	# Params:
	start - The index to start from in argv

	# Returns:
	A set of all arguments for a given arg. If start is -1 return None. And
	True if argv has a regular expression
	'''
	args: set[str] = set()
	start += 1

	for ii in range(start, len(argv)):
		if "-" in argv[ii]:
			return args
		
		args.add(argv[ii].lower())

	return args

if __name__ == "__main__":
	interface: str = None
	country: set[str] = set()
	src_ip: set[str] = set()
	dst_ip: set[str] = set()
	src_port: set[str] = set()
	dst_port: set[str] = set()
	transport_proto: set[str] = set()
	app_proto: set[str] = set()

	if "-i" in argv:
		interface: str = argv[argv.index("-i")+1]
	
	if "-c" in argv:
		country: set[str] = get_arguments(argv.index("-c"))
	
	if "-si" in argv:
		src_ip: set[str] = get_arguments(argv.index("-si"))

	if "-di" in argv:
		dst_ip: set[str] = get_arguments(argv.index("-di"))

	if "-sp" in argv:
		src_port: set[str] = get_arguments(argv.index("-sp"))

	if "-dp" in argv:
		dst_port: set[str] = get_arguments(argv.index("-dp"))

	if "-t" in argv:
		transport_proto: set[str] = get_arguments(argv.index("-t"))
	
	if "-a" in argv:
		app_proto: set[str] = get_arguments(argv.index("-a"))

	monitor = Monitor(interface, country, src_ip, dst_ip, src_port, dst_port, transport_proto, app_proto)
	monitor.capture_packets()
	monitor.parse_data()