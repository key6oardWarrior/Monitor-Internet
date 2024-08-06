from sys import argv, path, platform
slash = "\\" if platform == "win32" else "/"
path.append((path[0])[:path[0].rindex(slash)])
from Main import get_arguments

argv.append("-c")
argv.append("CN")
argv.append("RU")
argv.append("NK")

argv.append("-t")
argv.append("SSDP")
argv.append("TLSv1.2")

c_arguments = get_arguments(1)
t_arguments = get_arguments(argv.index("-t"))

assert len(c_arguments) == 3, f"Expected 3 arguments, but got {len(c_arguments)}"
for arg in c_arguments:
	assert arg in {"cn", "ru", "nk"}, f"Expected arg to be in set, but got \"{arg}\""

assert len(t_arguments) == 2, f"Expected 2 arguments, but got {len(c_arguments)}"
for arg in t_arguments:
	assert arg in {"ssdp", "tlsv1.2"}, f"Expected arg to be in set, but got \"{arg}\""

print("get_argument passed")