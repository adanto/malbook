#!/usr/bin/python3


def main():

	# Sorted strings compress nicely, to decrease load time - I/O is slower
	output = zlib.compress(output)

	fname = "apihashes.bin"
	with open(fname, "w+b") as f:
		f.write(output)

	print("Written the hashes file to " + fname + ", enjoy!")

if __name__ == "__main__":
	main()