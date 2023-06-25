#!/usr/bin/python3
# Bassed on the Kaspersky Lab make_apihashesv2_table.py script 
#
# Execution: python hasher.py C:\Windows\System32\advapi32.dll C:\Windows\System32\bcrypt.dll C:\Windows\System32\bcryptprimitives.dll C:\Windows\System32\comdlg32.dll C:\Windows\System32\crypt32.dll C:\Windows\System32\d3d10.dll C:\Windows\System32\d3d11.dll C:\Windows\System32\d3d9.dll C:\Windows\System32\d3dcompiler_47.dll C:\Windows\System32\d3dx9_43.dll C:\Windows\System32\ddraw.dll C:\Windows\System32\dinput.dll C:\Windows\System32\dinput8.dll C:\Windows\System32\dnsapi.dll C:\Windows\System32\dpapi.dll C:\Windows\System32\dsound.dll C:\Windows\System32\dwrite.dll C:\Windows\System32\dxgi.dll C:\Windows\System32\dxva2.dll C:\Windows\System32\fwpuclnt.dll C:\Windows\System32\gdi32.dll C:\Windows\System32\gdiplus.dll C:\Windows\System32\imm32.dll C:\Windows\System32\kernel32.dll C:\Windows\System32\kernel32legacy.dll C:\Windows\System32\kernelbase.dll C:\Windows\System32\lpk.dll C:\Windows\System32\mf.dll C:\Windows\System32\mfc42.dll C:\Windows\System32\mfcore.dll C:\Windows\System32\mfplat.dll C:\Windows\System32\mfplay.dll C:\Windows\System32\mfreadwrite.dll C:\Windows\System32\mfsrcsnk.dll C:\Windows\System32\mpr.dll C:\Windows\System32\mscoree.dll C:\Windows\System32\msvcp140.dll C:\Windows\System32\msvcr110.dll C:\Windows\System32\msvcr120.dll C:\Windows\System32\msvcrt.dll C:\Windows\System32\msvcrt20.dll C:\Windows\System32\msvcrt40.dll C:\Windows\System32\mswsock.dll C:\Windows\System32\netapi32.dll C:\Windows\System32\ntdll.dll C:\Windows\System32\ntoskrnl.exe C:\Windows\System32\odbc32.dll C:\Windows\System32\odbccp32.dll C:\Windows\System32\ole32.dll C:\Windows\System32\oleacc.dll C:\Windows\System32\oleaut32.dll C:\Windows\System32\olepro32.dll C:\Windows\System32\opengl.dll C:\Windows\System32\opengl32.dll C:\Windows\System32\rasapi32.dll C:\Windows\System32\rasman.dll C:\Windows\System32\rpcrt4.dll C:\Windows\System32\secur32.dll C:\Windows\System32\setupapi.dll C:\Windows\System32\shell32.dll C:\Windows\System32\shell64.dll C:\Windows\System32\shlwapi.dll C:\Windows\System32\sspi.dll C:\Windows\System32\ucrtbase.dll C:\Windows\System32\urlmon.dll C:\Windows\System32\user32.dll C:\Windows\System32\userenv.dll C:\Windows\System32\version.dll C:\Windows\System32\wininet.dll C:\Windows\System32\winmm.dll C:\Windows\System32\winscard.dll C:\Windows\System32\winspool.drv C:\Windows\System32\winsrv.dll C:\Windows\System32\ws2_32.dll C:\Windows\System32\ws2help.dll C:\Windows\System32\wsock32.dll C:\Windows\System32\x3daudio1_7.dll C:\Windows\System32\xaudio2_9.dll C:\Windows\System32\xinput1_3.dll C:\Windows\WinSxS\comctl32.dl


import pefile, sys, struct, zlib
import os, os.path

from hashdb import algorithms


def hash(algorithm_name, data):
	if algorithm_name not in list(algorithms.modules.keys()):
		raise AlgorithmError("Algorithm not found")
	if type(data) == str:
		data = data.encode('utf-8')
	return algorithms.modules[algorithm_name].hash(data)


def getPermutations(name, libname): 

	# return [name]

	perms = [
		name,
		libname + name,
		# libname + '\x00\x00\x00' + name,
		# '\x00'.join([i for i in libname.upper()]) + '\x00\x00\x00' + name,
		'\x00'.join([i for i in libname.upper()]) + '\x00\x00\x00' + name + '\x00',
		# '\x00'.join([i for i in libname.lower()]) + '\x00\x00\x00' + name,
		# '\x00'.join([i for i in libname.lower()]) + '\x00\x00\x00' + name + '\x00',
		# '\x00'.join([i for i in libname.upper()]) + '\x00\x00\x00' + '\x00'.join([i for i in name.upper()]) ,
		# '\x00'.join([i for i in libname.upper()]) + '\x00\x00\x00' + '\x00'.join([i for i in name.upper()]) + '\x00',
		# '\x00'.join([i for i in libname.lower()]) + '\x00\x00\x00' + '\x00'.join([i for i in name.lower()]),
		# '\x00'.join([i for i in libname.lower()]) + '\x00\x00\x00' + '\x00'.join([i for i in name.lower()]) + '\x00',
		# libname + '\x00\x00\x00' + '\x00'.join([i for i in name.upper()]) ,
		# libname + '\x00\x00\x00' + '\x00'.join([i for i in name.upper()]) + '\x00',
		# libname + '\x00\x00\x00' + '\x00'.join([i for i in name.lower()]),
		# libname + '\x00\x00\x00' + '\x00'.join([i for i in name.lower()]) + '\x00'
	]

	return perms

def main(): 

	# HashDB hashing routines
	hashModulesNames = [bytes(i, 'utf-8') for i in list(algorithms.modules.keys())]
	
	print([i for i in hashModulesNames[1]])
	print([i for i in bytes("add_hiword_add_lowword", 'utf-8')])

	# hash:name dict
	hashtable = {}
	# unique name set for exported symbols
	allStrings = set()

	files_to_process = []

	if len(sys.argv) < 2:
		print("Make the apihashesv2 binary database, for the IDA plugin")
		print("Usage: [dir with DLLs] [filename.dll] ...")
		exit()

	for f in sys.argv[1:]:
		if os.path.isfile(f):
			files_to_process.append(f)
		elif os.path.isdir(f):
			for dirname, _, filenames in os.walk(f):
				for fname in filenames:
					files_to_process.append(os.path.join(dirname, fname))

	print(f"Processing {len(files_to_process)} files...")
	o = 0
	for f in files_to_process:
		o+=1
		try:
			pe = pefile.PE(f)
		except:
			# print(f"Unable to load {f} as a PE file, skipping...")
			continue

		try:
			libname = pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8')
			
			p=0
			totalP = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

			print(f"Processing {f} {100*o/len(files_to_process)}%")
			for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				if not p%100: print(f'{100*p/totalP}%', end='\r')
				p+=1
				try:
					name = exp.name.decode('utf-8')

					dataPermutations = getPermutations(name, libname)

					for algorithm_name in hashModulesNames:

						for permutation in dataPermutations:

							hashvalue = hash(algorithm_name.decode('utf-8'), permutation)
							hashtable[hashvalue] = libname+'.'+name
							allStrings.add(libname+'.'+name)
							# Debug point - you can print out the results of hashing
							# if hashvalue == 0x876F8B31: print(f'\n\n##############\n{algorithm_name} -> {hex(hashvalue)} : {bytes(permutation, "utf-8")}\n##############\n')

				except Exception as e:
					pass
					# print('ERROR', e)
			print()

		except Exception as e:
			pass
			# print('ERROR', e)

	# No names at all? Nothing to do here
	if len(hashtable) == 0:
		exit()

	# Now build a binary database
	# QWORD						 number of items
	# [2*QWORD]*number of items	 pairs of [hash,name offset], sorted by the hash value
	# rest of the file			  null-terminated symbol names
	stringLocations = {}

	headerSize = 8 +  16 * len(hashtable)

	stringbuf = b""
	print('Sorting allStrings')
	for string in sorted(allStrings):
		# print(string)
		pos = len(stringbuf) + headerSize
		stringLocations[string] = pos
		stringbuf += string.encode('utf-8') + b'\x00'
	stringbuf += b'\x00' # Empty string as an ending mark

	output = b""
	# Number of items 

	# Pairs of [hash, name offset]
	print('Sorting hashtable.keys')

	s = sorted(hashtable.keys())

	print('iterating hashtable.keys')
	tmpoutput = b""
	tmpoutput += struct.pack("<Q", len(hashtable))
	print(len(tmpoutput))

	i = 0
	for hashvalue in s:
		if not i%10000: print(f'{i}/{len(s)}')
		i+=1
		# We write a pair of a hash and a name position
		tmpoutput += struct.pack("<Q", hashvalue)
		tmpoutput += struct.pack("<Q", stringLocations[hashtable[hashvalue]])
		if len(tmpoutput) >= 10000:
			output += tmpoutput
			tmpoutput = b""

	output += tmpoutput

	# All the symbol names
	output += stringbuf # All the strings, sorted

	# Sorted strings compress nicely, to decrease load time - I/O is slower
	output = zlib.compress(output)

	fname = "apihashesv2.bin"
	with open(fname, "w+b") as f:
		f.write(output)

	print("Written the hashes file to " + fname + ", enjoy!")

if __name__ == "__main__":
	main()