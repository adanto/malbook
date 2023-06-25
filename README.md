### Notebook

This is my lobby of malware analysis documentation sites and tips that I usually quickly check when in the need of finding information about a specific structure, library, technique, etc. Instead of having 200 firefox bookmarks, this repository has the objective of storing all my notes in the most simple and usefull way to just Ctrl+F the information that I need, and quickly find the notes I already have made in the subject. 

#### Tools 

- VBinDiff: Quickly check binary differences from a cmd. [link](https://github.com/madsen/vbindiff)
- Multi Algorithm Hashing creator: Creates a DB of hashes [link](/projects/AntiDissasembly/APIhasher)

#### Interesting links

- [https://hex-rays.com/blog/tag/idatips/](https://hex-rays.com/blog/tag/idatips/)
- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [IDA Pro Shortcuts](/static/IDA_Pro_Shortcuts.pdf)
- [Intel Manual](/static/325462-sdm-vol-1-2abcd-3abcd.pdf)


#### IDA PRO 

##### Signatures (SHIFT+F5): 

- msmfc64 (MFC64 WinMain detector)
- vc32rtf
- vc32seh (SEH for vc64 7-14)
- vc32ucrt
- vc64rtf
- vc64seh
- vc64ucrt

##### Libraries (SHIFT+F11): 

- ntapi
- ntapi64_win7
- ntddk64_win7 (it’s usually necessary while analyzing kernel drivers)
- mssdk64_win7 (usually inserted automatically). 

##### Interesting Structures

- IMAGE_DOS_HEADERS: Represents the DOS header format.
- IMAGE_NT_HEADERS: Represents the PE header format. [link](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)
- IMAGE_OPTIONAL_HEADER32: Represents the optional header format (part of NT_HEADER STRUCT). [link](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)
- IMAGE_DATA_DIRECTORY: Represents the data directory. [link](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)
- IMAGE_EXPORT_DIRECTORY: [link](http://pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY)
- PEB: Contains process information. [link](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- PEB_LDR_DATA: Contains information about the loaded modules for the process. [link](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
- LDR_DATA_TABLE: [link](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm)


##### Techniques

- [NOP Slide](https://unprotect.it/technique/nop-sled/): [Local Project](https://github.com/adanto/notebook/blob/main/projects/AntiDissasembly/NopSlide/NopSlide/Main.cpp)
- [ROP Chaining](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming)

##### Calling Conventions [wiki](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)

- \__cdecl: Default calling convention for x86 C compilers. Variables pushed on the stack and return on eax. 
- \__fastcall: Uses registers for the first four arguments (default in x64): 
- Microsoft x64 calling convention: The first four arguments are placed onto the registers RCX, RDX, R8, R9