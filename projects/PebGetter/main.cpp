#include <iostream>
#include <windows.h>

// Declare the TEB structure 
#ifdef _WIN64
typedef struct _TEB {
	NT_TIB NtTib;
} TEB, * PTEB;
#else
typedef struct _TEB {
	NT_TIB NtTib;
} TEB, * PTEB;
#endif

// Macro to get the TEB (works for both x86 and x64)
#ifdef _WIN64
#define NtCurrentTeb() ((TEB*)__readgsqword(0x30))
#else
#define NtCurrentTeb() ((TEB*)__readfsdword(0x18))
#endif

int main() {
	// Variable to store the current stack pointer
	void* stackPointer = nullptr;

	// Retrieve the current stack pointer
#ifdef _WIN64
	// For x64, use __readrsp intrinsic
	stackPointer = (void*)__readrsp();
#else
	// For x86, use inline assembly to get ESP
	__asm {
		mov stackPointer, esp
	}
#endif
	void* address = &stackPointer;

	// MEMORY_BASIC_INFORMATION structure to hold information about the memory region
	MEMORY_BASIC_INFORMATION mbi;

	// Call VirtualQuery to get information about the memory region containing the variable
	SIZE_T result = VirtualQuery(
		address,            // Address to query
		&mbi,               // Output structure
		sizeof(mbi)         // Size of the structure
	);

	if (result == 0) {
		std::cerr << "VirtualQuery failed with error: " << GetLastError() << std::endl;
		return 1;
	}

	// Retrieve the TEB base address
	TEB* teb = NtCurrentTeb();

	// Output the information retrieved
	std::cout << "Base address: " << mbi.BaseAddress << std::endl;
	std::cout << "Allocation base: " << mbi.AllocationBase << std::endl;
	std::cout << "Region size: " << mbi.RegionSize << " bytes" << std::endl;

	// Compare the BaseAddress + RegionSize with the StackBase address from the TEB
	std::cout << "TEB base address: " << teb << std::endl;
	uintptr_t BaseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
	uintptr_t EndAddress = BaseAddress + mbi.RegionSize;

	if (reinterpret_cast<void*>(EndAddress) == teb->NtTib.StackBase) {
		std::cout << "Correct!" << std::endl;
	}
	return 0;
}
