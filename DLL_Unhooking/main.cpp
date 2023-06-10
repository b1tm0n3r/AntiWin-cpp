#include <iostream>
#include <Windows.h>
#include <psapi.h>

int main() {
	printf("[+] DLL Unhooking");

	HANDLE hProcess = GetCurrentProcess();
	HMODULE hNtdllModule = GetModuleHandleA("ntdll.dll");

	if (hNtdllModule == NULL) {
		printf("[!] Cannot obtain ntdll.dll module handle\n");
		return 1;
	}
	printf("[+] Obtained handles to current process and ntdll.dll module\n");

	MODULEINFO modinfo;
	printf("[+] Allocated memory for moduleinfo, with size: %d\n", sizeof(modinfo));

	printf("[+] Getting ntdll module information\n");
	if (!GetModuleInformation(hProcess, hNtdllModule, &modinfo, sizeof(modinfo))) {
		printf("[!] Canont obtain ntdll.dll module information\n");
		return 1;
	}
	
	printf("[+] Opening handle to ntdll.dll file\n");
	HANDLE hNtdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hNtdllFile == NULL) {
		printf("[!] Cannot open ntdll.dll file from disk\n");
		return 1;
	}
	printf("[+] Obtained handle to ntdll.dll: %p\n", hNtdllFile);

	printf("[+] Creating ntdll.dll file mapping\n");
	HANDLE hNtdllFileMapping = CreateFileMapping(hNtdllFile, NULL, (PAGE_READONLY | SEC_IMAGE), 0, 0, NULL);
	if (hNtdllFileMapping == NULL) {
		printf("[!] Cannot create mapping of ntdll.dll\n");
		return 1;
	}

	LPVOID viewOfFilePtr = MapViewOfFile(hNtdllFileMapping, FILE_MAP_READ, 0, 0, 0);
	printf("[+] Ntdll mapping address: %p\n", viewOfFilePtr);
	
	LPVOID ntdllBase = modinfo.lpBaseOfDll;
	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			printf("[+] Found .text section at address: %p\n", hookedSectionHeader);
			DWORD oldProtection = 0;

			LPVOID srcAddress = (LPVOID)((DWORD_PTR)viewOfFilePtr + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
			LPVOID destAddress = (LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
			printf("[+] Source Address: %p\n", srcAddress);
			printf("[+] Destination Address: %p\n", destAddress);

			printf("[+] Changing protection of memory region\n");
			BOOL isProtected = VirtualProtect(destAddress, hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			if (!isProtected) {
				printf("[!] Couldn't change memory protection\n");
				return 1;
			}

			printf("[+] Old memory protection: %d\n", oldProtection);
			
			printf("[+] Copying .text section from the freshly mapped dll to (virtAddr) hooked ntdll.dll\n");
			memcpy(destAddress, srcAddress, hookedSectionHeader->Misc.VirtualSize);

			printf("[+] Setting back old memory protection\n");
			isProtected = VirtualProtect(destAddress, hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	printf("[+] Cleaning up\n");
	CloseHandle(hProcess);
	CloseHandle(hNtdllFile);
	CloseHandle(hNtdllFileMapping);
	FreeLibrary(hNtdllModule);

	printf("[+] Done\n");
	return 0;
}