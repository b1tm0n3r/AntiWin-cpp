#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <string>
#include <cstdlib>
#include <tchar.h>

#pragma comment(lib, "dbghelp.lib")

void listAllProcesses() {
	const DWORD procArraySize = 1024;
	DWORD procIdArray[procArraySize];
	DWORD lpcbNeeded;

	if (!EnumProcesses(procIdArray, procArraySize, &lpcbNeeded)) {
		printf("[!] Failed to read the processes. Leaving...\n");
		return;
	}

	printf("[+] Listing processes ids\n");
	for (DWORD i = 0; i < lpcbNeeded / 4; i++) {
		printf("%d\n", procIdArray[i]);
	}

	printf("[+] Printing processes...\n");

	DWORD procAccess = 0x1F0FFF;
	for (DWORD i = 0; i < lpcbNeeded / 4; i++) {
		DWORD procId = procIdArray[i];
		printf("[+] Processed process ID: %d\n", procId);

		printf("[+] Opening process handle\n");
		HANDLE procHandle = OpenProcess(procAccess, false, procId);
		if (procHandle == NULL) {
			printf("[!] Could not open handle to process with PID: %d\n", procId);
			continue;
		}

		char filenameBuffer[MAX_PATH];
		if (GetProcessImageFileNameA(procHandle, filenameBuffer, MAX_PATH)) {
			printf("[+] Found process filename: %s\n", filenameBuffer);
		}

		printf("[+] Closing process handle: %p\n", procHandle);
		if (!CloseHandle(procHandle)) {
			printf("[!] Could not close process handle: %p\n", procHandle);
		}
		else {
			printf("[+] Successfully closed process handle.\n");
		}
	}
}

LPCWSTR GetLPCWSTR(const char* charArray) {
	int requiredSize = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, NULL, 0);
	wchar_t* wideStr = new wchar_t[requiredSize];
	MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wideStr, requiredSize);
	return wideStr;
}

void dumpProcessMemoryToFile(DWORD pid, std::string outFileName) {
	printf("[+] PID to dump memory from: %d\n", pid);

	DWORD procAccess = 0x1F0FFF;
	printf("[+] Opening process handle\n");
	HANDLE procHandle = OpenProcess(procAccess, false, pid);
	if (procHandle == NULL) {
		printf("[!] Could not open handle to process with PID: %d\n", pid);
		return;
	}

	printf("[+] Obtained handle: %p for PID: %d\n", procHandle, pid);

	HANDLE hFile = CreateFileA(outFileName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL) {
		printf("[!] Could not create memory dump file! Aborting.\n");
		return;
	}

	printf("[+] Created file and obtained handle\n");
	printf("[+] Dumping process memory to file: %s\n", outFileName.c_str());
	if (MiniDumpWriteDump(procHandle, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
		printf("[+] Memory dumped successfully!\n");
	}
	else {
		printf("[!] Couldn't dump the memory!\n");
	}

	printf("[+] Closing handles");
	CloseHandle(procHandle);
	CloseHandle(hFile);
}

int main(int argc, char** argv) {
	printf("[i] Best to execute with elevated privileges!\n");
	printf("[i] Usage: appName.exe [<PID> <outFileName>]\n");

	if (argc == 1) {
		listAllProcesses();
	}
	else if (argc == 2 || argc == 3) {
		DWORD pid = atoi(argv[1]);
		if (argc == 2) {
			dumpProcessMemoryToFile(pid, "mem.dump");
		}
		else {
			dumpProcessMemoryToFile(pid, argv[2]);
		}
	}

	return 0;
}