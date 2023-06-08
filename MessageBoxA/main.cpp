#include <Windows.h>
#include <string>

int main() {
	printf("[+] MessageBoxA basic call");
	MessageBoxA(0, "test", "text", 0);
	return 0;
}