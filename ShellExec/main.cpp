#include <Windows.h>
#include <string>
#include <vector>
#include "main.h"

// Example exec: .\ShellExec.exe "powershell.exe \"calc.exe\""

std::string getParams(std::vector<std::string>& splitStrings) {
	std::string params;
	for (int i = 1; i < splitStrings.size(); i++) {
		std::string paramsPart = splitStrings[i];
		if (splitStrings[i].front() == '\"') {
			paramsPart = paramsPart.substr(1, paramsPart.size() - 1);
		}
		if (splitStrings[i].back() == '\"') {
			paramsPart = paramsPart.substr(0, paramsPart.size() - 1);
		}
		params += paramsPart + " ";
	}
	return params.substr(0, params.size() - 1);
}

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("[i] Usage: appName.exe \"<otherAppName.exe> [<param1>, <param2>, ...]\"");
		return 1;
	}

	std::string inputString = argv[1];
	printf("Input string: %s\n", inputString.c_str());

	std::vector<std::string> splitStrings;
	std::string delimiter = " ";
	size_t pos = 0;
	std::string token;

	while ((pos = inputString.find(delimiter)) != std::string::npos) {
		token = inputString.substr(0, pos);
		splitStrings.push_back(token);
		inputString.erase(0, pos + delimiter.length());
	}
	splitStrings.push_back(inputString);


	if (splitStrings.size() > 1) {
		std::string execName = splitStrings[0];
		std::string params = getParams(splitStrings);
		printf("[+] Executing command: %s \"%s\"\n", execName.c_str(), params.c_str());
		ShellExecuteA(NULL, "open", execName.c_str(), params.c_str(), NULL, 1);
	}
	else {
		std::string execName = splitStrings[0];
		printf("[+] Executing command: %s\n", execName.c_str());
		ShellExecuteA(NULL, "open", execName.c_str(), NULL, NULL, 1);
	}
}