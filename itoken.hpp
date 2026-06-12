#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

class IToken {
private:
	HANDLE token_ = NULL;
	DWORD source_pid_ = 0;
	HANDLE proc = NULL;

	static bool enableDebugPrivilege();
	bool findSystemProcess(const std::wstring& name);
public:
	IToken() = default;
		
	explicit IToken(const std::wstring& name);

	~IToken();

	IToken(const IToken&) = delete;
	IToken& operator=(const IToken&) = delete;

	IToken(IToken&& other) noexcept;
	IToken& operator=(IToken&& other) noexcept;

	bool spawnProcess(const std::wstring& path, const std::wstring& cmd = L"");
	bool steal();

};