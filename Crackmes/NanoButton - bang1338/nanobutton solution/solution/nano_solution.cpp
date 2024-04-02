#include <iostream>
#include <Windows.h>

// Verification info
wchar_t TARGET[] = L"NanoButton.exe";
uintptr_t verify_addr = 0x408008;

// Tagging info -- tag strlen needs to be <=20 chars to fit
uintptr_t splashtxt_addr = 0x40602F;
constexpr char tag[] = "Cracked by ret2null!";

int main()
{
	// Launch the target
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	std::wcout << L"Launching target: \"" << TARGET << "\"... ";

	if (!CreateProcessW(NULL, TARGET, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		std::wcout << L"Failed to launch target: " << TARGET << '\n';
		std::cout << "Error code: " << GetLastError() << std::endl;
		return -1;
	}

	std::cout << "Success!\n";
	std::cout << "Giving target a second to unpack...";

	// Give it a couple seconds to start up and unpack
	// You may need to adjust this on your system
	// If we wanted to be more precise about it, we could hook eg. DialogBoxParamA
	// which only occurs after unpacking is complete
	Sleep(2000);
		
	std::cout << "\nHot patching target... ";

	// Change the verification byte to a non-zero value
	char good = 1;

	if (!WriteProcessMemory(pi.hProcess, (LPVOID) verify_addr, &good, 1, NULL))
	{
		std::cout << "Failed to set verified byte\n";
		std::cout << "Error code: " << GetLastError() << std::endl;
		return -1;
	}

	// Tag it
	DWORD old_protect;

	if (!VirtualProtectEx(pi.hProcess, (LPVOID) splashtxt_addr, sizeof(tag), PAGE_READWRITE, &old_protect) ||
		!WriteProcessMemory(pi.hProcess, (LPVOID)splashtxt_addr, tag, sizeof(tag), NULL))
	{
		std::cout << L"Failed to tag exit splash message box\n";
		std::cout << "The verification bypass should still work\n";
		std::cout << "Error code: " << GetLastError() << std::endl;
		return -1;
	}

	std::cout << "Success!\n";

	// Clean up and exit. Target will remain running.
	DWORD ignored;
	VirtualProtectEx(pi.hProcess, (LPVOID)splashtxt_addr, sizeof(tag), old_protect, &ignored);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}