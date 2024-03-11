#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <thread>
#include "memory.h"
void BunnyHop(HMODULE hModule) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        uintptr_t localPlayer = VARS::memRead<uintptr_t>(VARS::baseAddress + 0x16D4F48);

        if (!localPlayer) {
            continue;
        }

        int32_t m_fFlags = VARS::memRead<int32_t>(localPlayer + 0x3C8);

        if (GetAsyncKeyState(VK_SPACE) && m_fFlags & (1 << 0)) {
            VARS::memWrite(VARS::baseAddress + 0x16CE390, 65537);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            VARS::memWrite(VARS::baseAddress + 0x16CE390, 256);
        }
    }
}

// entry point
int __stdcall DllMain(
    const HMODULE instance,
    const std::uintptr_t reason,
    const void* reserved
)
{
    // DLL_PROCESS_ATTACH
    if (reason == 1)
    {
        DisableThreadLibraryCalls(instance);

        // create hack thread
        const auto thread = CreateThread(
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(BunnyHop),
            instance,
            0,
            nullptr
        );

        if (thread)
            CloseHandle(thread);
    }

    return 1;
}
