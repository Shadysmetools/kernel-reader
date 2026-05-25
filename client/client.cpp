#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include "../shared/ioctl_shared.h"

int wmain(int argc, wchar_t** argv) {
    if (argc < 4) {
        wprintf(L"Usage: client.exe <pid> <hex-address> <size>\n");
        wprintf(L"Example: client.exe 1234 7FF712340000 64\n");
        return 1;
    }

    const DWORD    pid     = _wtoi(argv[1]);
    const uint64_t address = _wcstoui64(argv[2], nullptr, 16);
    const uint32_t size    = _wtoi(argv[3]);

    HANDLE hDriver = CreateFileW(
        DEVICE_PATH_USER,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hDriver == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFile failed: %lu (is the driver loaded?)\n", GetLastError());
        return 1;
    }

    READ_MEMORY_REQUEST req{};
    req.ProcessId     = pid;
    req.TargetAddress = address;
    req.Size          = size;

    std::vector<uint8_t> outBuf(size, 0);
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        hDriver,
        IOCTL_READ_PROCESS_MEMORY,
        &req, sizeof(req),
        outBuf.data(), static_cast<DWORD>(outBuf.size()),
        &bytesReturned,
        nullptr);

    if (!ok) {
        wprintf(L"DeviceIoControl failed: %lu\n", GetLastError());
        CloseHandle(hDriver);
        return 1;
    }

    wprintf(L"Read %lu bytes from PID %lu @ 0x%llx:\n", bytesReturned, pid, address);
    for (DWORD i = 0; i < bytesReturned; ++i) {
        wprintf(L"%02X ", outBuf[i]);
        if ((i + 1) % 16 == 0) wprintf(L"\n");
    }
    if (bytesReturned % 16) wprintf(L"\n");

    CloseHandle(hDriver);
    return 0;
}
