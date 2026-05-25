// Multi-command client for the kernel-reader driver.
//
//   client list                              -- list all processes
//   client modules <pid>                     -- list modules in process
//   client base    <pid> <module-name>       -- get a module's base+size
//   client read    <pid> <hex-addr> <size>   -- hex-dump memory
//   client scan    <pid> <module-name> <sig> -- pattern scan inside module
//
// Pattern signature: hex bytes separated by spaces, with "?" wildcards.
//   e.g. "48 8B 05 ? ? ? ?"

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include "../shared/ioctl_shared.h"

namespace {

struct Driver {
    HANDLE h = INVALID_HANDLE_VALUE;
    Driver() {
        h = CreateFileW(DEVICE_PATH_USER, GENERIC_READ | GENERIC_WRITE,
                        0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    ~Driver() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    bool ok() const { return h != INVALID_HANDLE_VALUE; }

    bool call(void* in, DWORD inLen, void* out, DWORD outLen, DWORD* returned) {
        return DeviceIoControl(h, IOCTL_DISPATCH, in, inLen, out, outLen, returned, nullptr);
    }
};

int cmd_list(Driver& d) {
    REQ_PROCESS_LIST_IN req{};
    req.Header.Type = REQ_PROCESS_LIST;
    std::vector<uint8_t> out(KR_MAX_OUTPUT_BYTES);
    DWORD got = 0;
    if (!d.call(&req, sizeof(req), out.data(), (DWORD)out.size(), &got)) {
        wprintf(L"DeviceIoControl failed: %lu\n", GetLastError());
        return 1;
    }
    auto* hdr = reinterpret_cast<PROCESS_LIST_OUT*>(out.data());
    auto* arr = reinterpret_cast<PROCESS_ENTRY*>(out.data() + sizeof(PROCESS_LIST_OUT));
    wprintf(L"%u processes:\n", hdr->Count);
    for (uint32_t i = 0; i < hdr->Count; ++i) {
        wprintf(L"  %6llu  %s\n", arr[i].ProcessId, arr[i].Name);
    }
    return 0;
}

int cmd_modules(Driver& d, uint64_t pid) {
    REQ_MODULE_LIST_IN req{};
    req.Header.Type = REQ_MODULE_LIST;
    req.ProcessId   = pid;
    std::vector<uint8_t> out(KR_MAX_OUTPUT_BYTES);
    DWORD got = 0;
    if (!d.call(&req, sizeof(req), out.data(), (DWORD)out.size(), &got)) {
        wprintf(L"DeviceIoControl failed: %lu\n", GetLastError());
        return 1;
    }
    auto* hdr = reinterpret_cast<MODULE_LIST_OUT*>(out.data());
    auto* arr = reinterpret_cast<MODULE_ENTRY*>(out.data() + sizeof(MODULE_LIST_OUT));
    wprintf(L"%u modules in pid %llu:\n", hdr->Count, pid);
    for (uint32_t i = 0; i < hdr->Count; ++i) {
        wprintf(L"  %016llx  %8llu  %s\n", arr[i].BaseAddress, arr[i].Size, arr[i].Name);
    }
    return 0;
}

std::optional<MODULE_BY_NAME_OUT> resolve_base(Driver& d, uint64_t pid, const wchar_t* name) {
    REQ_MODULE_BY_NAME_IN req{};
    req.Header.Type = REQ_MODULE_BY_NAME;
    req.ProcessId   = pid;
    wcsncpy_s(req.Name, name, _TRUNCATE);
    MODULE_BY_NAME_OUT out{};
    DWORD got = 0;
    if (!d.call(&req, sizeof(req), &out, sizeof(out), &got) || got < sizeof(out)) {
        return std::nullopt;
    }
    return out;
}

int cmd_base(Driver& d, uint64_t pid, const wchar_t* name) {
    auto r = resolve_base(d, pid, name);
    if (!r) { wprintf(L"not found (err=%lu)\n", GetLastError()); return 1; }
    wprintf(L"%s: base=0x%016llx size=%llu\n", name, r->BaseAddress, r->Size);
    return 0;
}

bool read_bytes(Driver& d, uint64_t pid, uint64_t addr, std::vector<uint8_t>& dst) {
    REQ_READ_MEMORY_IN req{};
    req.Header.Type    = REQ_READ_MEMORY;
    req.ProcessId      = pid;
    req.TargetAddress  = addr;
    req.Size           = dst.size();

    // Driver uses sysbuf for both in and out; we need a buffer that holds
    // the request header AND the output bytes. Use a combined buffer.
    std::vector<uint8_t> io(std::max<size_t>(sizeof(req), dst.size()));
    std::memcpy(io.data(), &req, sizeof(req));
    DWORD got = 0;
    if (!d.call(io.data(), sizeof(req), io.data(), (DWORD)dst.size(), &got)) return false;
    dst.assign(io.begin(), io.begin() + got);
    return true;
}

int cmd_read(Driver& d, uint64_t pid, uint64_t addr, uint32_t size) {
    std::vector<uint8_t> buf(size);
    if (!read_bytes(d, pid, addr, buf)) {
        wprintf(L"read failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"read %zu bytes from pid %llu @ 0x%llx:\n", buf.size(), pid, addr);
    for (size_t i = 0; i < buf.size(); ++i) {
        wprintf(L"%02X ", buf[i]);
        if ((i + 1) % 16 == 0) wprintf(L"\n");
    }
    if (buf.size() % 16) wprintf(L"\n");
    return 0;
}

// Parse "48 8B 05 ? ? ?" into bytes + mask.
bool parse_sig(const std::string& s, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace((unsigned char)s[i])) i++;
        if (i >= s.size()) break;
        if (s[i] == '?') {
            bytes.push_back(0); mask.push_back(false);
            i++;
            if (i < s.size() && s[i] == '?') i++;
        } else {
            if (i + 1 >= s.size()) return false;
            char buf[3] = { s[i], s[i+1], 0 };
            unsigned v = 0;
            if (std::sscanf(buf, "%x", &v) != 1) return false;
            bytes.push_back((uint8_t)v); mask.push_back(true);
            i += 2;
        }
    }
    return !bytes.empty();
}

int cmd_scan(Driver& d, uint64_t pid, const wchar_t* module, const std::string& sig) {
    auto base = resolve_base(d, pid, module);
    if (!base) { wprintf(L"module not found\n"); return 1; }

    std::vector<uint8_t> sigBytes;
    std::vector<bool>    sigMask;
    if (!parse_sig(sig, sigBytes, sigMask)) {
        wprintf(L"bad signature\n"); return 1;
    }

    // Read module in 64KB chunks, scan with overlap = sig length - 1.
    const uint64_t chunkSize = 64 * 1024;
    const size_t overlap = sigBytes.size() - 1;
    std::vector<uint8_t> window;
    uint64_t off = 0;
    while (off < base->Size) {
        uint64_t want = (base->Size - off > chunkSize) ? chunkSize : (base->Size - off);
        std::vector<uint8_t> chunk(want);
        if (!read_bytes(d, pid, base->BaseAddress + off, chunk)) {
            off += chunkSize; continue; // skip unreadable pages
        }
        window.insert(window.end(), chunk.begin(), chunk.end());

        for (size_t i = 0; i + sigBytes.size() <= window.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < sigBytes.size(); ++j) {
                if (sigMask[j] && window[i + j] != sigBytes[j]) { match = false; break; }
            }
            if (match) {
                uint64_t hitVa = base->BaseAddress + (off + i + sigBytes.size() - window.size());
                wprintf(L"  hit: 0x%016llx\n", hitVa);
            }
        }
        // keep tail for next iter
        if (window.size() > overlap) window.erase(window.begin(), window.end() - overlap);
        off += chunk.size();
    }
    return 0;
}

void usage() {
    wprintf(L"usage:\n");
    wprintf(L"  client list\n");
    wprintf(L"  client modules <pid>\n");
    wprintf(L"  client base    <pid> <module-name>\n");
    wprintf(L"  client read    <pid> <hex-addr> <size>\n");
    wprintf(L"  client scan    <pid> <module-name> <\"hex sig with ?\">\n");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { usage(); return 2; }
    Driver d;
    if (!d.ok()) {
        wprintf(L"CreateFile failed: %lu (driver loaded? admin?)\n", GetLastError());
        return 1;
    }
    std::wstring cmd = argv[1];
    try {
        if (cmd == L"list" && argc == 2)
            return cmd_list(d);
        if (cmd == L"modules" && argc == 3)
            return cmd_modules(d, _wcstoui64(argv[2], nullptr, 10));
        if (cmd == L"base" && argc == 4)
            return cmd_base(d, _wcstoui64(argv[2], nullptr, 10), argv[3]);
        if (cmd == L"read" && argc == 5)
            return cmd_read(d,
                _wcstoui64(argv[2], nullptr, 10),
                _wcstoui64(argv[3], nullptr, 16),
                (uint32_t)_wtoi(argv[4]));
        if (cmd == L"scan" && argc == 5) {
            // convert wide sig to narrow for sscanf
            std::wstring ws = argv[4];
            std::string s(ws.begin(), ws.end());
            return cmd_scan(d,
                _wcstoui64(argv[2], nullptr, 10),
                argv[3], s);
        }
    } catch (const std::exception& e) {
        wprintf(L"error: %hs\n", e.what());
        return 1;
    }
    usage();
    return 2;
}
