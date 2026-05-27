// Multi-command client for the kernel-reader driver.
//
//   client list                              -- list all processes
//   client modules <pid>                     -- list modules in process
//   client base    <pid> <module-name>       -- get a module's base+size
//   client regions <pid>                     -- list committed memory regions
//   client read    <pid> <hex-addr> <size>   -- hex-dump memory
//   client scan    <pid> <module-name> <sig> -- pattern scan inside module
//   client write   <pid> <hex-addr> <hex-bytes>  -- write raw bytes
//   client wu32    <pid> <hex-addr> <u32-value>  -- write 4-byte unsigned int
//   client wf32    <pid> <hex-addr> <float-val>  -- write 32-bit float
//   client find    <pid> <type> <value>          -- find addresses holding value
//   client freeze  <pid> <hex-addr> <type> <val> -- write value in a loop
//   client ptr     <pid> <hex-base> <off>...     -- resolve pointer chain
//
// Incremental (Cheat-Engine-style) workflow:
//   client find-first <pid> <type> <value> <session-file>     full scan → file
//   client find-next  <pid> <session-file> <value>            keep addrs holding value
//   client find-cmp   <pid> <session-file> <op>               op: changed|unchanged|inc|dec
//   client find-show  <session-file>                          print session contents
//
// Type: u32 | i32 | f32 | u64 | f64

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include <atomic>
#include <thread>
#include <chrono>
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

// ─── trainer-framework commands ─────────────────────────────────────────────

struct Region { uint64_t base, size; uint32_t protect, type; };

std::vector<Region> get_regions(Driver& d, uint64_t pid) {
    REQ_QUERY_REGIONS_IN req{};
    req.Header.Type = REQ_QUERY_REGIONS;
    req.ProcessId   = pid;
    std::vector<uint8_t> out(KR_MAX_OUTPUT_BYTES);
    DWORD got = 0;
    if (!d.call(&req, sizeof(req), out.data(), (DWORD)out.size(), &got)) return {};
    auto* hdr = reinterpret_cast<QUERY_REGIONS_OUT*>(out.data());
    auto* arr = reinterpret_cast<REGION_ENTRY*>(out.data() + sizeof(QUERY_REGIONS_OUT));
    std::vector<Region> result;
    result.reserve(hdr->Count);
    for (uint32_t i = 0; i < hdr->Count; ++i) {
        result.push_back({ arr[i].BaseAddress, arr[i].Size, arr[i].Protect, arr[i].Type });
    }
    return result;
}

int cmd_regions(Driver& d, uint64_t pid) {
    auto regs = get_regions(d, pid);
    wprintf(L"%zu regions in pid %llu:\n", regs.size(), pid);
    for (auto& r : regs) {
        wprintf(L"  %016llx  %12llu  prot=0x%08x  type=0x%08x\n",
                r.base, r.size, r.protect, r.type);
    }
    return 0;
}

bool write_bytes(Driver& d, uint64_t pid, uint64_t addr, const uint8_t* data, size_t n) {
    std::vector<uint8_t> io(sizeof(REQ_WRITE_MEMORY_IN) + n);
    auto* req = reinterpret_cast<REQ_WRITE_MEMORY_IN*>(io.data());
    req->Header.Type    = REQ_WRITE_MEMORY;
    req->ProcessId      = pid;
    req->TargetAddress  = addr;
    req->Size           = n;
    std::memcpy(io.data() + sizeof(REQ_WRITE_MEMORY_IN), data, n);
    DWORD got = 0;
    return d.call(io.data(), (DWORD)io.size(), nullptr, 0, &got) || GetLastError() == 0;
}

// "DE AD BE EF" → {0xDE, 0xAD, 0xBE, 0xEF}
std::vector<uint8_t> parse_hex_bytes(const std::wstring& s) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < s.size();) {
        while (i < s.size() && iswspace(s[i])) i++;
        if (i + 1 >= s.size()) break;
        wchar_t buf[3] = { s[i], s[i+1], 0 };
        unsigned v = 0;
        if (swscanf_s(buf, L"%x", &v) != 1) break;
        out.push_back((uint8_t)v);
        i += 2;
    }
    return out;
}

int cmd_write(Driver& d, uint64_t pid, uint64_t addr, const std::wstring& hex) {
    auto bytes = parse_hex_bytes(hex);
    if (bytes.empty()) { wprintf(L"no bytes parsed\n"); return 1; }
    if (!write_bytes(d, pid, addr, bytes.data(), bytes.size())) {
        wprintf(L"write failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"wrote %zu bytes\n", bytes.size());
    return 0;
}

int cmd_write_typed(Driver& d, uint64_t pid, uint64_t addr, const std::wstring& type, const std::wstring& val) {
    std::vector<uint8_t> buf;
    if (type == L"u32" || type == L"i32") {
        uint32_t v = (uint32_t)_wcstoui64(val.c_str(), nullptr, 0);
        buf.resize(4); std::memcpy(buf.data(), &v, 4);
    } else if (type == L"u64" || type == L"i64") {
        uint64_t v = _wcstoui64(val.c_str(), nullptr, 0);
        buf.resize(8); std::memcpy(buf.data(), &v, 8);
    } else if (type == L"f32") {
        float v = (float)_wtof(val.c_str());
        buf.resize(4); std::memcpy(buf.data(), &v, 4);
    } else if (type == L"f64") {
        double v = _wtof(val.c_str());
        buf.resize(8); std::memcpy(buf.data(), &v, 8);
    } else { wprintf(L"unknown type\n"); return 1; }

    if (!write_bytes(d, pid, addr, buf.data(), buf.size())) {
        wprintf(L"write failed: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"wrote %s = %s\n", type.c_str(), val.c_str());
    return 0;
}

// Value-of-type matcher
size_t type_size(const std::wstring& t) {
    if (t == L"u32" || t == L"i32" || t == L"f32") return 4;
    if (t == L"u64" || t == L"i64" || t == L"f64") return 8;
    return 0;
}
bool matches(const std::wstring& t, const uint8_t* p, const std::wstring& val) {
    if (t == L"u32") { uint32_t v = (uint32_t)_wcstoui64(val.c_str(), nullptr, 0); return std::memcmp(p, &v, 4) == 0; }
    if (t == L"i32") { int32_t  v = (int32_t)_wtoi(val.c_str());                   return std::memcmp(p, &v, 4) == 0; }
    if (t == L"u64") { uint64_t v = _wcstoui64(val.c_str(), nullptr, 0);           return std::memcmp(p, &v, 8) == 0; }
    if (t == L"i64") { int64_t  v = (int64_t)_wtoi64(val.c_str());                 return std::memcmp(p, &v, 8) == 0; }
    if (t == L"f32") { float    v = (float)_wtof(val.c_str()); float  q; std::memcpy(&q, p, 4); return q == v; }
    if (t == L"f64") { double   v = _wtof(val.c_str());        double q; std::memcpy(&q, p, 8); return q == v; }
    return false;
}

int cmd_find(Driver& d, uint64_t pid, const std::wstring& type, const std::wstring& val) {
    size_t ts = type_size(type);
    if (ts == 0) { wprintf(L"unknown type\n"); return 1; }
    auto regs = get_regions(d, pid);
    if (regs.empty()) { wprintf(L"no regions\n"); return 1; }

    size_t hitsTotal = 0;
    const uint64_t chunkSize = 256 * 1024;
    std::vector<uint8_t> buf(chunkSize);
    for (auto& r : regs) {
        // Only scan writable + private/heap regions (where dynamic game state lives).
        // PAGE_READWRITE = 0x04, PAGE_EXECUTE_READWRITE = 0x40
        bool writable = (r.protect & 0xCC) != 0;
        if (!writable) continue;
        for (uint64_t off = 0; off < r.size; off += chunkSize) {
            uint64_t want = std::min<uint64_t>(chunkSize, r.size - off);
            buf.resize((size_t)want);
            REQ_READ_MEMORY_IN req{};
            req.Header.Type = REQ_READ_MEMORY;
            req.ProcessId   = pid;
            req.TargetAddress = r.base + off;
            req.Size          = want;
            std::vector<uint8_t> io(std::max<size_t>(sizeof(req), (size_t)want));
            std::memcpy(io.data(), &req, sizeof(req));
            DWORD got = 0;
            if (!d.call(io.data(), sizeof(req), io.data(), (DWORD)want, &got)) continue;
            for (size_t i = 0; i + ts <= got; ++i) {
                if (matches(type, io.data() + i, val)) {
                    wprintf(L"  %016llx\n", r.base + off + i);
                    hitsTotal++;
                    if (hitsTotal >= 1000) { wprintf(L"  (capped at 1000)\n"); return 0; }
                }
            }
        }
    }
    wprintf(L"%zu matches\n", hitsTotal);
    return 0;
}

static std::atomic<bool> g_freezeStop{false};
BOOL WINAPI CtrlHandler(DWORD t) { if (t == CTRL_C_EVENT) { g_freezeStop = true; return TRUE; } return FALSE; }

int cmd_freeze(Driver& d, uint64_t pid, uint64_t addr, const std::wstring& type, const std::wstring& val) {
    std::vector<uint8_t> buf;
    if      (type == L"u32") { uint32_t v = (uint32_t)_wcstoui64(val.c_str(), nullptr, 0); buf.assign((uint8_t*)&v, (uint8_t*)&v + 4); }
    else if (type == L"i32") { int32_t  v = (int32_t)_wtoi(val.c_str());                   buf.assign((uint8_t*)&v, (uint8_t*)&v + 4); }
    else if (type == L"u64") { uint64_t v = _wcstoui64(val.c_str(), nullptr, 0);           buf.assign((uint8_t*)&v, (uint8_t*)&v + 8); }
    else if (type == L"f32") { float    v = (float)_wtof(val.c_str());                     buf.assign((uint8_t*)&v, (uint8_t*)&v + 4); }
    else if (type == L"f64") { double   v = _wtof(val.c_str());                            buf.assign((uint8_t*)&v, (uint8_t*)&v + 8); }
    else { wprintf(L"unknown type\n"); return 1; }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    wprintf(L"freezing pid %llu @ 0x%llx = %s (%s). Ctrl-C to stop.\n", pid, addr, val.c_str(), type.c_str());
    uint64_t ticks = 0;
    while (!g_freezeStop) {
        write_bytes(d, pid, addr, buf.data(), buf.size());
        ticks++;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    wprintf(L"\nstopped after %llu writes\n", ticks);
    return 0;
}

int cmd_ptr(Driver& d, uint64_t pid, uint64_t base, const std::vector<uint64_t>& offsets) {
    uint64_t cur = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        uint64_t addr = cur + offsets[i];
        if (i + 1 == offsets.size()) {
            wprintf(L"[step %zu] final addr = 0x%016llx (= base", i, addr);
            for (auto o : offsets) wprintf(L" + 0x%llx", o);
            wprintf(L")\n");
            cur = addr;
            break;
        }
        // dereference: read 8 bytes at addr
        std::vector<uint8_t> buf(8);
        REQ_READ_MEMORY_IN req{};
        req.Header.Type    = REQ_READ_MEMORY;
        req.ProcessId      = pid;
        req.TargetAddress  = addr;
        req.Size           = 8;
        std::vector<uint8_t> io(std::max<size_t>(sizeof(req), 8));
        std::memcpy(io.data(), &req, sizeof(req));
        DWORD got = 0;
        if (!d.call(io.data(), sizeof(req), io.data(), 8, &got) || got < 8) {
            wprintf(L"read failed at step %zu (addr 0x%016llx)\n", i, addr);
            return 1;
        }
        uint64_t nxt;
        std::memcpy(&nxt, io.data(), 8);
        wprintf(L"[step %zu] *(0x%016llx) = 0x%016llx\n", i, addr, nxt);
        cur = nxt;
    }
    return 0;
}

// ─── Incremental scan sessions ──────────────────────────────────────────────
//
// Session file format (plain text, tab-separated):
//   # kr-session v1 pid=<pid> type=<type>
//   <addr-hex>\t<value>
//   ...
//
// Values stored as the canonical decimal/float representation for the type.

struct Session {
    uint64_t              pid;
    std::wstring          type;       // u32|i32|u64|f32|f64
    // entries: address → string-formatted value
    std::vector<std::pair<uint64_t, std::wstring>> entries;
};

bool session_save(const std::wstring& path, const Session& s) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"w") != 0 || !f) return false;
    fwprintf(f, L"# kr-session v1 pid=%llu type=%s\n", s.pid, s.type.c_str());
    for (auto& [a, v] : s.entries) fwprintf(f, L"%016llx\t%s\n", a, v.c_str());
    fclose(f);
    return true;
}

bool session_load(const std::wstring& path, Session& s) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"r") != 0 || !f) return false;
    s.entries.clear();
    wchar_t line[512];
    bool gotHeader = false;
    while (fgetws(line, 512, f)) {
        if (line[0] == L'#') {
            // parse: # kr-session v1 pid=N type=T
            wchar_t typeBuf[16] = {0};
            if (swscanf_s(line, L"# kr-session v1 pid=%llu type=%15s",
                          &s.pid, typeBuf, (unsigned)_countof(typeBuf)) == 2) {
                s.type = typeBuf;
                gotHeader = true;
            }
            continue;
        }
        wchar_t* tab = wcschr(line, L'\t');
        if (!tab) continue;
        *tab = 0;
        uint64_t addr = _wcstoui64(line, nullptr, 16);
        std::wstring val = tab + 1;
        // strip trailing newline
        while (!val.empty() && (val.back() == L'\n' || val.back() == L'\r')) val.pop_back();
        s.entries.emplace_back(addr, std::move(val));
    }
    fclose(f);
    return gotHeader;
}

// Read `n` bytes from target into out — used to refresh a single address.
bool read_at(Driver& d, uint64_t pid, uint64_t addr, void* out, size_t n) {
    REQ_READ_MEMORY_IN req{};
    req.Header.Type = REQ_READ_MEMORY;
    req.ProcessId   = pid;
    req.TargetAddress = addr;
    req.Size          = n;
    std::vector<uint8_t> io(std::max<size_t>(sizeof(req), n));
    std::memcpy(io.data(), &req, sizeof(req));
    DWORD got = 0;
    if (!d.call(io.data(), sizeof(req), io.data(), (DWORD)n, &got) || got < n) return false;
    std::memcpy(out, io.data(), n);
    return true;
}

// Format a freshly-read value back to its canonical string form for the type.
std::wstring fmt_value(const std::wstring& type, const uint8_t* p) {
    wchar_t buf[64];
    if      (type == L"u32") { uint32_t v; std::memcpy(&v, p, 4); swprintf_s(buf, L"%u", v); }
    else if (type == L"i32") { int32_t  v; std::memcpy(&v, p, 4); swprintf_s(buf, L"%d", v); }
    else if (type == L"u64") { uint64_t v; std::memcpy(&v, p, 8); swprintf_s(buf, L"%llu", v); }
    else if (type == L"i64") { int64_t  v; std::memcpy(&v, p, 8); swprintf_s(buf, L"%lld", v); }
    else if (type == L"f32") { float    v; std::memcpy(&v, p, 4); swprintf_s(buf, L"%g", v); }
    else if (type == L"f64") { double   v; std::memcpy(&v, p, 8); swprintf_s(buf, L"%g", v); }
    else return L"?";
    return buf;
}

int cmd_find_first(Driver& d, uint64_t pid, const std::wstring& type,
                   const std::wstring& value, const std::wstring& sessFile) {
    size_t ts = type_size(type);
    if (ts == 0) { wprintf(L"unknown type\n"); return 1; }
    auto regs = get_regions(d, pid);
    if (regs.empty()) { wprintf(L"no regions\n"); return 1; }

    Session s; s.pid = pid; s.type = type;
    const uint64_t chunkSize = 256 * 1024;
    std::vector<uint8_t> buf;
    size_t cap = 100000; // sanity cap

    for (auto& r : regs) {
        if ((r.protect & 0xCC) == 0) continue; // writable only
        for (uint64_t off = 0; off < r.size; off += chunkSize) {
            uint64_t want = std::min<uint64_t>(chunkSize, r.size - off);
            buf.resize((size_t)want);
            if (!read_at(d, pid, r.base + off, buf.data(), buf.size())) continue;
            for (size_t i = 0; i + ts <= buf.size(); ++i) {
                if (matches(type, buf.data() + i, value)) {
                    s.entries.emplace_back(r.base + off + i, value);
                    if (s.entries.size() >= cap) goto done;
                }
            }
        }
    }
done:
    if (!session_save(sessFile, s)) { wprintf(L"failed to write session\n"); return 1; }
    wprintf(L"first scan: %zu matches → %s\n", s.entries.size(), sessFile.c_str());
    return 0;
}

int cmd_find_next(Driver& d, const std::wstring& sessFile, const std::wstring& value) {
    Session s;
    if (!session_load(sessFile, s)) { wprintf(L"could not load session\n"); return 1; }
    size_t ts = type_size(s.type);
    if (ts == 0) { wprintf(L"session has bad type\n"); return 1; }

    std::vector<std::pair<uint64_t, std::wstring>> kept;
    uint8_t buf[8];
    for (auto& [addr, _prev] : s.entries) {
        if (!read_at(d, s.pid, addr, buf, ts)) continue;
        if (matches(s.type, buf, value)) {
            kept.emplace_back(addr, value);
        }
    }
    s.entries = std::move(kept);
    session_save(sessFile, s);
    wprintf(L"narrowed: %zu remaining (value=%s)\n", s.entries.size(), value.c_str());
    if (s.entries.size() <= 20) {
        for (auto& [a, v] : s.entries) wprintf(L"  %016llx = %s\n", a, v.c_str());
    }
    return 0;
}

int cmd_find_cmp(Driver& d, const std::wstring& sessFile, const std::wstring& op) {
    Session s;
    if (!session_load(sessFile, s)) { wprintf(L"could not load session\n"); return 1; }
    size_t ts = type_size(s.type);
    if (ts == 0) { wprintf(L"session has bad type\n"); return 1; }

    auto cmp = [&](const std::wstring& a, const std::wstring& b) -> int {
        if (s.type == L"f32" || s.type == L"f64") {
            double da = _wtof(a.c_str()), db = _wtof(b.c_str());
            return (da > db) - (da < db);
        }
        long long la = _wtoi64(a.c_str()), lb = _wtoi64(b.c_str());
        return (la > lb) - (la < lb);
    };

    std::vector<std::pair<uint64_t, std::wstring>> kept;
    uint8_t buf[8];
    for (auto& [addr, prev] : s.entries) {
        if (!read_at(d, s.pid, addr, buf, ts)) continue;
        std::wstring now = fmt_value(s.type, buf);
        int c = cmp(now, prev);
        bool keep =
            (op == L"changed"   && c != 0) ||
            (op == L"unchanged" && c == 0) ||
            (op == L"inc"       && c >  0) ||
            (op == L"dec"       && c <  0);
        if (keep) kept.emplace_back(addr, now);
    }
    s.entries = std::move(kept);
    session_save(sessFile, s);
    wprintf(L"after '%s': %zu remaining\n", op.c_str(), s.entries.size());
    if (s.entries.size() <= 20) {
        for (auto& [a, v] : s.entries) wprintf(L"  %016llx = %s\n", a, v.c_str());
    }
    return 0;
}

int cmd_find_show(const std::wstring& sessFile) {
    Session s;
    if (!session_load(sessFile, s)) { wprintf(L"could not load session\n"); return 1; }
    wprintf(L"# pid=%llu type=%s entries=%zu\n", s.pid, s.type.c_str(), s.entries.size());
    for (auto& [a, v] : s.entries) wprintf(L"  %016llx = %s\n", a, v.c_str());
    return 0;
}

void usage() {
    wprintf(L"usage:\n");
    wprintf(L"  client list\n");
    wprintf(L"  client modules <pid>\n");
    wprintf(L"  client base    <pid> <module-name>\n");
    wprintf(L"  client regions <pid>\n");
    wprintf(L"  client read    <pid> <hex-addr> <size>\n");
    wprintf(L"  client scan    <pid> <module-name> <\"hex sig with ?\">\n");
    wprintf(L"  client write   <pid> <hex-addr> <\"DE AD BE EF\">\n");
    wprintf(L"  client wu32    <pid> <hex-addr> <value>\n");
    wprintf(L"  client wf32    <pid> <hex-addr> <value>\n");
    wprintf(L"  client find    <pid> <u32|i32|u64|f32|f64> <value>\n");
    wprintf(L"  client freeze  <pid> <hex-addr> <type> <value>\n");
    wprintf(L"  client ptr     <pid> <hex-base> <hex-off1> [hex-off2 ...]\n");
    wprintf(L"  client find-first <pid> <type> <value> <session-file>\n");
    wprintf(L"  client find-next  <pid> <session-file> <value>\n");
    wprintf(L"  client find-cmp   <pid> <session-file> <changed|unchanged|inc|dec>\n");
    wprintf(L"  client find-show  <session-file>\n");
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
            std::wstring ws = argv[4];
            std::string s(ws.begin(), ws.end());
            return cmd_scan(d,
                _wcstoui64(argv[2], nullptr, 10),
                argv[3], s);
        }
        if (cmd == L"regions" && argc == 3)
            return cmd_regions(d, _wcstoui64(argv[2], nullptr, 10));
        if (cmd == L"write" && argc == 5)
            return cmd_write(d, _wcstoui64(argv[2], nullptr, 10),
                             _wcstoui64(argv[3], nullptr, 16), argv[4]);
        if (cmd == L"wu32" && argc == 5)
            return cmd_write_typed(d, _wcstoui64(argv[2], nullptr, 10),
                                   _wcstoui64(argv[3], nullptr, 16), L"u32", argv[4]);
        if (cmd == L"wf32" && argc == 5)
            return cmd_write_typed(d, _wcstoui64(argv[2], nullptr, 10),
                                   _wcstoui64(argv[3], nullptr, 16), L"f32", argv[4]);
        if (cmd == L"find" && argc == 5)
            return cmd_find(d, _wcstoui64(argv[2], nullptr, 10), argv[3], argv[4]);
        if (cmd == L"freeze" && argc == 6)
            return cmd_freeze(d, _wcstoui64(argv[2], nullptr, 10),
                              _wcstoui64(argv[3], nullptr, 16), argv[4], argv[5]);
        if (cmd == L"find-first" && argc == 6)
            return cmd_find_first(d, _wcstoui64(argv[2], nullptr, 10),
                                  argv[3], argv[4], argv[5]);
        if (cmd == L"find-next" && argc == 5) {
            // signature: find-next <pid> <session> <value>
            // pid is implicit in the session header; accept and validate.
            uint64_t pidArg = _wcstoui64(argv[2], nullptr, 10);
            (void)pidArg; // currently informational
            return cmd_find_next(d, argv[3], argv[4]);
        }
        if (cmd == L"find-cmp" && argc == 5) {
            uint64_t pidArg = _wcstoui64(argv[2], nullptr, 10);
            (void)pidArg;
            return cmd_find_cmp(d, argv[3], argv[4]);
        }
        if (cmd == L"find-show" && argc == 3)
            return cmd_find_show(argv[2]);
        if (cmd == L"ptr" && argc >= 4) {
            std::vector<uint64_t> offs;
            for (int i = 4; i < argc; ++i) offs.push_back(_wcstoui64(argv[i], nullptr, 16));
            return cmd_ptr(d, _wcstoui64(argv[2], nullptr, 10),
                           _wcstoui64(argv[3], nullptr, 16), offs);
        }
    } catch (const std::exception& e) {
        wprintf(L"error: %hs\n", e.what());
        return 1;
    }
    usage();
    return 2;
}
