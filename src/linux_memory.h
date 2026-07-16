/*
 * linux_memory.h - Linux/Android process memory operations
 *
 * Replaces Windows APIs:
 *   OpenProcess            -> open /proc/pid/mem
 *   ReadProcessMemory      -> process_vm_readv / pread64
 *   VirtualQueryEx         -> parse /proc/pid/maps
 *   EnumProcessModules     -> parse /proc/pid/maps
 *   GetModuleInformation   -> parse /proc/pid/maps
 *
 * Works on any Linux system (including Android with root).
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

// process_vm_readv syscall number (not always in NDK headers)
#ifndef __NR_process_vm_readv
#if defined(__aarch64__)
#define __NR_process_vm_readv 270
#elif defined(__arm__)
#define __NR_process_vm_readv 376
#elif defined(__x86_64__)
#define __NR_process_vm_readv 310
#elif defined(__i386__)
#define __NR_process_vm_readv 347
#else
#define __NR_process_vm_readv 0
#endif
#endif

// ─── Platform detection ────────────────────────────────────────────────
#if defined(__aarch64__) || defined(__arm64__)
    #define PLATFORM_ARM64 1
    #define PLATFORM_X86_64 0
#elif defined(__x86_64__) || defined(__amd64__)
    #define PLATFORM_ARM64 0
    #define PLATFORM_X86_64 1
#else
    #error "Unsupported architecture. Only ARM64 and x86_64 are supported."
#endif

// ─── Memory region info ────────────────────────────────────────────────
struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint8_t  prot;       // r=1 w=2 x=4
    std::string path;    // e.g. libUE4.so, /system/lib64/libc.so

    size_t size() const { return static_cast<size_t>(end - start); }
    bool isReadable() const { return prot & 0x1; }
    bool isExecutable() const { return prot & 0x4; }
};

// ─── Module info ───────────────────────────────────────────────────────
struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t baseAddress;
    size_t   size;
};

// ─── Process handle (replaces HANDLE) ──────────────────────────────────
class ProcessHandle {
public:
    pid_t pid;
    int   memFd;           // fd for /proc/pid/mem
    std::vector<MemoryRegion> regions;
    std::vector<ModuleInfo>    modules;

    ProcessHandle() : pid(0), memFd(-1) {}
    ~ProcessHandle() { close(); }

    bool open(int target_pid);
    void close();

    // Read memory (replaces ReadProcessMemory)
    bool readMemory(uint64_t addr, void* buf, size_t len) const;

    // Read a typed value
    template<typename T>
    T read(uint64_t addr) const {
        T val{};
        readMemory(addr, &val, sizeof(T));
        return val;
    }

    // Find memory region containing an address
    const MemoryRegion* findRegion(uint64_t addr) const;

    // Get the main UE4 module (libUE4.so)
    const ModuleInfo* findUE4Module() const;

private:
    void parseMaps();
};

// ─── Implementation ────────────────────────────────────────────────────

inline bool ProcessHandle::open(int target_pid) {
    pid = target_pid;

    // Open /proc/pid/mem for direct memory access
    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    memFd = ::open(memPath, O_RDONLY);
    if (memFd < 0) {
        fprintf(stderr, "[!] Failed to open %s (are you root?)\n", memPath);
        return false;
    }

    parseMaps();
    return true;
}

inline void ProcessHandle::close() {
    if (memFd >= 0) {
        ::close(memFd);
        memFd = -1;
    }
    pid = 0;
}

inline bool ProcessHandle::readMemory(uint64_t addr, void* buf, size_t len) const {
    if (!buf || len == 0) return false;

    // Method 1: syscall process_vm_readv (works on all Linux >=3.2, no NDK wrapper needed)
    struct iovec local_iov = { buf, len };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr), len };
    ssize_t nread = syscall(__NR_process_vm_readv, (long)pid,
                            &local_iov, 1ul, &remote_iov, 1ul, 0ul);
    if (nread == static_cast<ssize_t>(len)) {
        return true;
    }

    // Method 2: fallback to pread64 on /proc/pid/mem
    if (memFd >= 0) {
        ssize_t n = pread64(memFd, buf, len, static_cast<off64_t>(addr));
        return n == static_cast<ssize_t>(len);
    }

    return false;
}

inline void ProcessHandle::parseMaps() {
    regions.clear();
    modules.clear();

    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);

    std::ifstream maps(mapsPath);
    if (!maps.is_open()) {
        fprintf(stderr, "[!] Failed to open %s\n", mapsPath);
        return;
    }

    std::string line;
    std::vector<std::string> modulePaths;

    while (std::getline(maps, line)) {
        MemoryRegion region{};
        char perms[8] = {};
        char path[512] = {};
        uint64_t inode = 0;

        // Parse: addr-perms offset dev inode path
        int n = sscanf(line.c_str(), "%lx-%lx %4s %lx %*x:%*x %lu %511s",
                       &region.start, &region.end, perms, &region.offset, &inode, path);

        if (n < 3) continue;

        // Parse permissions
        region.prot = 0;
        if (perms[0] == 'r') region.prot |= 0x1;
        if (perms[1] == 'w') region.prot |= 0x2;
        if (perms[2] == 'x') region.prot |= 0x4;

        // Extract path
        if (n >= 6 && path[0] != '\0') {
            region.path = path;

            // Track unique modules
            if (inode > 0 && region.offset == 0) {
                // Check if already seen this path
                bool found = false;
                for (auto& m : modules) {
                    if (m.path == region.path) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    // Extract just the filename
                    std::string name = region.path;
                    size_t slashPos = name.rfind('/');
                    if (slashPos != std::string::npos) {
                        name = name.substr(slashPos + 1);
                    }

                    ModuleInfo mod;
                    mod.name = name;
                    mod.path = region.path;
                    mod.baseAddress = region.start;
                    modules.push_back(mod);
                }
            }

            // Update module size: find the largest end for this path
            for (auto& m : modules) {
                if (region.path == m.path) {
                    uint64_t modEnd = region.end;
                    // Don't include [stack], [heap] etc in size
                    if (modEnd > m.baseAddress && modEnd - m.baseAddress < 0x20000000) {
                        m.size = std::max(m.size, static_cast<size_t>(modEnd - m.baseAddress));
                    }
                }
            }
        } else {
            // Anonymous mappings
            char anonName[32];
            if (strstr(line.c_str(), "[stack]")) {
                region.path = "[stack]";
            } else if (strstr(line.c_str(), "[heap]")) {
                region.path = "[heap]";
            }
        }

        regions.push_back(region);
    }

    maps.close();

    // Sort regions by start address
    std::sort(regions.begin(), regions.end(),
              [](const MemoryRegion& a, const MemoryRegion& b) { return a.start < b.start; });

    printf("[*] Parsed %zu memory regions, %zu modules\n", regions.size(), modules.size());
    for (auto& m : modules) {
        printf("    %-40s base=0x%lx size=0x%zx\n", m.name.c_str(), m.baseAddress, m.size);
    }
}

inline const MemoryRegion* ProcessHandle::findRegion(uint64_t addr) const {
    // Binary search
    auto it = std::lower_bound(regions.begin(), regions.end(), addr,
        [](const MemoryRegion& r, uint64_t a) { return r.end <= a; });
    if (it != regions.end() && it->start <= addr && addr < it->end) {
        return &(*it);
    }
    return nullptr;
}

inline const ModuleInfo* ProcessHandle::findUE4Module() const {
    for (auto& m : modules) {
        // Common UE4 Android library names
        if (m.name.find("libUE4") != std::string::npos ||
            m.name.find("libUnreal") != std::string::npos ||
            m.name.find("libCrab") != std::string::npos) {  // Some games rename it
            return &m;
        }
    }
    // Fallback: look for the largest executable .so
    const ModuleInfo* best = nullptr;
    for (auto& m : modules) {
        if (m.path.find(".so") != std::string::npos && m.size > 10 * 1024 * 1024) {
            if (!best || m.size > best->size) {
                best = &m;
            }
        }
    }
    return best;
}

// ─── ARM64 instruction helpers ─────────────────────────────────────────
#if PLATFORM_ARM64

// ADRP instruction: decode page-relative 4KB-aligned address
// Encoding: 1ii 10000 iii...iii ddddd
inline bool isADRP(uint32_t insn) {
    return (insn & 0x9F000000) == 0x90000000;
}

// ADR instruction: decode byte-offset address
// Encoding: 0ii 10000 iii...iii ddddd
inline bool isADR(uint32_t insn) {
    return (insn & 0x9F000000) == 0x10000000;
}

// ADD immediate: Rd = Rn + imm12
// Encoding: 1001000100 shift imm12 Rn Rd
inline bool isADD_imm(uint32_t insn) {
    return (insn & 0xFFC00000) == 0x91000000;
}

// LDR literal: load from PC-relative address
// Encoding: 01 011 00 iii...iii ddddd
inline bool isLDR_literal(uint32_t insn) {
    return (insn & 0x3B000000) == 0x18000000;
}

// Decode ADRP target page address from instruction at given PC
inline uint64_t decodeADRP(uint32_t insn, uint64_t pc) {
    // Extract immediate: immlo (bits 30-29) + immhi (bits 23-5)
    int64_t immlo = (insn >> 29) & 0x3;
    int64_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm = (immlo << 19) | immhi;  // 21-bit signed immediate
    // Sign extend from 21-bit
    imm = (imm << 43) >> 43;
    // ADRP gives 4KB-aligned address
    return (pc & ~0xFFFull) + (imm << 12);
}

// Decode ADD immediate value
inline uint64_t decodeADD_imm(uint32_t insn) {
    return (insn >> 10) & 0xFFF;
}

// Get destination register from ADRP/ADR/ADD
inline int getRd(uint32_t insn) {
    return insn & 0x1F;
}

// Get source register from ADD
inline int getRn(uint32_t insn) {
    return (insn >> 5) & 0x1F;
}

#endif // PLATFORM_ARM64

// ─── x86_64 instruction helpers ────────────────────────────────────────
#if PLATFORM_X86_64

// LEA reg, [rip+disp32] - check if instruction is RIP-relative LEA
// Encoding: REX.W (48/4C) 8D ModRM SIB disp32
inline bool isLEA_RIP(uint8_t opcode1, uint8_t opcode2) {
    // 48 8D 0D = lea rcx, [rip+...]
    // 4C 8D 0D = lea r9, [rip+...]
    // 48 8D 15 = lea rdx, [rip+...]
    // 48 8D 1D = lea rbx, [rip+...]
    // 48 8D 05 = lea rax, [rip+...]
    return (opcode1 == 0x48 || opcode1 == 0x4C) && opcode2 == 0x8D;
}

#endif // PLATFORM_X86_64
