/*
 * ue4_scanner.h - UE4 engine address scanner
 *
 * Finds GNames, GObjects, GWorld, and key function addresses
 * by scanning process memory for AOB signatures.
 *
 * Supports both ARM64 (Android phones) and x86_64 (Android emulator / PC).
 */

#pragma once
#include "linux_memory.h"
#include "algorithm.h"
#include "profile.h"
#include <thread>
#include <atomic>
#include <vector>

static std::atomic<bool> gSearchComplete{false};

// ─── Helper: convert absolute address to offset ────────────────────────
static int64_t toOffset(int64_t addr, int64_t base) {
    return addr - base;
}

// ═══════════════════════════════════════════════════════════════════════
//  ENGINE VERSION DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace EngineVersion {

// The string reference approach: find "%sunreal-v%i-%s.dmp" string
// and locate the associated GEngineVersion global.

#if PLATFORM_X86_64
bool detectX86_64(const ProcessHandle& ph, int64_t moduleBase, size_t moduleSize) {
    const wchar_t* targetStr = L"%sunreal-v%i-%s.dmp";
    size_t strLen = wcslen(targetStr);

    for (const auto& region : ph.regions) {
        if (!region.isReadable() || region.path.empty()) continue;
        if (region.size() < 1024) continue;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        auto foundAddr = Algorithm::ScanforStringRef(
            ph, buffer, (const uint16_t*)targetStr,
            static_cast<int64_t>(region.start), 3,
            "GetEngineVersion()");

        if (foundAddr) {
            // Pre-4.10: Look for LEA that references GEngineVersion global
            if (auto leaAddr = Algorithm::ScanFor(ph, foundAddr,
                    {0x48, 0x8D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8}, true, 36)) {
                auto relative = Algorithm::ReadAs<int32_t>(ph, leaAddr + 3);
                auto gVersionAddr = leaAddr + relative + 7;

                int16_t major = Algorithm::ReadAs<int16_t>(ph, gVersionAddr);
                int16_t minor = Algorithm::ReadAs<int16_t>(ph, gVersionAddr + 2);
                int16_t patch = Algorithm::ReadAs<int16_t>(ph, gVersionAddr + 4);
                int version = major * 10000 + minor * 100 + patch;

                printf("[*] Engine Version: %d.%d.%d (%d)\n", major, minor, patch, version);
                gProfile.EngineVersion = version;
                gProfile.IsUsing4_22 = (version / 100 == 422);
                gProfile.IsUsingFChunkedFixedUObjectArray = (version / 100 >= 418);
                return true;
            }

            // 4.11+: Look for CALL to GetEngineVersion function
            if (auto callAddr = Algorithm::ScanFor(ph, foundAddr,
                    {0x48, 0xFF, 0xFF, 0xE8}, true) - 4) {
                auto relative = Algorithm::ReadAs<int32_t>(ph, callAddr);
                auto getVersionFn = callAddr + relative + 4;

                printf("[*] Found GetEngineVersion() at 0x%lx\n", getVersionFn);
                // TODO: Use ptrace to call the function and get return value
                // For now, ask user to specify version
                printf("[!] Auto-detection for 4.11+ requires manual version input\n");
                return false;
            }
        }
    }
    return false;
}
#endif // PLATFORM_X86_64

#if PLATFORM_ARM64
bool detectARM64(const ProcessHandle& ph, int64_t moduleBase, size_t moduleSize) {
    // On ARM64, look for the same engine version string
    // The string is usually ASCII in UE4
    const char* targetStr = "%sunreal-v%i-%s.dmp";

    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        if (region.size() < 1024) continue;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        // Search for the string using ADRP scanning
        auto foundAddr = Algorithm::ScanforStringRef(
            ph, buffer, targetStr,
            static_cast<int64_t>(region.start),
            "GetEngineVersion()");

        if (foundAddr) {
            // Near this string, look for ADRP+ADD that loads GEngineVersion
            // On ARM64, the version global is accessed via ADRP + LDR
            // Pattern: ADRP Xn, page; LDR Xn, [Xn, #offset]
            // For now, scan nearby for ADRP instructions that might point to version data

            printf("[*] Found engine version string reference at 0x%lx\n", foundAddr);

            // Scan backward to find the function that uses this string
            // The function prologue should be nearby
            // ARM64 prologue: FD 7B BF A9 (STP X29, X30, [SP, #-0x10]!)
            int64_t searchStart = foundAddr - 0x200;
            for (int64_t addr = searchStart; addr < foundAddr; addr += 4) {
                uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);
                // Check for common ARM64 prologue
                if ((insn & 0xFF000000) == 0xA9000000) {
                    // STP instruction - likely function start
                    printf("[*] Possible function entry at 0x%lx\n", addr);
                }
            }

            printf("[!] Engine version auto-detection on ARM64 is experimental\n");
            printf("[!] Please specify --ue4-version <ver> manually (e.g. 426 for 4.26)\n");
            return false;
        }
    }
    return false;
}
#endif // PLATFORM_ARM64

} // namespace EngineVersion

// ═══════════════════════════════════════════════════════════════════════
//  GNames / FNamePool DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace NameScanner {

static std::atomic<bool> gFound{false};

#if PLATFORM_X86_64

// Method 1: String reference for "Hardcoded name '%s' at index %i..."
bool method1_x86(const ProcessHandle& ph, const MemoryRegion& region) {
    if (gFound) return false;

    std::vector<uint8_t> buffer(region.size());
    if (!ph.readMemory(region.start, buffer.data(), region.size())) return false;

    const wchar_t* str = L"Hardcoded name '%s' at index %i was duplicated (or unexpected concurrency). Existing entry is '%s'.";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str,
        static_cast<int64_t>(region.start), 3, "FName::GetNames()");

    if (strAddr) {
        // Find the call that precedes the string reference
        // Pattern: BA 01 00 00 00 48 8B C8 E8 (mov edx,1; mov rcx,rax; call ...)
        auto beforeCall = Algorithm::ScanFor(ph, strAddr,
            {0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0xE8}, true);

        if (beforeCall >= 0) {
            // Find the actual CALL to GetName function
            auto callGetName = Algorithm::ScanFor(ph, beforeCall,
                {0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x8B}, true, 70);

            if (callGetName >= 0) {
                int32_t relative = Algorithm::ReadAs<int32_t>(ph, callGetName + 1);
                auto getNameFn = callGetName + relative + 5;

                // Inside GetName, look for MOV that loads GNames from a global
                auto movGNames = Algorithm::ScanFor(ph, getNameFn,
                    {0x48, 0x8B}, false, 50);

                if (movGNames >= 0) {
                    int32_t rel = Algorithm::ReadAs<int32_t>(ph, movGNames + 3);
                    auto gNamesAddr = movGNames + 3 + rel + 4;

                    printf("[*] Found GNames: 0x%lx\n", gNamesAddr);
                    gProfile.GNameOffset = toOffset(gNamesAddr, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                    gFound = true;
                    return true;
                }
            }
        }
    }
    return false;
}

// Method 2: Brute-force search for TNameEntryArray structure
bool method2_x86(const ProcessHandle& ph, const MemoryRegion& region) {
    if (gFound) return false;

    size_t numQwords = region.size() / 8;
    std::vector<int64_t> buffer(numQwords);
    if (!ph.readMemory(region.start, buffer.data(), region.size() & ~7ull)) return false;

    for (size_t i = 0; i < buffer.size(); i++) {
        if (gFound) return false;

        int64_t ptr1 = buffer[i];
        if (!ptr1) continue;

        int64_t name1 = Algorithm::ReadAs<int64_t>(ph, ptr1);
        if (!name1) continue;

        int64_t nameIndexAddr = Algorithm::ReadAs<int64_t>(ph, name1);
        if (!nameIndexAddr) continue;

        nameIndexAddr += 0xC;
        uint8_t nameCheck[16];
        if (!ph.readMemory(nameIndexAddr, nameCheck, sizeof(nameCheck))) continue;

        for (int bi = 0; bi <= 4; bi++) {
            uint32_t checkVal = *(uint32_t*)(&nameCheck[bi]);
            if (checkVal == 0x656E6F4E) { // "None"
                auto gNamesAddr = static_cast<int64_t>(region.start) + i * 8;

                // Verify by reading entry 0
                int64_t entryPtr = Algorithm::ReadAs<int64_t>(ph, gNamesAddr);
                int64_t firstEntry = Algorithm::ReadAs<int64_t>(ph, entryPtr);
                char ansiName[32] = {};
                ph.readMemory(firstEntry + 0x10, ansiName, sizeof(ansiName));
                if (strcmp(ansiName, "None") != 0) {
                    printf("[-] False GNames at 0x%lx (entry[0]='%s')\n", gNamesAddr, ansiName);
                    continue;
                }
                printf("[*] Found GNames (method 2): 0x%lx\n", gNamesAddr);
                gProfile.GNameOffset = toOffset(gNamesAddr, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                gFound = true;
                return true;
            }
        }
    }
    return false;
}

#endif // PLATFORM_X86_64

#if PLATFORM_ARM64

// ARM64 GNames detection using string reference
bool scanARM64(const ProcessHandle& ph, const MemoryRegion& region) {
    if (gFound) return false;

    std::vector<uint8_t> buffer(region.size());
    if (!ph.readMemory(region.start, buffer.data(), region.size())) return false;

    // Look for "Hardcoded name '%s' at index %i..." string via ADRP
    const char* str = "Hardcoded name '%s' at index %i was duplicated (or unexpected concurrency). Existing entry is '%s'.";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str,
        static_cast<int64_t>(region.start), "FName::GetNames()");

    if (strAddr) {
        printf("[*] Found GNames string ref at 0x%lx\n", strAddr);

        // On ARM64, scan backward from the string reference to find the function entry
        // Look for ARM64 prologue: STP X29, X30, [SP, #...]!
        for (int64_t addr = strAddr - 0x100; addr < strAddr; addr += 4) {
            uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);

            // STP pre-index: 0xA9...
            // For STP X29, X30 with pre-index: FD 7B ?? A9
            if ((insn & 0xFFC0FFFF) == 0xA9007BFD) {
                // Found function entry, now look for ADRP that loads GNames
                int64_t fnEntry = addr;

                // Scan for ADRP + LDR pattern loading GNames array
                for (int64_t cur = fnEntry; cur < strAddr + 0x500; cur += 4) {
                    uint32_t insn2 = Algorithm::ReadAs<uint32_t>(ph, cur);
                    if (isADRP(insn2)) {
                        // Verify this ADRP points to data section
                        uint64_t target = decodeADRP(insn2, cur);
                        bool inData = true;
                        auto* reg = ph.findRegion(target);
                        if (!reg || reg->isExecutable()) {
                            inData = false;
                        }
                        if (inData) {
                            // Might be GNames - verify by checking first entry
                            int64_t firstPtr = Algorithm::ReadAs<int64_t>(ph, target);
                            if (firstPtr > 0 && firstPtr < 0x800000000000ULL) {
                                int64_t innerPtr = Algorithm::ReadAs<int64_t>(ph, firstPtr);
                                if (innerPtr > 0) {
                                    char nameCheck[32] = {};
                                    ph.readMemory(innerPtr + 0xC, nameCheck, sizeof(nameCheck));
                                    if (strncmp(nameCheck, "None", 4) == 0) {
                                        printf("[*] Found GNames (ARM64): 0x%lx\n", target);
                                        gProfile.GNameOffset = toOffset(target,
                                            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                                        gFound = true;
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}

// ARM64 FNamePool detection (UE 4.23+)
bool scanFNamePoolARM64(const ProcessHandle& ph, const MemoryRegion& region) {
    if (gFound) return false;

    // FNamePool in 4.23+ is detected by scanning for pointers that point to "None" string
    // Same brute-force approach as x86_64 method2 but adapted

    size_t numQwords = region.size() / 8;
    std::vector<int64_t> buffer(numQwords);
    if (!ph.readMemory(region.start, buffer.data(), region.size() & ~7ull)) return false;

    for (size_t i = 0; i < buffer.size(); i++) {
        if (gFound) return false;

        int64_t ptr = buffer[i];
        if (!ptr || ptr >= 0x800000000000ULL) continue;

        // Read what this pointer points to
        std::vector<int64_t> inner(1);
        if (!ph.readMemory(ptr, inner.data(), 8)) continue;

        int64_t innerPtr = inner[0];
        if (!innerPtr) continue;

        // Check if it points to readable data with "None" at offset
        char strData[16] = {};
        if (!ph.readMemory(innerPtr, strData, sizeof(strData))) continue;

        for (int bi = 0; bi <= 4; bi++) {
            if (*(uint32_t*)(&strData[bi]) == 0x656E6F4E) { // "None"
                // Is this pointer inside the module's data section?
                if (ptr < static_cast<int64_t>(ph.findUE4Module()->baseAddress)) continue;

                // FNamePool starts at ptr - 0x10 typically
                auto fnpAddr = static_cast<int64_t>(region.start) + i * 8 - 0x10;
                printf("[*] Found FNamePool (ARM64): 0x%lx\n", fnpAddr);
                gProfile.GNameOffset = toOffset(fnpAddr,
                    static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                gProfile.UseFNamePool = true;
                gFound = true;
                return true;
            }
        }
    }
    return false;
}

#endif // PLATFORM_ARM64

bool find(const ProcessHandle& ph, int64_t moduleBase, size_t moduleSize) {
    gFound = false;
    std::vector<std::thread> threads;

    printf("[*] Searching for GNames/FNamePool...\n");

    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;

#if PLATFORM_X86_64
        if (gProfile.UseFNamePool) {
            // If UE 4.23+ detected, use FNamePool search only
            // (searching for FNamePool is done via brute force - see Names.h)
            printf("[*] FNamePool search... will try brute force\n");
        } else {
            threads.emplace_back([&ph, &region]() {
                if (!method1_x86(ph, region)) {
                    // If method1 fails, we'll handle in second pass
                }
            });
        }
#endif

#if PLATFORM_ARM64
        if (gProfile.IsUE4_23_Plus()) {
            threads.emplace_back([&ph, &region]() {
                scanFNamePoolARM64(ph, region);
            });
        } else {
            threads.emplace_back([&ph, &region]() {
                scanARM64(ph, region);
            });
        }
#endif
    }

    for (auto& t : threads) t.join();

#if PLATFORM_X86_64
    // If method 1 failed and we're not in FNamePool mode, try method 2
    if (!gFound && !gProfile.UseFNamePool) {
        printf("[*] Method 1 failed, trying brute-force Method 2...\n");
        std::vector<std::thread> threads2;
        for (const auto& region : ph.regions) {
            if (!region.isReadable()) continue;
            threads2.emplace_back([&ph, &region]() {
                method2_x86(ph, region);
            });
        }
        for (auto& t : threads2) t.join();
    }
#endif

    if (gFound) {
        printf("[+] GNames offset: 0x%lx\n", gProfile.GNameOffset);
    } else {
        printf("[-] GNames not found\n");
    }
    return gFound;
}

} // namespace NameScanner

// ═══════════════════════════════════════════════════════════════════════
//  GOBJECTS DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace ObjectScanner {

#if PLATFORM_X86_64
bool findX86_64(const ProcessHandle& ph, int64_t moduleBase) {
    // Pattern: 8B 46 10 3B 46 3C 75 0F 48 8B D6 48 8D 0D xx xx xx xx E8
    // This accesses GObjectArray and calls a function
    const std::vector<uint8_t> pattern = {
        0x8B, 0x46, 0x10, 0x3B, 0x46, 0x3C, 0x75, 0x0F,
        0x48, 0x8B, 0xD6, 0x48, 0x8D, 0x0D, 0xFF, 0xFF,
        0xFF, 0xFF, 0xE8
    };

    for (const auto& region : ph.regions) {
        if (!region.isReadable() || !region.isExecutable()) continue;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        int64_t idx = Algorithm::searchArray(buffer, pattern, false);
        if (idx >= 0) {
            int32_t relative = *(int32_t*)(&buffer[idx + 14]);
            int64_t gObjectAddr = static_cast<int64_t>(region.start) + idx + 14 + relative + 4;

            printf("[*] Found GObjects: 0x%lx\n", gObjectAddr);
            gProfile.GObjectOffset = toOffset(gObjectAddr, moduleBase);
            return true;
        }
    }

    // Fallback: use SpawnActorFTrans to derive GObjects
    if (gProfile.SpawnActorFTransOffset != 0) {
        auto spawnAddr = moduleBase + gProfile.SpawnActorFTransOffset;
        auto cmpJge = Algorithm::ScanFor(ph, spawnAddr,
            {0x3B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x7D, 0xFF}, false);
        auto leaMov = Algorithm::ScanFor(ph, cmpJge,
            {0x48, 0x8D, 0xFF, 0x40, 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF}, false, 50) + 4;

        auto rel1 = Algorithm::ReadAs<int32_t>(ph, cmpJge + 2);
        auto rel2 = Algorithm::ReadAs<int32_t>(ph, leaMov + 3);
        auto numElements = cmpJge + rel1 + 6;
        auto objFlags = leaMov + rel2 + 7;
        auto offset = numElements - objFlags;

        int64_t gObjAddr = objFlags - 0x10;
        if (offset == 0x14) {
            printf("[*] Using FChunkedFixedUObjectArray\n");
            gProfile.IsUsingFChunkedFixedUObjectArray = true;
        } else if (offset == 0xC) {
            printf("[*] Not using FChunkedFixedUObjectArray\n");
            gProfile.IsUsingFChunkedFixedUObjectArray = false;
        } else {
            printf("[!] Unusual UObjectArray alignment (offset=0x%lx)\n", offset);
        }
        printf("[*] Found GObjects (via SpawnActor): 0x%lx\n", gObjAddr);
        gProfile.GObjectOffset = toOffset(gObjAddr, moduleBase);
        return true;
    }
    return false;
}
#endif

#if PLATFORM_ARM64
bool findARM64(const ProcessHandle& ph, int64_t moduleBase) {
    // ARM64 GObjectArray detection
    // Look for ADRP + LDR patterns that access the global object array
    // The access pattern is typically:
    // ADRP Xn, page
    // LDR  Wm, [Xn, #offset+0x10]   ; NumElements
    // LDR  Wk, [Xn, #offset+0x3C]   ; MaxElements
    // CMP  Wm, Wk
    // B.NE ...
    // ... LEA Xn, [Xn, #offset]      ; (for loading GObjectArray address)

    // Simpler approach: scan for a common GObjectArray access pattern
    // The INI approach: scan for references to FUObjectArray fields
    // Try the "Chunked" detection first if SpawnActor is found

    if (gProfile.SpawnActorFTransOffset != 0) {
        auto spawnAddr = moduleBase + gProfile.SpawnActorFTransOffset;

        // On ARM64: look for LDRSW (load signed word) followed by CMP with another LDR
        // Pattern: LDR Wx, [Xn, #off1]; LDR Wy, [Xn, #off2]; CMP Wx, Wy
        // B.GT ...; ADRP Xz, page; ADD Xz, Xz, #off

        // For now, scan forward from SpawnActor for ADRP that loads GObjectArray
        for (int64_t addr = spawnAddr; addr < spawnAddr + 0x300; addr += 4) {
            uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);
            if (isADRP(insn)) {
                uint64_t pageAddr = decodeADRP(insn, addr);
                int rd = getRd(insn);

                // Look for following ADD
                for (int64_t a2 = addr + 4; a2 < addr + 20; a2 += 4) {
                    uint32_t addInsn = Algorithm::ReadAs<uint32_t>(ph, a2);
                    if (isADD_imm(addInsn) && getRd(addInsn) == rd && getRn(addInsn) == rd) {
                        uint64_t target = pageAddr + decodeADD_imm(addInsn);

                        // Verify this is in data section
                        auto* reg = ph.findRegion(target);
                        if (reg && !reg->isExecutable()) {
                            int64_t val = Algorithm::ReadAs<int64_t>(ph, target);
                            if (val > 0 && val < 0x800000000000ULL) {
                                printf("[*] Found GObjects (ARM64): 0x%lx\n", target);
                                gProfile.GObjectOffset = toOffset(target, moduleBase);
                                gProfile.IsUsingFChunkedFixedUObjectArray = true;
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    printf("[-] GObjects: ARM64 scan not yet implemented (needs SpawnActor first)\n");
    return false;
}
#endif

} // namespace ObjectScanner

// ═══════════════════════════════════════════════════════════════════════
//  GWORLD DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace WorldScanner {

#if PLATFORM_X86_64
bool findX86_64(const ProcessHandle& ph, int64_t moduleBase) {
    // Method 1: Pattern scan for GWorld access
    // 0F 2E ?? 74 ?? 48 8B 1D xx xx xx xx 48 85 DB 74
    const std::vector<uint8_t> pattern1 = {
        0x0F, 0x2E, 0xFF, 0x74, 0xFF, 0x48, 0x8B, 0x1D,
        0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xDB, 0x74
    };

    for (const auto& region : ph.regions) {
        if (!region.isReadable() || !region.isExecutable()) continue;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        int64_t idx = Algorithm::searchArray(buffer, pattern1, false);
        if (idx >= 0) {
            int64_t loc = static_cast<int64_t>(region.start) + idx;
            auto relative = Algorithm::ReadAs<int32_t>(ph, loc + 8);
            auto gWorldAddr = loc + relative + 12;

            printf("[*] Found GWorld: 0x%lx\n", gWorldAddr);
            gProfile.GWorldOffset = toOffset(gWorldAddr, moduleBase);
            return true;
        }
    }

    // Method 2: String reference
    const wchar_t* str = L"Failed to load package '%s' into a new game world.";
    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str,
            static_cast<int64_t>(region.start), 3, "Searching for GWorld");

        if (strAddr) {
            // Look for MOV instructions that store GWorld pointer
            // 48 89 1D / 48 89 2D / 4C 89 2D / 4C 89 1D / 48 89 15
            std::vector<std::vector<uint8_t>> movPatterns = {
                {0x48, 0x89, 0x1D}, {0x48, 0x89, 0x2D},
                {0x4C, 0x89, 0x2D}, {0x4C, 0x89, 0x1D},
                {0x48, 0x89, 0x15}
            };

            int64_t lastFound = 0;
            for (auto& pat : movPatterns) {
                auto mov = Algorithm::ScanFor(ph, strAddr, pat, false, 300);
                if (mov >= 0) {
                    printf("[*] Possible GWorld reference at 0x%lx\n", mov);
                    lastFound = mov;
                }
            }

            if (lastFound > 0) {
                auto relative = Algorithm::ReadAs<int32_t>(ph, lastFound + 3);
                auto gWorldAddr = lastFound + relative + 7;
                printf("[*] Found GWorld: 0x%lx\n", gWorldAddr);
                gProfile.GWorldOffset = toOffset(gWorldAddr, moduleBase);
                return true;
            }
        }
    }
    return false;
}
#endif

#if PLATFORM_ARM64
bool findARM64(const ProcessHandle& ph, int64_t moduleBase) {
    // ARM64 GWorld detection
    // Look for "Failed to load package '%s' into a new game world." string
    // The GWorld store on ARM64 is typically: ADRP + ADD + STR

    const char* str = "Failed to load package '%s' into a new game world.";

    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        if (region.size() < 1024) continue;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str,
            static_cast<int64_t>(region.start), "Searching for GWorld");

        if (strAddr) {
            printf("[*] Found GWorld string ref at 0x%lx\n", strAddr);

            // Near the string ref, look for ADRP + ADD pair that might be GWorld store
            for (int64_t addr = strAddr - 0x200; addr < strAddr + 0x100; addr += 4) {
                uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);
                if (isADRP(insn)) {
                    int rd = getRd(insn);
                    uint64_t pageAddr = decodeADRP(insn, addr);

                    // Look for following STR/ADD using same register pair
                    for (int64_t a2 = addr + 4; a2 < addr + 20; a2 += 4) {
                        uint32_t insn2 = Algorithm::ReadAs<uint32_t>(ph, a2);
                        if (isADD_imm(insn2) && getRd(insn2) == rd && getRn(insn2) == rd) {
                            uint64_t gWorldAddr = pageAddr + decodeADD_imm(insn2);

                            // Verify: GWorld is in data section
                            auto* reg = ph.findRegion(gWorldAddr);
                            if (reg && !reg->isExecutable()) {
                                printf("[*] Found GWorld (ARM64): 0x%lx\n", gWorldAddr);
                                gProfile.GWorldOffset = toOffset(gWorldAddr, moduleBase);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}
#endif

} // namespace WorldScanner

// ═══════════════════════════════════════════════════════════════════════
//  FUNCTION ADDRESS FINDER
// ═══════════════════════════════════════════════════════════════════════

namespace FunctionFinder {

#if PLATFORM_X86_64

int64_t findStaticLoadObject(const ProcessHandle& ph,
                              const std::vector<uint8_t>& buffer,
                              int64_t regionBase) {
    const wchar_t* str = L"Failed to find object '{ClassName} {OuterName}.{ObjectName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase, 3,
        "UObject::StaticLoadObject()");
    if (strAddr) {
        // Scan backward for push r14; push r15 pattern
        auto pushStaticLoad = Algorithm::ScanFor(ph, strAddr,
            {0x41, 0x56, 0x41, 0x57, 0x48}, true);
        // Scan backward ~12 bytes from pushStaticLoad for push rbp
        auto funcAddr = Algorithm::ScanFor(ph, pushStaticLoad,
            {0x40, 0x55}, true, 12);
        printf("[*] StaticLoadObject: 0x%lx\n", funcAddr);
        gProfile.StaticLoadObjectOffset = toOffset(funcAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return funcAddr;
    }
    return 0;
}

int64_t findSpawnActor(const ProcessHandle& ph,
                        const std::vector<uint8_t>& buffer,
                        int64_t regionBase) {
    const wchar_t* str = L"SpawnActor failed.";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase, 3,
        "UWorld::SpawnActor()");
    if (strAddr) {
        // Find the CALL to SpawnActor function
        auto callSpawnActor = Algorithm::ScanFor(ph, strAddr, {0xE8}, true, 20);
        auto relative = Algorithm::ReadAs<int32_t>(ph, callSpawnActor + 1);
        auto fnAddr = callSpawnActor + relative + 5;

        if (gProfile.EngineVersion / 100 <= 408) {
            printf("[*] SpawnActorFVector: 0x%lx (old engine)\n", fnAddr);
            gProfile.SpawnActorFTransOffset = toOffset(fnAddr,
                static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fnAddr;
        }

        // Follow jumps
        Algorithm::CheckNSkipJump(ph, fnAddr, fnAddr);
        // Look for return (5B C3 = pop rbx; ret)
        auto retnAddr = Algorithm::ScanFor(ph, fnAddr, {0x5B, 0xC3}, false, 192);
        // After return, find call to SpawnActorTransform
        auto callTransform = Algorithm::ScanFor(ph, retnAddr,
            {0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0xFF, 0xFF, 0xFF, 0xFF, 0x48}, true, 30);
        auto rel = Algorithm::ReadAs<int32_t>(ph, callTransform + 1);
        auto transformAddr = callTransform + rel + 5;
        Algorithm::CheckNSkipJump(ph, transformAddr, transformAddr);

        printf("[*] SpawnActorFTransform: 0x%lx\n", transformAddr);
        gProfile.SpawnActorFTransOffset = toOffset(transformAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return transformAddr;
    }
    return 0;
}

int64_t findCallFunctionByNameWithArguments(const ProcessHandle& ph,
                                             const std::vector<uint8_t>& buffer,
                                             int64_t regionBase) {
    const wchar_t* str = L"'{Message}': Bad or missing property '{PropertyName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase, 3,
        "UObject::CallFunctionByNameWithArguments()");
    if (strAddr) {
        auto pushCFn = Algorithm::ScanFor(ph, strAddr,
            {0x41, 0x56, 0x41, 0x57, 0x48}, true, 3500);
        auto funcAddr = Algorithm::ScanFor(ph, pushCFn, {0x40, 0x55}, true, 0x40);
        printf("[*] CallFunctionByNameWithArguments: 0x%lx\n", funcAddr);
        gProfile.CallFunctionByNameWithArgumentsOffset = toOffset(funcAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return funcAddr;
    }
    return 0;
}

int64_t findInitGameState(const ProcessHandle& ph,
                           const std::vector<uint8_t>& buffer,
                           int64_t regionBase) {
    // Pattern 1
    auto begin = Algorithm::searchArray(buffer,
        {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x41, 0x10,
         0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x91}, false);
    if (begin >= 0) {
        auto fnAddr = regionBase + begin;
        printf("[*] InitGameState: 0x%lx\n", fnAddr);
        gProfile.GameStateInitOffset = toOffset(fnAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fnAddr;
    }

    // Pattern 2 (fallback)
    begin = Algorithm::searchArray(buffer,
        {0x48, 0xFF, 0xFF, 0xFF, 0x90, 0xFF, 0xFF, 0xFF, 0xFF, 0x48,
         0x8B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0x48, 0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0x48, 0x8B}, false);
    if (begin >= 0) {
        auto movAddr = regionBase + begin;
        auto fnAddr = Algorithm::ScanFor(ph, movAddr, {0x40, 0x53}, true, 100);
        printf("[*] InitGameState: 0x%lx\n", fnAddr);
        gProfile.GameStateInitOffset = toOffset(fnAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fnAddr;
    }
    return 0;
}

int64_t findBeginPlay(const ProcessHandle& ph,
                       const std::vector<uint8_t>& buffer,
                       int64_t regionBase) {
    auto begin = Algorithm::searchArray(buffer,
        {0x48, 0x8B, 0xD9, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xF6, 0x83,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x74, 0x12, 0x48, 0x8B, 0x03}, false);
    if (begin >= 0) {
        auto fnAddr = regionBase + begin;
        printf("[*] BeginPlay: 0x%lx\n", fnAddr);
        gProfile.BeginPlayOffset = toOffset(fnAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fnAddr;
    }
    return 0;
}

int64_t findProcessEvent(const ProcessHandle& ph,
                          const std::vector<uint8_t>& buffer,
                          int64_t regionBase) {
    // ProcessEvent is identifiable via its unique prologue + vtable offset
    // Pattern: push many regs, large stack frame, specific control flow
    auto begin = Algorithm::searchArray(buffer,
        {0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
         0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC}, false);
    if (begin >= 0) {
        auto fnAddr = regionBase + begin;
        printf("[*] ProcessEvent: 0x%lx\n", fnAddr);
        gProfile.ProcessEventOffset = toOffset(fnAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fnAddr;
    }
    return 0;
}

#endif // PLATFORM_X86_64

#if PLATFORM_ARM64

// ARM64 function prologue detection helper
static int64_t findARM64FunctionEntry(const ProcessHandle& ph, int64_t searchAddr) {
    // Scan backward from searchAddr looking for ARM64 prologue
    for (int64_t addr = searchAddr - 0x200; addr < searchAddr; addr += 4) {
        uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);
        // STP X29, X30, [SP, #...]!
        if ((insn & 0xFFC0FFFF) == 0xA9007BFD) {
            return addr;
        }
        // STP with other regs: STP Xn, Xm, [SP, #...]!
        if ((insn & 0xFF800000) == 0xA9000000) {
            // Could be function entry - check if it looks like a prologue
            uint32_t nextInsn = Algorithm::ReadAs<uint32_t>(ph, addr + 4);
            if (isADD_imm(nextInsn) && getRd(nextInsn) == 29 && getRn(nextInsn) == 31) {
                // MOV X29, SP (ADD X29, XZR/SP, #0)
                return addr;
            }
        }
        // SUB SP, SP, #imm (large stack frame start)
        if ((insn & 0xFF000000) == 0xD1000000) {
            uint32_t prevInsn = Algorithm::ReadAs<uint32_t>(ph, addr - 4);
            if ((prevInsn & 0xFF800000) == 0xA9000000) {
                return addr - 4;
            }
        }
    }
    return 0;
}

int64_t findStaticLoadObjectARM64(const ProcessHandle& ph,
                                   const std::vector<uint8_t>& buffer,
                                   int64_t regionBase) {
    const char* str = "Failed to find object '{ClassName} {OuterName}.{ObjectName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase,
        "UObject::StaticLoadObject()");
    if (strAddr) {
        // Find the function entry before the string reference
        auto fnAddr = findARM64FunctionEntry(ph, strAddr);
        if (fnAddr) {
            printf("[*] StaticLoadObject (ARM64): 0x%lx\n", fnAddr);
            gProfile.StaticLoadObjectOffset = toOffset(fnAddr,
                static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fnAddr;
        }
    }
    return 0;
}

int64_t findSpawnActorARM64(const ProcessHandle& ph,
                             const std::vector<uint8_t>& buffer,
                             int64_t regionBase) {
    const char* str = "SpawnActor failed.";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase,
        "UWorld::SpawnActor()");
    if (strAddr) {
        // Look for BL (branch-and-link) calls near the string ref
        // The function wrapping SpawnActor typically has a BL to the actual impl
        // Scan backward for function entry
        auto fnAddr = findARM64FunctionEntry(ph, strAddr);
        if (fnAddr) {
            printf("[*] SpawnActorFTransform (ARM64): 0x%lx\n", fnAddr);
            gProfile.SpawnActorFTransOffset = toOffset(fnAddr,
                static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fnAddr;
        }
    }
    return 0;
}

int64_t findCallFunctionByNameARM64(const ProcessHandle& ph,
                                     const std::vector<uint8_t>& buffer,
                                     int64_t regionBase) {
    const char* str = "'{Message}': Bad or missing property '{PropertyName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase,
        "UObject::CallFunctionByNameWithArguments()");
    if (strAddr) {
        auto fnAddr = findARM64FunctionEntry(ph, strAddr);
        if (fnAddr) {
            printf("[*] CallFunctionByNameWithArguments (ARM64): 0x%lx\n", fnAddr);
            gProfile.CallFunctionByNameWithArgumentsOffset = toOffset(fnAddr,
                static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fnAddr;
        }
    }
    return 0;
}

int64_t findInitGameStateARM64(const ProcessHandle& ph,
                                const std::vector<uint8_t>& buffer,
                                int64_t regionBase) {
    // ARM64: Scan for AGameState::InitGameState prologue pattern
    // STP + SUB SP, SP, imm + ...
    // This is the ARM64 equivalent of:
    // 40 53             push rbx
    // 48 83 EC 20       sub rsp, 20
    // 48 8B 41 10       mov rax, [rcx+10]
    // 48 8B D9          mov rbx, rcx
    // 48 8B 91 ...      mov rdx, [rcx+...]

    // On ARM64, the pattern translates to:
    // STP X..., X..., [SP, #-0x...]!
    // LDR X..., [X0, #0x10]
    // ...uses X0 and loads member at offset 0x10

    const std::vector<uint8_t> pattern = {
        0xFD, 0x7B, 0xBF, 0xA9,  // STP X29, X30, [SP, #-0x10]!
        0xFD, 0x03, 0x00, 0x91,  // MOV X29, SP
        0xFF, 0xFF, 0xFF, 0xFF,  // variable
        0xFF, 0xFF, 0xFF, 0xFF,  // variable
        0xFF, 0xFF, 0x40, 0xF9,  // LDR X?, [X0, #0x10] (offset 0x10 = this->GameStateClass)
    };

    auto begin = Algorithm::searchArray(buffer, pattern, false);
    if (begin >= 0) {
        auto fnAddr = regionBase + begin;
        printf("[*] InitGameState (ARM64): 0x%lx\n", fnAddr);
        gProfile.GameStateInitOffset = toOffset(fnAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fnAddr;
    }
    return 0;
}

int64_t findBeginPlayARM64(const ProcessHandle& ph,
                            const std::vector<uint8_t>& buffer,
                            int64_t regionBase) {
    // ARM64: Scan for AActor::BeginPlay prologue
    // On x86_64: 48 8B D9 E8 xx xx xx xx F6 83 xx xx xx xx xx 74 12 48 8B 03
    //          = mov rbx, rcx; call ...; test byte [rbx+...]; jz ...; mov rax, [rbx]
    //
    // On ARM64, this would look like:
    // STP X29, X30, [SP, #...]!
    // MOV X29, SP
    // STR X0, [SP, #var]        ; save 'this'
    // BL  <isPendingKill>       ; call
    // LDRB Wx, [X0, #offset]    ; test byte
    // ...

    const std::vector<uint8_t> pattern = {
        0xFD, 0x7B, 0xFF, 0xA9,  // STP X29, X30, [SP, #imm]! (variable immediate)
        0xFD, 0x03, 0x00, 0x91,  // MOV X29, SP
        0xFF, 0xFF, 0xFF, 0xFF,  // variable instructions
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0x94,  // BL ... (function call - isPendingKill check)
    };

    auto begin = Algorithm::searchArray(buffer, pattern, false);
    if (begin >= 0) {
        auto fnAddr = regionBase + begin;
        printf("[*] BeginPlay (ARM64): 0x%lx\n", fnAddr);
        gProfile.BeginPlayOffset = toOffset(fnAddr,
            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fnAddr;
    }
    return 0;
}

int64_t findProcessEventARM64(const ProcessHandle& ph,
                               const std::vector<uint8_t>& buffer,
                               int64_t regionBase) {
    // ARM64 ProcessEvent: very large function with big stack frame
    // Typically starts with: STP X29, X30, [SP, #-0x80]!  ; save FP/LR
    //                        SUB SP, SP, #0x...           ; big stack frame
    // Known ARM64 encoding for ProcessEvent prologue:
    // FD 7B 0x A9 (STP with large negative offset, e.g., -0x70 or -0x80)

    // Try scanning for large stack frame prologues
    for (size_t i = 0; i + 16 < buffer.size(); i += 4) {
        uint32_t insn = *(uint32_t*)(&buffer[i]);
        // STP X29, X30 with pre-index (large stack frame)
        if ((insn & 0xFFC0FFFF) == 0xA9007BFD) {
            // Check for SUB SP instruction shortly after
            for (size_t j = i + 4; j < std::min(i + 20, buffer.size()); j += 4) {
                uint32_t subInsn = *(uint32_t*)(&buffer[j]);
                // SUB SP, SP, #large_imm
                if ((subInsn & 0xFF000000) == 0xD1000000) {
                    // Check that the subtract is significant (big stack frame)
                    uint32_t imm = (subInsn >> 10) & 0xFFF;
                    if (imm >= 0x20) {  // At least 32 bytes stack frame
                        // Potentially ProcessEvent
                        auto fnAddr = regionBase + i;
                        printf("[*] ProcessEvent candidate (ARM64): 0x%lx (stack=0x%x)\n", fnAddr, imm);
                        // For now, report the first large function found
                        gProfile.ProcessEventOffset = toOffset(fnAddr,
                            static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                        return fnAddr;
                    }
                }
            }
        }
    }
    return 0;
}

#endif // PLATFORM_ARM64

// ─── Main scan orchestrator ───────────────────────────────────────────
bool scanAll(const ProcessHandle& ph) {
    auto* mod = ph.findUE4Module();
    if (!mod) {
        fprintf(stderr, "[!] No UE4 module found\n");
        return false;
    }
    int64_t base = static_cast<int64_t>(mod->baseAddress);
    printf("[*] Target: %s (base=0x%lx, size=0x%zx)\n", mod->name.c_str(), base, mod->size);

    std::atomic<int> foundCount{0};
    const int TARGET_COUNT = 7; // GNames, GObjects, GWorld + 4 functions (StaticLoadObject, SpawnActor, CallFunction, BeginPlay)

    // Process each readable+executable region
    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        if (gSearchComplete) break;

        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;

        int64_t regionBase = static_cast<int64_t>(region.start);

#if PLATFORM_X86_64
        findStaticLoadObject(ph, buffer, regionBase);
        findSpawnActor(ph, buffer, regionBase);
        findCallFunctionByNameWithArguments(ph, buffer, regionBase);
        findInitGameState(ph, buffer, regionBase);
        findBeginPlay(ph, buffer, regionBase);
        findProcessEvent(ph, buffer, regionBase);
#endif

#if PLATFORM_ARM64
        findStaticLoadObjectARM64(ph, buffer, regionBase);
        findSpawnActorARM64(ph, buffer, regionBase);
        findCallFunctionByNameARM64(ph, buffer, regionBase);
        findInitGameStateARM64(ph, buffer, regionBase);
        findBeginPlayARM64(ph, buffer, regionBase);
        findProcessEventARM64(ph, buffer, regionBase);
#endif
    }

    // Run object/world finders (x86_64)
#if PLATFORM_X86_64
    ObjectScanner::findX86_64(ph, base);
    WorldScanner::findX86_64(ph, base);
#endif

#if PLATFORM_ARM64
    ObjectScanner::findARM64(ph, base);
    WorldScanner::findARM64(ph, base);
#endif

    gSearchComplete = true;
    return true;
}

} // namespace FunctionFinder

// ═══════════════════════════════════════════════════════════════════════
//  MAIN SCANNING ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════

inline bool scanUE4(const ProcessHandle& ph, int engineVersion) {
    if (engineVersion > 0) {
        gProfile.EngineVersion = engineVersion;
        gProfile.IsUsing4_22 = (engineVersion / 100 == 422);
        gProfile.IsUsingFChunkedFixedUObjectArray = (engineVersion / 100 >= 418);
        gProfile.UseFNamePool = (engineVersion / 100 >= 423);
        printf("[*] Using specified engine version: %d\n", engineVersion);
    } else {
        // Try auto-detection
#if PLATFORM_X86_64
        if (!EngineVersion::detectX86_64(ph,
                static_cast<int64_t>(ph.findUE4Module()->baseAddress),
                ph.findUE4Module()->size)) {
            printf("[-] Could not auto-detect engine version\n");
            printf("[!] Please re-run with --ue4-version <ver> (e.g. 426 for 4.26)\n");
        }
#endif
#if PLATFORM_ARM64
        if (!EngineVersion::detectARM64(ph,
                static_cast<int64_t>(ph.findUE4Module()->baseAddress),
                ph.findUE4Module()->size)) {
            printf("[-] Could not auto-detect engine version\n");
            printf("[!] Please re-run with --ue4-version <ver> (e.g. 426 for 4.26)\n");
        }
#endif
    }

    // Step 1: Find GNames / FNamePool
    NameScanner::find(ph,
        static_cast<int64_t>(ph.findUE4Module()->baseAddress),
        ph.findUE4Module()->size);

    // Step 2: Find all function addresses
    FunctionFinder::scanAll(ph);

    return true;
}
