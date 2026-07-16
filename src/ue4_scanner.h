/*
 * ue4_scanner.h - UE4 engine address scanner
 *
 * ARM64 + x86_64 AOB signature scanning for GNames, GObjects, GWorld,
 * and key function addresses.
 *
 * Supports UE4 4.8 – 4.27 on Android (ARM64) and PC (x86_64).
 */

#pragma once
#include "linux_memory.h"
#include "algorithm.h"
#include "profile.h"
#include "offsets.h"
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>

static std::atomic<bool> gSearchComplete{false};

static int64_t toOffset(int64_t addr, int64_t base) { return addr - base; }

// ═══════════════════════════════════════════════════════════════════════
//  ARM64 HELPERS
// ═══════════════════════════════════════════════════════════════════════

#if PLATFORM_ARM64

// Find the function entry (STP X29,X30 prologue) before a given address
static int64_t findARM64Prologue(const ProcessHandle& ph, int64_t addr, int64_t maxScanBack) {
    for (int64_t cur = addr & ~3ull; cur > addr - maxScanBack; cur -= 4) {
        uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, cur);
        // STP X29, X30, [SP, #imm]!  pre-index  → 0xA9..7BFD
        if ((insn & 0xFFC0FFFF) == 0xA9007BFD) return cur;
        // STP Xn, Xm, [SP, #imm]! generic
        if ((insn & 0xFF800000) == 0xA9000000) {
            uint32_t next = Algorithm::ReadAs<uint32_t>(ph, cur + 4);
            if (isADD_imm(next) && getRd(next) == 29 && getRn(next) == 31)
                return cur; // MOV X29, SP after STP
        }
    }
    return 0;
}

// Try to resolve an ADRP at `pc` to an absolute address
static uint64_t resolveADRP(const ProcessHandle& ph, uint64_t pc, uint32_t insn) {
    uint64_t page = decodeADRP(insn, pc);
    int rd = getRd(insn);
    // Look ahead for ADD imm with same Rd
    for (uint64_t nxt = pc + 4; nxt < pc + 24; nxt += 4) {
        uint32_t ni = Algorithm::ReadAs<uint32_t>(ph, nxt);
        if (isADD_imm(ni) && getRd(ni) == rd && getRn(ni) == rd) {
            return page + decodeADD_imm(ni);
        }
    }
    // No ADD found; just return the 4K-aligned page
    return page;
}

// Check if a byte sequence looks like a valid "None" string (first GNames entry)
static bool isNoneString(const char* buf, int len) {
    if (len < 4) return false;
    for (int off = 0; off <= 4 && off + 3 < len; off++) {
        if (*(uint32_t*)(buf + off) == 0x656E6F4E) return true; // "None"
    }
    return false;
}

#endif // PLATFORM_ARM64

// ═══════════════════════════════════════════════════════════════════════
//  ENGINE VERSION DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace EngineVersion {

#if PLATFORM_X86_64
bool detectX86_64(const ProcessHandle& ph, int64_t moduleBase, size_t moduleSize) {
    const char16_t* targetStr = u"%sunreal-v%i-%s.dmp";
    for (const auto& region : ph.regions) {
        if (!region.isReadable() || region.path.empty()) continue;
        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;
        auto foundAddr = Algorithm::ScanforStringRef(ph, buffer, targetStr,
            static_cast<int64_t>(region.start), 3, "GetEngineVersion()");
        if (foundAddr) {
            if (auto leaAddr = Algorithm::ScanFor(ph, foundAddr,
                    {0x48,0x8D,0xFF,0xFF,0xFF,0xFF,0xFF,0xE8}, true, 36)) {
                auto rel = Algorithm::ReadAs<int32_t>(ph, leaAddr + 3);
                auto gv = leaAddr + rel + 7;
                int16_t major = Algorithm::ReadAs<int16_t>(ph, gv);
                int16_t minor = Algorithm::ReadAs<int16_t>(ph, gv + 2);
                int16_t patch = Algorithm::ReadAs<int16_t>(ph, gv + 4);
                int ver = major * 10000 + minor * 100 + patch;
                printf("[*] Engine Version: %d.%d.%d (%d)\n", major, minor, patch, ver);
                gProfile.EngineVersion = ver;
                gProfile.IsUsing4_22 = (ver / 100 == 422);
                gProfile.IsUsingFChunkedFixedUObjectArray = (ver / 100 >= 418);
                gProfile.UseFNamePool = (ver / 100 >= 423);
                return true;
            }
        }
    }
    return false;
}
#endif

#if PLATFORM_ARM64
// Simple UE4 version string search in rodata
bool detectARM64(const ProcessHandle& ph, int64_t moduleBase, size_t moduleSize) {
    // Look for the engine version macro string in rodata
    // Common strings: "4.18", "4.19", etc. in the build metadata
    const char* versionStrs[] = {
        "4.27", "4.26", "4.25", "4.24", "4.23", "4.22", "4.21", "4.20",
        "4.19", "4.18", "4.17", "4.16", "4.15", "4.14", "4.13", "4.12",
        "4.11", "4.10", "4.9", "4.8", nullptr
    };

    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        std::vector<uint8_t> buf(std::min(region.size(), (size_t)0x400000));
        if (!ph.readMemory(region.start, buf.data(), buf.size())) continue;

        for (int vi = 0; versionStrs[vi]; vi++) {
            size_t slen = strlen(versionStrs[vi]);
            // Simple linear scan for version substring
            for (size_t pos = 0; pos + slen < buf.size(); pos++) {
                if (memcmp(&buf[pos], versionStrs[vi], slen) == 0) {
                    // Check context: should be near "UE4" or "Engine"
                    int major = (versionStrs[vi][0]-'0')*10 + (versionStrs[vi][2]-'0');
                    int patch = (versionStrs[vi][3]-'0');
                    int ver = major * 10000 + (patch * 100); // approximate

                    // Refine with full version string nearby
                    printf("[*] Engine version detected: ~%s (ver=%d)\n", versionStrs[vi], ver);
                    gProfile.EngineVersion = ver;
                    gProfile.IsUsing4_22 = (major == 4 && patch == 22);
                    gProfile.IsUsingFChunkedFixedUObjectArray = (ver / 100 >= 418);
                    gProfile.UseFNamePool = (ver / 100 >= 423);
                    return true;
                }
            }
        }
    }
    printf("[-] Could not auto-detect engine version\n");
    return false;
}
#endif

} // namespace EngineVersion

// ═══════════════════════════════════════════════════════════════════════
//  GNames / FNamePool DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace NameScanner {

static std::atomic<bool> gFound{false};

#if PLATFORM_X86_64
// (x86_64 methods kept from original — see full file for details)
bool method1_x86(const ProcessHandle& ph, const MemoryRegion& region) {
    if (gFound) return false;
    std::vector<uint8_t> buffer(region.size());
    if (!ph.readMemory(region.start, buffer.data(), region.size())) return false;
    const char16_t* str = u"Hardcoded name '%s' at index %i was duplicated (or unexpected concurrency). Existing entry is '%s'.";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str,
        static_cast<int64_t>(region.start), 3, "FName::GetNames()");
    if (strAddr) {
        auto beforeCall = Algorithm::ScanFor(ph, strAddr,
            {0xBA,0x01,0x00,0x00,0x00,0x48,0x8B,0xC8,0xE8}, true);
        if (beforeCall >= 0) {
            auto callGetName = Algorithm::ScanFor(ph, beforeCall,
                {0xE8,0xFF,0xFF,0xFF,0xFF,0xFF,0x8B}, true, 70);
            if (callGetName >= 0) {
                int32_t relative = Algorithm::ReadAs<int32_t>(ph, callGetName + 1);
                auto getNameFn = callGetName + relative + 5;
                auto movGNames = Algorithm::ScanFor(ph, getNameFn, {0x48,0x8B}, false, 50);
                if (movGNames >= 0) {
                    int32_t rel = Algorithm::ReadAs<int32_t>(ph, movGNames + 3);
                    auto gns = movGNames + 3 + rel + 4;
                    printf("[*] Found GNames: 0x%lx\n", gns);
                    gProfile.GNameOffset = toOffset(gns, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                    gFound = true;
                    return true;
                }
            }
        }
    }
    return false;
}

bool method2_x86(const ProcessHandle& ph, const MemoryRegion& region) {
    if (gFound) return false;
    size_t nq = region.size() / 8;
    std::vector<int64_t> buf(nq);
    if (!ph.readMemory(region.start, buf.data(), region.size() & ~7ull)) return false;
    for (size_t i = 0; i < buf.size() && !gFound; i++) {
        int64_t p1 = buf[i]; if (!p1) continue;
        int64_t n1 = Algorithm::ReadAs<int64_t>(ph, p1); if (!n1) continue;
        int64_t nia = Algorithm::ReadAs<int64_t>(ph, n1); if (!nia) continue;
        nia += 0xC;
        uint8_t nc[16]; if (!ph.readMemory(nia, nc, sizeof(nc))) continue;
        for (int bi=0; bi<=4; bi++) {
            if (*(uint32_t*)(&nc[bi]) == 0x656E6F4E) {
                auto gns = static_cast<int64_t>(region.start) + i * 8;
                int64_t ep = Algorithm::ReadAs<int64_t>(ph, gns);
                int64_t fe = Algorithm::ReadAs<int64_t>(ph, ep);
                char an[32]={}; ph.readMemory(fe+0x10, an, sizeof(an));
                if (strcmp(an,"None")!=0){ printf("[-] False GNames 0x%lx ('%s')\n",gns,an); continue; }
                printf("[*] Found GNames (m2): 0x%lx\n", gns);
                gProfile.GNameOffset = toOffset(gns, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                gFound = true; return true;
            }
        }
    }
    return false;
}
#endif // PLATFORM_X86_64

// ─── ARM64 GNames (TNameEntryArray, pre-4.23) ──────────────────────
#if PLATFORM_ARM64

// Method A: scan for TNameEntryArray pattern in data sections
// Structure: array of 8-byte pointers to FNameEntry chunks (0x4000 entries each)
// Per SDK Offsets.h: TNameEntryArray = getPtr(GNames) or getPtr(getPtr(GNames))
// UE 4.22: Index@0x8, Name@0xC  |  UE 4.18: Index@0x0, Name@0x10
bool scanTNameEntryArray(const ProcessHandle& ph, const MemoryRegion& region, int64_t modBase) {
    if (gFound) return false;

    // Determine correct offsets based on engine version
    int nameOffset, indexOffset;
    if (gProfile.IsUsing4_22) {
        nameOffset = 0xC;   // 4.22+
        indexOffset = 0x8;
    } else {
        nameOffset = 0x10;  // pre-4.22
        indexOffset = 0x0;
    }
    // Also try alternate: some games use 0xC even pre-4.22 (PUBG etc.)

    size_t nq = region.size() / 8;
    if (nq > 0x200000) nq = 0x200000;

    std::vector<int64_t> buf(nq);
    if (!ph.readMemory(region.start, buf.data(), nq * 8)) return false;

    for (size_t i = 0; i < buf.size() && !gFound; i++) {
        int64_t chunkPtr = buf[i];
        if (!chunkPtr || chunkPtr < modBase || chunkPtr > modBase + 0x20000000) continue;

        int64_t entry0Ptr = Algorithm::ReadAs<int64_t>(ph, chunkPtr);
        int64_t entry1Ptr = Algorithm::ReadAs<int64_t>(ph, chunkPtr + 8);
        if (!entry0Ptr || !entry1Ptr) continue;

        // Try name offsets: primary (version-dependent), then alternate
        std::vector<int> nameOffsets = {nameOffset};
        if (nameOffset == 0xC) nameOffsets.push_back(0x10);
        else nameOffsets.push_back(0xC);

        for (int nOff : nameOffsets) {
            int32_t idx0 = Algorithm::ReadAs<int32_t>(ph, entry0Ptr + indexOffset);
            char name0[32] = {};
            ph.readMemory(entry0Ptr + nOff, name0, sizeof(name0));

            if (idx0 == 0 && strcmp(name0, "None") == 0) {
                int32_t idx1 = Algorithm::ReadAs<int32_t>(ph, entry1Ptr + indexOffset);
                char name1[32] = {};
                ph.readMemory(entry1Ptr + nOff, name1, sizeof(name1));

                if (idx1 == 1 && strlen(name1) > 0) {
                    // Found valid TNameEntryArray chunk
                    // The direct GNames pointer = region.start + i*8
                    // BUT some games need: TNameEntryArray = getPtr(GNames) (extra deref)
                    // OR: TNameEntryArray = getPtr(getPtr(GNames)) (double deref)

                    auto directAddr = static_cast<int64_t>(region.start) + i * 8;

                    // Check: does directAddr point to chunkPtr? (indirect case)
                    // If *directAddr == chunkPtr, then GNames is indirect (needs one deref)
                    // If directAddr itself IS the chunk array, it's direct

                    // Try indirect first (GNames → ptr → TNameEntryArray[0])
                    int64_t indirectVal = Algorithm::ReadAs<int64_t>(ph, directAddr);
                    if (indirectVal == chunkPtr) {
                        // GNames is a pointer TO the TNameEntryArray
                        printf("[*] TNameEntryArray chunk at 0x%lx (indirect, nameOff=0x%x, entry[1]=%s)\n",
                               chunkPtr, nOff, name1);
                        printf("[*] GNames: 0x%lx (derefs to 0x%lx)\n", directAddr, chunkPtr);
                        gProfile.GNameOffset = toOffset(directAddr, modBase);
                        gProfile.UseFNamePool = false;
                        gFound = true;
                        return true;
                    }

                    // Try double-indirect (GNames → ptr → ptr → chunk)
                    int64_t indirect2 = Algorithm::ReadAs<int64_t>(ph, indirectVal);
                    if (indirect2 == chunkPtr) {
                        printf("[*] TNameEntryArray chunk at 0x%lx (double-indirect, nameOff=0x%x, entry[1]=%s)\n",
                               chunkPtr, nOff, name1);
                        printf("[*] GNames: 0x%lx → 0x%lx → 0x%lx\n", directAddr, indirectVal, chunkPtr);
                        gProfile.GNameOffset = toOffset(directAddr, modBase);
                        gProfile.UseFNamePool = false;
                        gFound = true;
                        return true;
                    }

                    // Try direct (chunk IS at directAddr)
                    if (chunkPtr == directAddr) {
                        printf("[*] TNameEntryArray direct at 0x%lx (nameOff=0x%x, entry[1]=%s)\n",
                               directAddr, nOff, name1);
                        printf("[*] GNames: 0x%lx (direct)\n", directAddr);
                        gProfile.GNameOffset = toOffset(directAddr, modBase);
                        gProfile.UseFNamePool = false;
                        gFound = true;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// Method B: find via string reference to "Failed to load package" (often near GWorld,
// and GWorld references are co-located with GNames in the same data region)
bool scanViaStringRef(const ProcessHandle& ph, const MemoryRegion& region, int64_t modBase) {
    if (gFound) return false;

    std::vector<uint8_t> buffer(region.size());
    if (!ph.readMemory(region.start, buffer.data(), region.size())) return false;

    // Try to find "Failed to find object" string (this is the StaticLoadObject error)
    const char* str = "Failed to find object '{ClassName} {OuterName}.{ObjectName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str,
        static_cast<int64_t>(region.start), "StaticLoadObject");

    if (!strAddr) {
        // Try shorter prefix
        strAddr = Algorithm::ScanforStringRef(ph, buffer,
            "Failed to find object",
            static_cast<int64_t>(region.start), "StaticLoadObject(short)");
    }

    if (strAddr) {
        printf("[*] Found StaticLoadObject string ref at 0x%lx\n", strAddr);
        // Find the function that references this string
        auto fnEntry = findARM64Prologue(ph, strAddr, 0x200);
        if (fnEntry) {
            // Inside this function, look for ADRP references to global data
            // StaticLoadObject accesses GNames to resolve class names
            for (int64_t cur = fnEntry; cur < strAddr + 0x300; cur += 4) {
                uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, cur);
                if (isADRP(insn)) {
                    uint64_t target = resolveADRP(ph, cur, insn);
                    // Check if target points into a data section
                    auto* tr = ph.findRegion(target);
                    if (tr && !tr->isExecutable() && tr->isReadable()) {
                        // Could be GNames — verify by reading first entry
                        int64_t firstPtr = Algorithm::ReadAs<int64_t>(ph, target);
                        if (firstPtr > modBase && firstPtr < modBase + 0x10000000) {
                            int64_t fe = Algorithm::ReadAs<int64_t>(ph, firstPtr);
                            if (fe > modBase) {
                                char nb[32] = {};
                                ph.readMemory(fe + 0x10, nb, sizeof(nb));
                                if (strcmp(nb, "None") == 0) {
                                    printf("[*] GNames (via string ref ADRP): 0x%lx\n", target);
                                    gProfile.GNameOffset = toOffset(target, modBase);
                                    gProfile.UseFNamePool = false;
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
    return false;
}

// Method C: brute-force scan for "None" string in data, trace back to GNames
bool scanBruteForce(const ProcessHandle& ph, const MemoryRegion& region, int64_t modBase) {
    if (gFound) return false;

    size_t scanSize = std::min(region.size(), (size_t)0x800000);
    std::vector<uint8_t> buf(scanSize);
    if (!ph.readMemory(region.start, buf.data(), scanSize)) return false;

    const uint8_t pattern[] = {'N','o','n','e'};
    std::vector<uint8_t> patVec(pattern, pattern + 4);

    // Find all occurrences of "None"
    std::vector<int64_t> noneOffsets;
    for (size_t pos = 0; pos + 4 <= buf.size(); pos++) {
        if (memcmp(&buf[pos], "None", 4) == 0) {
            noneOffsets.push_back(static_cast<int64_t>(region.start) + pos);
            if (noneOffsets.size() > 5000) break; // limit candidates
        }
    }

    printf("[*] Found %zu 'None' strings, checking candidates...\n", noneOffsets.size());

    int checked = 0;
    for (auto noneAddr : noneOffsets) {
        if (gFound || checked++ > 5000) break;

        // Check if this "None" is inside an FNameEntry (at offset 0x10)
        // FNameEntry starts at noneAddr - 0x10
        int64_t fNameEntry = noneAddr - 0x10;

        // Try offset 0xC (4.22+)
        int64_t fNameEntry22 = noneAddr - 0xC;

        for (int attempt = 0; attempt < 2; attempt++) {
            int64_t entryAddr = (attempt == 0) ? fNameEntry : fNameEntry22;
            if (entryAddr < modBase || entryAddr > modBase + 0x20000000) continue;

            int32_t idx = Algorithm::ReadAs<int32_t>(ph, entryAddr);
            if (idx != 0) continue; // Only entry 0 should have index 0

            // Now scan backward in data to find a pointer TO this entry's chunk
            // The chunk is: entryAddr rounded down (entries are 8-byte aligned pointers within chunk)
            // Actually, in TNameEntryArray, we have: TNameEntryArray[i] → chunkPtr → chunkPtr[j] → FNameEntry

            // For now, just report this candidate
            int64_t candidateGNames = 0;

            // Scan data sections for a pointer that points to a structure containing entryAddr
            for (const auto& r : ph.regions) {
                if (!r.isReadable() || r.isExecutable()) continue;
                size_t rnq = std::min(r.size() / 8, (size_t)0x80000);
                std::vector<int64_t> rbuf(rnq);
                if (!ph.readMemory(r.start, rbuf.data(), rnq * 8)) continue;

                for (size_t ri = 0; ri < rbuf.size(); ri++) {
                    if (rbuf[ri] == entryAddr - (entryAddr & 0x7)) { // pointer to nearby
                        // Verify this is a chunk pointer
                        int64_t gns = static_cast<int64_t>(r.start) + ri * 8;
                        // TNameEntryArray has consecutive chunk pointers
                        int64_t cp2 = Algorithm::ReadAs<int64_t>(ph, gns + 8);
                        if (cp2 && cp2 > modBase && cp2 < modBase + 0x10000000) {
                            printf("[*] GNames (brute force via 'None' at 0x%lx): 0x%lx\n", noneAddr, gns);
                            gProfile.GNameOffset = toOffset(gns, modBase);
                            gProfile.UseFNamePool = false;
                            gFound = true;
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

#endif // PLATFORM_ARM64

bool find(const ProcessHandle& ph, int64_t moduleBase, size_t moduleSize) {
    gFound = false;
    printf("[*] Searching for GNames/FNamePool...\n");

#if PLATFORM_X86_64
    std::vector<std::thread> threads;
    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        threads.emplace_back([&ph, &region]() { method1_x86(ph, region); });
    }
    for (auto& t : threads) t.join();
    if (!gFound) {
        printf("[*] Method 1 failed, trying brute-force...\n");
        threads.clear();
        for (const auto& region : ph.regions) {
            if (!region.isReadable()) continue;
            threads.emplace_back([&ph, &region]() { method2_x86(ph, region); });
        }
        for (auto& t : threads) t.join();
    }
#endif

#if PLATFORM_ARM64
    if (gProfile.UseFNamePool) {
        printf("[*] UE 4.23+ detected, scanning for FNamePool...\n");
        printf("[-] FNamePool ARM64 scanner not yet fully implemented\n");
    } else {
        // Pre-4.23 TNameEntryArray: try multiple methods
        printf("[*] Pre-4.23 detected, searching TNameEntryArray...\n");

        // Count scannable regions for debug
        int dataRegions = 0, codeRegions = 0;
        for (const auto& region : ph.regions) {
            if (region.isReadable() && !region.isExecutable()) dataRegions++;
            if (region.isReadable() && region.isExecutable()) codeRegions++;
        }
        printf("[*] Regions: %d data, %d code\n", dataRegions, codeRegions);

        // Method A: scan data sections for TNameEntryArray pattern
        printf("[*] Method A: TNameEntryArray pattern scan in data sections...\n");
        {
            std::vector<std::thread> threads;
            int scanned = 0;
            for (const auto& region : ph.regions) {
                if (gFound) break;
                if (!region.isReadable() || region.isExecutable()) continue;
                scanned++;
                printf("[*]   scanning data region 0x%lx-0x%lx (%zu MB)...\n",
                       region.start, region.end, region.size() / 1048576);
                threads.emplace_back([&ph, &region, moduleBase]() {
                    scanTNameEntryArray(ph, region, moduleBase);
                });
            }
            for (auto& t : threads) t.join();
            printf("[*] Method A scanned %d data regions, gFound=%d\n", scanned, (int)gFound);
        }

        // Method B: string reference scan in code sections
        if (!gFound) {
            printf("[*] Method B: string reference scan in code sections...\n");
            std::vector<std::thread> threads;
            int scanned = 0;
            for (const auto& region : ph.regions) {
                if (gFound) break;
                if (!region.isReadable() || !region.isExecutable()) continue;
                scanned++;
                threads.emplace_back([&ph, &region, moduleBase]() {
                    scanViaStringRef(ph, region, moduleBase);
                });
            }
            for (auto& t : threads) t.join();
            printf("[*] Method B scanned %d code regions, gFound=%d\n", scanned, (int)gFound);
        }

        // Method C: brute-force "None" scan in ALL readable regions
        if (!gFound) {
            printf("[*] Method C: brute-force scan in all readable regions...\n");
            int scanned = 0;
            for (const auto& region : ph.regions) {
                if (gFound) break;
                if (!region.isReadable()) continue;
                scanned++;
                printf("[*]   scanning region 0x%lx-0x%lx (%zu MB)...\n",
                       region.start, region.end, region.size() / 1048576);
                scanBruteForce(ph, region, moduleBase);
            }
            printf("[*] Method C scanned %d regions, gFound=%d\n", scanned, (int)gFound);
        }
    }
#endif

    if (gFound) printf("[+] GNames offset: 0x%lx\n", gProfile.GNameOffset);
    else printf("[-] GNames not found\n");
    return gFound;
}

} // namespace NameScanner

// ═══════════════════════════════════════════════════════════════════════
//  GOBJECTS DETECTION
// ═══════════════════════════════════════════════════════════════════════

namespace ObjectScanner {

#if PLATFORM_X86_64
bool findX86_64(const ProcessHandle& ph, int64_t moduleBase) {
    const std::vector<uint8_t> pattern = {
        0x8B,0x46,0x10,0x3B,0x46,0x3C,0x75,0x0F,
        0x48,0x8B,0xD6,0x48,0x8D,0x0D,0xFF,0xFF,0xFF,0xFF,0xE8
    };
    for (const auto& region : ph.regions) {
        if (!region.isReadable() || !region.isExecutable()) continue;
        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;
        int64_t idx = Algorithm::searchArray(buffer, pattern, false);
        if (idx >= 0) {
            int32_t rel = *(int32_t*)(&buffer[idx+14]);
            auto go = static_cast<int64_t>(region.start) + idx + 14 + rel + 4;
            printf("[*] Found GObjects: 0x%lx\n", go);
            gProfile.GObjectOffset = toOffset(go, moduleBase);
            return true;
        }
    }
    if (gProfile.SpawnActorFTransOffset != 0) {
        auto sa = moduleBase + gProfile.SpawnActorFTransOffset;
        auto cj = Algorithm::ScanFor(ph, sa, {0x3B,0x05,0xFF,0xFF,0xFF,0xFF,0x7D,0xFF}, false);
        auto lm = Algorithm::ScanFor(ph, cj, {0x48,0x8D,0xFF,0x40,0x48,0x8B,0x05,0xFF,0xFF,0xFF,0xFF}, false, 50) + 4;
        auto r1 = Algorithm::ReadAs<int32_t>(ph, cj+2);
        auto r2 = Algorithm::ReadAs<int32_t>(ph, lm+3);
        auto ne = cj+r1+6; auto of = lm+r2+7;
        auto off = ne - of;
        auto go = of - 0x10;
        gProfile.IsUsingFChunkedFixedUObjectArray = (off == 0x14);
        printf("[*] Found GObjects (via SpawnActor): 0x%lx\n", go);
        gProfile.GObjectOffset = toOffset(go, moduleBase);
        return true;
    }
    return false;
}
#endif

#if PLATFORM_ARM64
bool findARM64(const ProcessHandle& ph, int64_t moduleBase) {
    // For pre-4.23 TNameEntryArray era: GObjectArray is accessed via a global pointer
    // In the function that calls UObjectArray::GetObjectArray, look for ADRP that loads it
    if (gProfile.SpawnActorFTransOffset != 0) {
        auto sa = moduleBase + gProfile.SpawnActorFTransOffset;
        for (int64_t addr = sa; addr < sa + 0x300; addr += 4) {
            uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);
            if (isADRP(insn)) {
                uint64_t tgt = resolveADRP(ph, addr, insn);
                auto* tr = ph.findRegion(tgt);
                if (tr && !tr->isExecutable()) {
                    int64_t v0 = Algorithm::ReadAs<int64_t>(ph, tgt);
                    if (v0 > moduleBase && v0 < moduleBase + 0x10000000) {
                        int64_t vv = Algorithm::ReadAs<int64_t>(ph, v0);
                        if (vv > moduleBase) {
                            printf("[*] Found GObjects (ARM64 via SpawnActor): 0x%lx\n", tgt);
                            gProfile.GObjectOffset = toOffset(tgt, moduleBase);
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Fallback: scan for common GObjectArray access pattern in executable sections
    // ADRP Xn, page ; LDR Wm, [Xn, #off+0x10] ; LDR Wk, [Xn, #off+0x3C]
    for (const auto& region : ph.regions) {
        if (!region.isReadable() || !region.isExecutable()) continue;
        size_t nw = region.size() / 4;
        if (nw > 0x100000) nw = 0x100000;
        std::vector<uint32_t> buf(nw);
        if (!ph.readMemory(region.start, buf.data(), nw * 4)) continue;

        for (size_t i = 0; i + 8 < buf.size(); i++) {
            if (isADRP(buf[i])) {
                int rd = getRd(buf[i]);
                uint64_t page = decodeADRP(buf[i], region.start + i*4);
                // Look for ADD + two LDRs using the same base register
                for (size_t j = i+1; j < std::min(i+16, buf.size()); j++) {
                    if (isADD_imm(buf[j]) && getRd(buf[j]) == rd && getRn(buf[j]) == rd) {
                        uint64_t base = page + decodeADD_imm(buf[j]);
                        // Check for LDR Wx, [rd, #off1] and LDR Wy, [rd, #off2] pattern
                        for (size_t k = j+1; k < std::min(j+8, buf.size()); k++) {
                            // LDR Wt, [Xn, #imm12] = 0xB9400000 | (imm12<<10) | (Rn<<5) | Rt
                            if ((buf[k] & 0xFFC00000) == 0xB9400000) {
                                int rn = (buf[k] >> 5) & 0x1F;
                                if (rn == rd) { // using same base register
                                    auto* tr = ph.findRegion(base);
                                    if (tr && !tr->isExecutable()) {
                                        printf("[*] Found GObjects candidate (ARM64): 0x%lx\n", base);
                                        gProfile.GObjectOffset = toOffset(base, moduleBase);
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
    printf("[-] GObjects not found on ARM64\n");
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
    const std::vector<uint8_t> p1 = {
        0x0F,0x2E,0xFF,0x74,0xFF,0x48,0x8B,0x1D,
        0xFF,0xFF,0xFF,0xFF,0x48,0x85,0xDB,0x74
    };
    for (const auto& region : ph.regions) {
        if (!region.isReadable() || !region.isExecutable()) continue;
        std::vector<uint8_t> b(region.size());
        if (!ph.readMemory(region.start, b.data(), region.size())) continue;
        int64_t idx = Algorithm::searchArray(b, p1, false);
        if (idx >= 0) {
            auto loc = static_cast<int64_t>(region.start) + idx;
            auto rel = Algorithm::ReadAs<int32_t>(ph, loc+8);
            auto gw = loc + rel + 12;
            printf("[*] Found GWorld: 0x%lx\n", gw);
            gProfile.GWorldOffset = toOffset(gw, moduleBase);
            return true;
        }
    }
    const char16_t* s = u"Failed to load package '%s' into a new game world.";
    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        std::vector<uint8_t> b(region.size());
        if (!ph.readMemory(region.start, b.data(), region.size())) continue;
        auto sa = Algorithm::ScanforStringRef(ph, b, s, static_cast<int64_t>(region.start), 3, "GWorld");
        if (sa) {
            int64_t last = 0;
            for (auto& pat : std::vector<std::vector<uint8_t>>{
                {0x48,0x89,0x1D},{0x48,0x89,0x2D},{0x4C,0x89,0x2D},{0x4C,0x89,0x1D},{0x48,0x89,0x15}}) {
                auto m = Algorithm::ScanFor(ph, sa, pat, false, 300);
                if (m >= 0) last = m;
            }
            if (last > 0) {
                auto rel = Algorithm::ReadAs<int32_t>(ph, last+3);
                auto gw = last + rel + 7;
                printf("[*] Found GWorld: 0x%lx\n", gw);
                gProfile.GWorldOffset = toOffset(gw, moduleBase);
                return true;
            }
        }
    }
    return false;
}
#endif

#if PLATFORM_ARM64
bool findARM64(const ProcessHandle& ph, int64_t moduleBase) {
    // Search for "Failed to load package" string via ADRP
    const char* str = "Failed to load package '%s' into a new game world.";
    for (const auto& region : ph.regions) {
        if (!region.isReadable()) continue;
        if (region.size() < 1024) continue;
        std::vector<uint8_t> buf(region.size());
        if (!ph.readMemory(region.start, buf.data(), region.size())) continue;

        auto strAddr = Algorithm::ScanforStringRef(ph, buf, str,
            static_cast<int64_t>(region.start), "GWorld");
        if (!strAddr) {
            // Try short form
            strAddr = Algorithm::ScanforStringRef(ph, buf,
                "Failed to load package",
                static_cast<int64_t>(region.start), "GWorld(short)");
        }
        if (strAddr) {
            printf("[*] Found GWorld string ref at 0x%lx\n", strAddr);
            // Near the string, look for ADRP that stores to a global (GWorld ptr)
            for (int64_t addr = strAddr - 0x200; addr < strAddr + 0x200; addr += 4) {
                uint32_t insn = Algorithm::ReadAs<uint32_t>(ph, addr);
                if (isADRP(insn)) {
                    uint64_t tgt = resolveADRP(ph, addr, insn);
                    auto* tr = ph.findRegion(tgt);
                    if (tr && !tr->isExecutable() && tr->isReadable()) {
                        // Check if this is a writable data section (GWorld is a global ptr)
                        if (tr->prot & 0x2) {
                            printf("[*] Found GWorld (ARM64): 0x%lx\n", tgt);
                            gProfile.GWorldOffset = toOffset(tgt, moduleBase);
                            return true;
                        }
                    }
                }
            }
        }
    }
    printf("[-] GWorld not found on ARM64\n");
    return false;
}
#endif

} // namespace WorldScanner

// ═══════════════════════════════════════════════════════════════════════
//  FUNCTION ADDRESS FINDER
// ═══════════════════════════════════════════════════════════════════════

namespace FunctionFinder {

#if PLATFORM_X86_64
// (x86_64 function finders — same as original port)
int64_t findStaticLoadObject(const ProcessHandle& ph, const std::vector<uint8_t>& buffer, int64_t regionBase) {
    const char16_t* str = u"Failed to find object '{ClassName} {OuterName}.{ObjectName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase, 3, "StaticLoadObject");
    if (strAddr) {
        auto pushAddr = Algorithm::ScanFor(ph, strAddr, {0x41,0x56,0x41,0x57,0x48}, true);
        auto fn = Algorithm::ScanFor(ph, pushAddr, {0x40,0x55}, true, 12);
        printf("[*] StaticLoadObject: 0x%lx\n", fn);
        gProfile.StaticLoadObjectOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fn;
    }
    return 0;
}
int64_t findSpawnActor(const ProcessHandle& ph, const std::vector<uint8_t>& buffer, int64_t regionBase) {
    const char16_t* str = u"SpawnActor failed.";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase, 3, "SpawnActor");
    if (strAddr) {
        auto call = Algorithm::ScanFor(ph, strAddr, {0xE8}, true, 20);
        auto rel = Algorithm::ReadAs<int32_t>(ph, call+1);
        auto fn = call + rel + 5;
        Algorithm::CheckNSkipJump(ph, fn, fn);
        auto retn = Algorithm::ScanFor(ph, fn, {0x5B,0xC3}, false, 192);
        auto ct = Algorithm::ScanFor(ph, retn, {0xE8,0xFF,0xFF,0xFF,0xFF,0x48,0xFF,0xFF,0xFF,0xFF,0x48}, true, 30);
        rel = Algorithm::ReadAs<int32_t>(ph, ct+1);
        auto tf = ct + rel + 5;
        Algorithm::CheckNSkipJump(ph, tf, tf);
        printf("[*] SpawnActorFTransform: 0x%lx\n", tf);
        gProfile.SpawnActorFTransOffset = toOffset(tf, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return tf;
    }
    return 0;
}
int64_t findCallFunctionByNameWithArguments(const ProcessHandle& ph, const std::vector<uint8_t>& buffer, int64_t regionBase) {
    const char16_t* str = u"'{Message}': Bad or missing property '{PropertyName}'";
    auto strAddr = Algorithm::ScanforStringRef(ph, buffer, str, regionBase, 3, "CallFunctionByName");
    if (strAddr) {
        auto push = Algorithm::ScanFor(ph, strAddr, {0x41,0x56,0x41,0x57,0x48}, true, 3500);
        auto fn = Algorithm::ScanFor(ph, push, {0x40,0x55}, true, 0x40);
        printf("[*] CallFunctionByNameWithArguments: 0x%lx\n", fn);
        gProfile.CallFunctionByNameWithArgumentsOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fn;
    }
    return 0;
}
int64_t findInitGameState(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    auto b = Algorithm::searchArray(buf, {0x40,0x53,0x48,0x83,0xEC,0x20,0x48,0x8B,0x41,0x10,0x48,0x8B,0xD9,0x48,0x8B,0x91}, false);
    if (b>=0){ auto fn=rb+b; printf("[*] InitGameState: 0x%lx\n",fn); gProfile.GameStateInitOffset=toOffset(fn,static_cast<int64_t>(ph.findUE4Module()->baseAddress)); return fn; }
    return 0;
}
int64_t findBeginPlay(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    auto b = Algorithm::searchArray(buf, {0x48,0x8B,0xD9,0xE8,0xFF,0xFF,0xFF,0xFF,0xF6,0x83,0xFF,0xFF,0xFF,0xFF,0xFF,0x74,0x12,0x48,0x8B,0x03}, false);
    if (b>=0){ auto fn=rb+b; printf("[*] BeginPlay: 0x%lx\n",fn); gProfile.BeginPlayOffset=toOffset(fn,static_cast<int64_t>(ph.findUE4Module()->baseAddress)); return fn; }
    return 0;
}
int64_t findProcessEvent(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    auto b = Algorithm::searchArray(buf, {0x40,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC}, false);
    if (b>=0){ auto fn=rb+b; printf("[*] ProcessEvent: 0x%lx\n",fn); gProfile.ProcessEventOffset=toOffset(fn,static_cast<int64_t>(ph.findUE4Module()->baseAddress)); return fn; }
    return 0;
}
#endif

#if PLATFORM_ARM64
// ARM64 function finders use string reference + prologue detection

int64_t findStaticLoadObjectARM64(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    const char* str = "Failed to find object '{ClassName} {OuterName}.{ObjectName}'";
    auto sa = Algorithm::ScanforStringRef(ph, buf, str, rb, "StaticLoadObject");
    if (!sa) sa = Algorithm::ScanforStringRef(ph, buf, "Failed to find object", rb, "StaticLoadObject(short)");
    if (sa) {
        auto fn = findARM64Prologue(ph, sa, 0x300);
        if (fn) {
            printf("[*] StaticLoadObject (ARM64): 0x%lx\n", fn);
            gProfile.StaticLoadObjectOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fn;
        }
    }
    return 0;
}

int64_t findSpawnActorARM64(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    const char* str = "SpawnActor failed.";
    auto sa = Algorithm::ScanforStringRef(ph, buf, str, rb, "SpawnActor");
    if (sa) {
        auto fn = findARM64Prologue(ph, sa, 0x300);
        if (fn) {
            printf("[*] SpawnActorFTransform (ARM64): 0x%lx\n", fn);
            gProfile.SpawnActorFTransOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fn;
        }
    }
    return 0;
}

int64_t findCallFunctionByNameARM64(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    const char* str = "'{Message}': Bad or missing property '{PropertyName}'";
    auto sa = Algorithm::ScanforStringRef(ph, buf, str, rb, "CallFunctionByName");
    if (!sa) sa = Algorithm::ScanforStringRef(ph, buf, "Bad or missing property", rb, "CallFunctionByName(short)");
    if (sa) {
        auto fn = findARM64Prologue(ph, sa, 0x300);
        if (fn) {
            printf("[*] CallFunctionByNameWithArguments (ARM64): 0x%lx\n", fn);
            gProfile.CallFunctionByNameWithArgumentsOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
            return fn;
        }
    }
    return 0;
}

int64_t findInitGameStateARM64(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    // AGameState::InitGameState - look for prologue storing X0 (this) then loading offset 0x10
    const std::vector<uint8_t> pat = {
        0xFD,0x7B,0xBF,0xA9,  // STP X29,X30,[SP,#-0x10]!
        0xFD,0x03,0x00,0x91,  // MOV X29,SP
        0xFF,0xFF,0xFF,0xFF,  // (variable)
        0xFF,0xFF,0x40,0xF9,  // LDR X?,[X0,#0x10]
    };
    auto idx = Algorithm::searchArray(buf, pat, false);
    if (idx >= 0) {
        auto fn = rb + idx;
        printf("[*] InitGameState (ARM64): 0x%lx\n", fn);
        gProfile.GameStateInitOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fn;
    }
    return 0;
}

int64_t findBeginPlayARM64(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    // AActor::BeginPlay starts with STP + BL (call IsPendingKill)
    const std::vector<uint8_t> pat = {
        0xFD,0x7B,0xFF,0xA9,  // STP X29,X30,[SP,#imm]!
        0xFD,0x03,0x00,0x91,  // MOV X29,SP
        0xFF,0xFF,0xFF,0xFF,  // (var)
        0xFF,0xFF,0xFF,0xFF,  // (var)
        0xFF,0xFF,0xFF,0x94,  // BL ...
    };
    auto idx = Algorithm::searchArray(buf, pat, false);
    if (idx >= 0) {
        auto fn = rb + idx;
        printf("[*] BeginPlay (ARM64): 0x%lx\n", fn);
        gProfile.BeginPlayOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
        return fn;
    }
    return 0;
}

int64_t findProcessEventARM64(const ProcessHandle& ph, const std::vector<uint8_t>& buf, int64_t rb) {
    // Large function with big stack frame
    for (size_t i = 0; i + 16 < buf.size(); i += 4) {
        uint32_t insn = *(uint32_t*)(&buf[i]);
        if ((insn & 0xFFC0FFFF) == 0xA9007BFD) { // STP X29,X30 pre-index
            for (size_t j = i+4; j < std::min(i+20, buf.size()); j += 4) {
                uint32_t si = *(uint32_t*)(&buf[j]);
                if ((si & 0xFF000000) == 0xD1000000) { // SUB SP,SP,#imm
                    uint32_t imm = (si >> 10) & 0xFFF;
                    if (imm >= 0x40) { // big stack frame (>= 64 bytes)
                        auto fn = rb + i;
                        printf("[*] ProcessEvent (ARM64): 0x%lx (stack=0x%x)\n", fn, imm);
                        gProfile.ProcessEventOffset = toOffset(fn, static_cast<int64_t>(ph.findUE4Module()->baseAddress));
                        return fn;
                    }
                }
            }
        }
    }
    return 0;
}
#endif

bool scanAll(const ProcessHandle& ph) {
    auto* mod = ph.findUE4Module();
    if (!mod) { fprintf(stderr, "[!] No UE4 module\n"); return false; }
    int64_t base = static_cast<int64_t>(mod->baseAddress);
    printf("[*] Target: %s (base=0x%lx, size=0x%zx)\n", mod->name.c_str(), base, mod->size);

    for (const auto& region : ph.regions) {
        if (!region.isReadable() || !region.isExecutable()) continue;
        if (gSearchComplete) break;
        std::vector<uint8_t> buffer(region.size());
        if (!ph.readMemory(region.start, buffer.data(), region.size())) continue;
        int64_t rb = static_cast<int64_t>(region.start);

#if PLATFORM_X86_64
        findStaticLoadObject(ph, buffer, rb);
        findSpawnActor(ph, buffer, rb);
        findCallFunctionByNameWithArguments(ph, buffer, rb);
        findInitGameState(ph, buffer, rb);
        findBeginPlay(ph, buffer, rb);
        findProcessEvent(ph, buffer, rb);
#endif
#if PLATFORM_ARM64
        findStaticLoadObjectARM64(ph, buffer, rb);
        findSpawnActorARM64(ph, buffer, rb);
        findCallFunctionByNameARM64(ph, buffer, rb);
        findInitGameStateARM64(ph, buffer, rb);
        findBeginPlayARM64(ph, buffer, rb);
        findProcessEventARM64(ph, buffer, rb);
#endif
    }

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
//  MAIN ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════

inline bool scanUE4(const ProcessHandle& ph, int engineVersion) {
    if (engineVersion > 0) {
        gProfile.EngineVersion = engineVersion;
        gProfile.IsUsing4_22 = (engineVersion / 100 == 422);
        gProfile.IsUsingFChunkedFixedUObjectArray = (engineVersion / 100 >= 418);
        gProfile.UseFNamePool = (engineVersion / 100 >= 423);
        printf("[*] Using specified engine version: %d\n", engineVersion);
        Offsets::configure(engineVersion);
    } else {
        auto* mod = ph.findUE4Module();
        auto modBase = static_cast<int64_t>(mod->baseAddress);
#if PLATFORM_X86_64
        EngineVersion::detectX86_64(ph, modBase, mod->size);
#endif
#if PLATFORM_ARM64
        EngineVersion::detectARM64(ph, modBase, mod->size);
#endif
        if (gProfile.EngineVersion == 0) {
            printf("[!] Could not auto-detect engine version.\n");
            printf("[!] Please re-run with --ue4-version <ver> (e.g. 418 for 4.18)\n");
        }
    }

    NameScanner::find(ph,
        static_cast<int64_t>(ph.findUE4Module()->baseAddress),
        ph.findUE4Module()->size);

    FunctionFinder::scanAll(ph);
    return true;
}
