/*
 * algorithm.h - Cross-platform AOB signature scanning
 *
 * Ported from aLgorithm.h. Core scanning algorithms are architecture-
 * independent; only string-reference detection differs per ISA.
 */

#pragma once
#include "linux_memory.h"

namespace Algorithm {

// ─── KMP Partial Match Table ───────────────────────────────────────────
// 0xFF is treated as wildcard
inline std::vector<int> getPartialMatchTable(const std::vector<uint8_t>& pattern) {
    const int patternSize = static_cast<int>(pattern.size());
    std::vector<int> table(patternSize, 0);

    int j = 0;
    for (int i = 1; i < patternSize; i++) {
        while (j > 0 && (pattern[j] != pattern[i] && pattern[j] != 0xFF)) {
            j = table[j - 1];
        }
        if (pattern[j] == pattern[i] || pattern[j] == 0xFF) {
            j++;
        }
        table[i] = j;
    }
    return table;
}

// ─── Array-of-Bytes search (KMP with 0xFF wildcard) ────────────────────
// Returns the index of the first/last match, or -1
inline int64_t searchArray(const std::vector<uint8_t>& array,
                           const std::vector<uint8_t>& pattern,
                           bool lastResult) {
    int arraySize = static_cast<int>(array.size());
    int patternSize = static_cast<int>(pattern.size());
    if (patternSize == 0 || arraySize < patternSize) return -1;

    std::vector<int> partialMatchTable = getPartialMatchTable(pattern);

    int j = 0;
    int64_t result = -1;
    for (int i = 0; i < arraySize; i++) {
        while (j > 0 && (pattern[j] != array[i] && pattern[j] != 0xFF)) {
            i = i - j + 1;
            j = partialMatchTable[j - 1];
        }
        if (pattern[j] == array[i] || pattern[j] == 0xFF) {
            j++;
        }
        if (j == patternSize) {
            if (lastResult) {
                result = i - patternSize + 1;
            } else {
                return i - patternSize + 1;
            }
            i = i - j + 1;
            j = partialMatchTable[j - 1];
        }
    }
    return result;
}

// ─── Scan for byte pattern within a range ──────────────────────────────
// Searches near StartAddress (backward if lastResult, then forward)
inline int64_t ScanFor(const ProcessHandle& ph,
                       int64_t StartAddress,
                       const std::vector<uint8_t>& bytearray,
                       bool lastResult,
                       size_t Size = 3000) {
    StartAddress = lastResult ? StartAddress - static_cast<int64_t>(Size) : StartAddress;

    std::vector<uint8_t> buffer(Size);
    if (ph.readMemory(static_cast<uint64_t>(StartAddress), buffer.data(), Size)) {
        int indexfound = static_cast<int>(searchArray(buffer, bytearray, lastResult));
        if (indexfound >= 0) {
            return StartAddress + indexfound;
        }
    }
    return -1;
}

// ─── Read typed value from remote process ──────────────────────────────
template<typename T>
T ReadAs(const ProcessHandle& ph, uint64_t address) {
    T val{};
    ph.readMemory(address, &val, sizeof(T));
    return val;
}

// ─── Check and skip JMP instruction ────────────────────────────────────
#if PLATFORM_X86_64
inline bool CheckNSkipJump(const ProcessHandle& ph, int64_t AddrIn, int64_t& AddrOut) {
    uint8_t read = ReadAs<uint8_t>(ph, AddrIn);
    if (read == 0xE9 || read == 0xEB) {
        AddrOut = AddrIn + ReadAs<int32_t>(ph, AddrIn + 1) + 0x5;
        return true;
    }
    AddrOut = AddrIn;
    return false;
}
#endif

#if PLATFORM_ARM64
inline bool CheckNSkipJump(const ProcessHandle& ph, int64_t AddrIn, int64_t& AddrOut) {
    uint32_t insn = ReadAs<uint32_t>(ph, AddrIn);
    // B instruction: unconditional branch
    if ((insn & 0xFC000000) == 0x14000000) {
        // 26-bit signed offset * 4
        int64_t offset = (insn & 0x03FFFFFF);
        offset = (offset << 38) >> 36;  // sign extend 26-bit to 64-bit
        AddrOut = AddrIn + offset;
        return true;
    }
    // BR instruction (indirect jump via register) - can't follow statically
    AddrOut = AddrIn;
    return false;
}
#endif

// ─── String reference scanning ─────────────────────────────────────────
// Scans a buffer for instruction sequences that reference a known string.
// On ARM64: ADRP + ADD (or ADR, or LDR literal)
// On x86_64: LEA reg, [rip+disp32]

#if PLATFORM_X86_64
inline int64_t ScanforStringRef(const ProcessHandle& ph,
                                const std::vector<uint8_t>& buffer,
                                const char16_t* String,      // UTF-16 string (UE4 wide char)
                                int64_t AbsoluteRegionStartAddress,
                                int32_t offset,
                                const std::string& Name) {
    int64_t result = 0;
    size_t StringLength = 0;
    const char16_t* p = String;
    while (*p++) StringLength++;
    size_t StringBytes = StringLength * sizeof(char16_t);

    for (size_t i = 0; i < buffer.size(); i++) {
        if (i + offset >= buffer.size()) return result;

        // Look for LEA with RIP-relative addressing
        // 48 8D 0D XX XX XX XX  (lea rcx, [rip+...])
        // 4C 8D 0D XX XX XX XX  (lea r9,  [rip+...])
        // 48 8D 15 XX XX XX XX  (lea rdx, [rip+...])
        // 48 8D 05 XX XX XX XX  (lea rax, [rip+...])
        if ((buffer[i] == 0x4C || buffer[i] == 0x48) && buffer[i+1] == 0x8D) {
            int32_t relative = *(int32_t*)(&buffer[i + offset]);

            int64_t absoluteStringAddr = AbsoluteRegionStartAddress + i + offset + relative + 4;

            std::vector<char16_t> stringBuffer(StringLength);
            if (ph.readMemory(static_cast<uint64_t>(absoluteStringAddr),
                              stringBuffer.data(), StringBytes)) {
                bool match = true;
                for (size_t si = 0; si < StringLength; si++) {
                    if (stringBuffer[si] != String[si]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    printf("[*] Searching for %s\n", Name.c_str());
                    return AbsoluteRegionStartAddress + i;
                }
            }
        }
    }
    return result;
}
#endif

#if PLATFORM_ARM64
// ASCII string reference scan on ARM64
inline int64_t ScanforStringRef(const ProcessHandle& ph,
                                const std::vector<uint8_t>& buffer,
                                const char* String,            // ASCII/UTF-8 string
                                int64_t AbsoluteRegionStartAddress,
                                const std::string& Name) {
    size_t StringLen = strlen(String);

    for (size_t i = 0; i + 4 < buffer.size(); i++) {
        uint32_t insn = *(uint32_t*)(&buffer[i]);

        // ADRP instruction
        if (isADRP(insn)) {
            int rd = getRd(insn);
            uint64_t pc = AbsoluteRegionStartAddress + i;
            uint64_t pageAddr = decodeADRP(insn, pc);

            // Look for ADD immediate within next few instructions (same Rd)
            for (size_t j = i + 4; j < std::min(i + 24, buffer.size()); j += 4) {
                uint32_t addInsn = *(uint32_t*)(&buffer[j]);
                if (isADD_imm(addInsn) && getRd(addInsn) == rd && getRn(addInsn) == rd) {
                    uint64_t strAddr = pageAddr + decodeADD_imm(addInsn);

                    // Verify by reading the string at this address
                    std::vector<char> strBuf(StringLen + 1);
                    if (ph.readMemory(strAddr, strBuf.data(), StringLen)) {
                        strBuf[StringLen] = '\0';
                        if (strcmp(strBuf.data(), String) == 0) {
                            printf("[*] Searching for %s\n", Name.c_str());
                            return AbsoluteRegionStartAddress + i;
                        }
                    }
                    break;
                }
            }
        }

        // ADR instruction (short-range, single instruction)
        if (isADR(insn)) {
            int rd = getRd(insn);
            uint64_t pc = AbsoluteRegionStartAddress + i;
            // ADR gives PC-relative byte address
            int64_t imm = ((insn >> 5) & 0x7FFFF) | ((insn >> 29) & 0x3) << 19;
            imm = (imm << 43) >> 43;  // sign extend 21-bit
            uint64_t strAddr = pc + imm;

            std::vector<char> strBuf(StringLen + 1);
            if (ph.readMemory(strAddr, strBuf.data(), StringLen)) {
                strBuf[StringLen] = '\0';
                if (strcmp(strBuf.data(), String) == 0) {
                    printf("[*] Searching for %s\n", Name.c_str());
                    return AbsoluteRegionStartAddress + i;
                }
            }
        }
    }
    return 0;
}

// Wide string reference scan on ARM64 (less common, but used in some UE4 builds)
inline int64_t ScanforStringRefWide(const ProcessHandle& ph,
                                    const std::vector<uint8_t>& buffer,
                                    const uint16_t* String,
                                    int64_t AbsoluteRegionStartAddress,
                                    const std::string& Name) {
    size_t StringLen = 0;
    const uint16_t* p = String;
    while (*p++) StringLen++;
    size_t StringBytes = StringLen * sizeof(uint16_t);

    for (size_t i = 0; i + 4 < buffer.size(); i++) {
        uint32_t insn = *(uint32_t*)(&buffer[i]);

        if (isADRP(insn)) {
            int rd = getRd(insn);
            uint64_t pc = AbsoluteRegionStartAddress + i;
            uint64_t pageAddr = decodeADRP(insn, pc);

            for (size_t j = i + 4; j < std::min(i + 24, buffer.size()); j += 4) {
                uint32_t addInsn = *(uint32_t*)(&buffer[j]);
                if (isADD_imm(addInsn) && getRd(addInsn) == rd && getRn(addInsn) == rd) {
                    uint64_t strAddr = pageAddr + decodeADD_imm(addInsn);

                    std::vector<uint16_t> strBuf(StringLen);
                    if (ph.readMemory(strAddr, strBuf.data(), StringBytes)) {
                        bool match = true;
                        for (size_t si = 0; si < StringLen; si++) {
                            if (strBuf[si] != String[si]) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            printf("[*] Searching for %s\n", Name.c_str());
                            return AbsoluteRegionStartAddress + i;
                        }
                    }
                    break;
                }
            }
        }
    }
    return 0;
}
#endif // PLATFORM_ARM64

} // namespace Algorithm
