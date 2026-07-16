/*
 * name_system.h - GNames / FNamePool name resolution
 *
 * Supports both:
 *   - TNameEntryArray (UE4 pre-4.23): chunked pointer array
 *   - FNamePool (UE4 4.23+): block-based allocator
 */

#pragma once
#include "linux_memory.h"
#include "offsets.h"
#include <string>
#include <fstream>
#include <vector>

class NameSystem {
public:
    NameSystem(const ProcessHandle& ph, int64_t gNamesAddr)
        : ph_(ph), gNames_(gNamesAddr) {}

    // Get name string from FName index
    std::string getName(uint32_t index);

    // Dump all names to file
    void dumpAll(const std::string& filepath);

    // Number of names
    uint32_t numNames();

private:
    const ProcessHandle& ph_;
    int64_t gNames_;

    // ─── TNameEntryArray methods (pre-4.23) ──────────────────────────
    std::string getNameOld(uint32_t index);
    int64_t getTNameEntryArray();
    void dumpOld(std::ofstream& out, uint32_t& count);

    // ─── FNamePool methods (4.23+) ───────────────────────────────────
    std::string getNameNew(uint32_t index);
    void dumpNew(std::ofstream& out, uint32_t& count);
};

// ─── Get name by index ────────────────────────────────────────────────
inline std::string NameSystem::getName(uint32_t index) {
    if (Offsets::isUE423)
        return getNameNew(index);
    else
        return getNameOld(index);
}

// ─── Get total name count ─────────────────────────────────────────────
inline uint32_t NameSystem::numNames() {
    if (Offsets::isUE423) {
        // FNamePool: estimate from blocks
        int64_t pool = gNames_ + Offsets::FNamePool::GNamesOffset;
        uint32_t currentBlock = Algorithm::ReadAs<uint32_t>(ph_, pool + Offsets::FNamePool::CurrentBlock);
        return (currentBlock + 1) * 65536;  // rough estimate
    } else {
        return 170000;  // default GNameLimit from SDK
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  TNameEntryArray (pre-4.23)
// ═══════════════════════════════════════════════════════════════════════

inline int64_t NameSystem::getTNameEntryArray() {
    // GNames may be direct or indirect (deRefGNames)
    // Try direct first, then single deref, then double deref
    int64_t val = gNames_;

    // Try direct: if first chunk pointer is valid
    int64_t firstChunk = Algorithm::ReadAs<int64_t>(ph_, val);
    if (firstChunk > 0x1000 && firstChunk < 0x800000000000ULL) {
        int64_t firstEntry = Algorithm::ReadAs<int64_t>(ph_, firstChunk);
        if (firstEntry > 0x1000) return val;  // direct, val IS the TNameEntryArray
    }

    // Try single deref: GNames → ptr → TNameEntryArray
    val = Algorithm::ReadAs<int64_t>(ph_, gNames_);
    firstChunk = Algorithm::ReadAs<int64_t>(ph_, val);
    if (firstChunk > 0x1000 && firstChunk < 0x800000000000ULL) {
        int64_t firstEntry = Algorithm::ReadAs<int64_t>(ph_, firstChunk);
        if (firstEntry > 0x1000) return val;
    }

    // Try double deref with +0x80 offset (32-bit style from SDK)
    val = Algorithm::ReadAs<int64_t>(ph_, gNames_);
    val = Algorithm::ReadAs<int64_t>(ph_, val + 0x80);
    firstChunk = Algorithm::ReadAs<int64_t>(ph_, val);
    if (firstChunk > 0x1000 && firstChunk < 0x800000000000ULL) {
        int64_t firstEntry = Algorithm::ReadAs<int64_t>(ph_, firstChunk);
        if (firstEntry > 0x1000) return val;
    }

    return 0;
}

inline std::string NameSystem::getNameOld(uint32_t index) {
    static int64_t tNameEntryArray = 0;
    if (!tNameEntryArray)
        tNameEntryArray = getTNameEntryArray();
    if (!tNameEntryArray) return "";

    int nameOff = Offsets::FNameEntry_Old::NameString;
    int idxOff  = Offsets::FNameEntry_Old::Index;
    int chunkSz = Offsets::ObjArray::TNameChunkSize;
    int ptrSz   = Offsets::PointerSize;

    // Get chunk pointer
    int64_t chunk = Algorithm::ReadAs<int64_t>(ph_,
        tNameEntryArray + (index / chunkSz) * ptrSz);
    if (!chunk) return "";

    // Get FNameEntry pointer
    int64_t entry = Algorithm::ReadAs<int64_t>(ph_,
        chunk + (index % chunkSz) * ptrSz);
    if (!entry) return "";

    // Read name string
    char buf[256] = {};
    ph_.readMemory(entry + nameOff, buf, sizeof(buf) - 1);
    return std::string(buf);
}

inline void NameSystem::dumpOld(std::ofstream& out, uint32_t& count) {
    for (uint32_t i = 0; i < 170000; i++) {
        std::string name = getNameOld(i);
        if (name.empty()) continue;
        out << "[" << i << "] " << name << "\n";
        count++;
        if (count % 10000 == 0)
            printf("[*] Dumped %u names...\n", count);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  FNamePool (UE 4.23+)
// ═══════════════════════════════════════════════════════════════════════

inline std::string NameSystem::getNameNew(uint32_t index) {
    int64_t pool = gNames_ + Offsets::FNamePool::GNamesOffset;

    uint32_t block = index >> 16;
    uint16_t offset = (uint16_t)index;

    // Validate block
    uint32_t numBlocks = Algorithm::ReadAs<uint32_t>(ph_,
        pool + Offsets::FNamePool::CurrentBlock) + 1;
    if (block >= numBlocks) return "";

    // Get block base
    int64_t blockPtr = Algorithm::ReadAs<int64_t>(ph_,
        pool + Offsets::FNamePool::Blocks + block * Offsets::PointerSize);
    if (!blockPtr) return "";

    // Get FNameEntry
    int64_t entry = blockPtr + Offsets::FNamePool::Stride * offset;

    // Read header
    uint16_t header = Algorithm::ReadAs<uint16_t>(ph_, entry);
    int strLen = header >> Offsets::FNameEntry_New::LenBit;
    if (strLen <= 0 || strLen > 250) return "";

    bool isWide = header & 1;
    int64_t strPtr = entry + Offsets::FNameEntry_New::ToString;

    if (isWide) {
        // UTF-16 → UTF-8
        std::vector<uint16_t> wbuf(strLen);
        ph_.readMemory(strPtr, wbuf.data(), strLen * 2);
        std::string result;
        for (int i = 0; i < strLen; i++) {
            if (wbuf[i] < 0x80) result += (char)wbuf[i];
            else if (wbuf[i] < 0x800) {
                result += (char)(0xC0 | (wbuf[i] >> 6));
                result += (char)(0x80 | (wbuf[i] & 0x3F));
            } else {
                result += (char)(0xE0 | (wbuf[i] >> 12));
                result += (char)(0x80 | ((wbuf[i] >> 6) & 0x3F));
                result += (char)(0x80 | (wbuf[i] & 0x3F));
            }
        }
        return result;
    } else {
        char buf[256] = {};
        ph_.readMemory(strPtr, buf, std::min(strLen, 255));
        return std::string(buf, strLen);
    }
}

inline void NameSystem::dumpNew(std::ofstream& out, uint32_t& count) {
    int64_t pool = gNames_ + Offsets::FNamePool::GNamesOffset;
    uint32_t currentBlock = Algorithm::ReadAs<uint32_t>(ph_,
        pool + Offsets::FNamePool::CurrentBlock);
    uint32_t currentCursor = Algorithm::ReadAs<uint32_t>(ph_,
        pool + Offsets::FNamePool::CurrentByteCursor);

    for (uint32_t blk = 0; blk <= currentBlock; blk++) {
        int64_t blockPtr = Algorithm::ReadAs<int64_t>(ph_,
            pool + Offsets::FNamePool::Blocks + blk * Offsets::PointerSize);
        if (!blockPtr) continue;

        uint32_t blockSize = (blk == currentBlock) ? currentCursor : 65536 * Offsets::FNamePool::Stride;
        int64_t end = blockPtr + blockSize - Offsets::FNameEntry_New::HeaderSize;

        for (int64_t cur = blockPtr; cur < end; ) {
            uint16_t header = Algorithm::ReadAs<uint16_t>(ph_, cur);
            int strLen = header >> Offsets::FNameEntry_New::LenBit;
            if (strLen <= 0) break;

            bool isWide = header & 1;
            uint32_t key = (blk << 16) | ((cur - blockPtr) / Offsets::FNamePool::Stride);

            std::string name;
            int64_t strPtr = cur + Offsets::FNameEntry_New::ToString;

            if (isWide) {
                std::vector<uint16_t> wbuf(strLen);
                ph_.readMemory(strPtr, wbuf.data(), strLen * 2);
                for (int i = 0; i < strLen; i++) {
                    if (wbuf[i] < 0x80) name += (char)wbuf[i];
                    else { name += '?'; }
                }
            } else {
                char buf[256] = {};
                ph_.readMemory(strPtr, buf, std::min(strLen, 255));
                name.assign(buf, strLen);
            }

            out << "[" << std::hex << key << "] " << name << "\n";
            count++;

            int entryBytes = Offsets::FNameEntry_New::HeaderSize +
                             strLen * (isWide ? 2 : 1);
            cur += (entryBytes + Offsets::FNamePool::Stride - 1) &
                   ~(Offsets::FNamePool::Stride - 1);
        }
    }
}

// ─── Dump all names ───────────────────────────────────────────────────
inline void NameSystem::dumpAll(const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) {
        fprintf(stderr, "[!] Cannot open %s for writing\n", filepath.c_str());
        return;
    }
    uint32_t count = 0;
    printf("[*] Dumping names to %s...\n", filepath.c_str());

    if (Offsets::isUE423)
        dumpNew(out, count);
    else
        dumpOld(out, count);

    out.close();
    printf("[+] Dumped %u names to %s\n", count, filepath.c_str());
}
