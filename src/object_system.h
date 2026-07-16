/*
 * object_system.h - GObjects / UObject traversal & SDK generation
 *
 * Supports both:
 *   - Pre-4.23: flat TUObjectArray (direct index → UObject*)
 *   - 4.23+: chunked TUObjectArray (chunk[index/65536][index%65536])
 */

#pragma once
#include "linux_memory.h"
#include "offsets.h"
#include "name_system.h"
#include <string>
#include <fstream>
#include <map>

class ObjectSystem {
public:
    ObjectSystem(const ProcessHandle& ph, int64_t gObjAddr, NameSystem* names)
        : ph_(ph), gObj_(gObjAddr), names_(names) {}

    // Get total object count
    uint32_t count();

    // Get UObject* at index
    int64_t getObject(uint32_t index);

    // Get object name
    std::string getObjectName(int64_t uobj);
    // Get object class name
    std::string getClassName(int64_t uobj);
    // Get object full name (ClassName ObjectName)
    std::string getFullName(int64_t uobj);

    // Dump all objects to file
    void dumpAll(const std::string& filepath);

    // Check if UObject is valid
    bool isValid(int64_t uobj);

private:
    const ProcessHandle& ph_;
    int64_t gObj_;
    NameSystem* names_;

    int64_t getTUObjectArray();
};

// ─── Get TUObjectArray ────────────────────────────────────────────────
inline int64_t ObjectSystem::getTUObjectArray() {
    int64_t fuObjectArray = gObj_;

    // Try direct first
    int64_t tuArray = Algorithm::ReadAs<int64_t>(ph_,
        fuObjectArray + Offsets::ObjArray::TUObjectArray);
    if (tuArray > 0x1000 && tuArray < 0x800000000000ULL) return tuArray;

    // Try deref (deRefGUObjectArray)
    fuObjectArray = Algorithm::ReadAs<int64_t>(ph_, gObj_);
    if (fuObjectArray) {
        tuArray = Algorithm::ReadAs<int64_t>(ph_,
            fuObjectArray + Offsets::ObjArray::TUObjectArray);
        if (tuArray > 0x1000 && tuArray < 0x800000000000ULL) return tuArray;
    }

    return 0;
}

// ─── Count ─────────────────────────────────────────────────────────────
inline uint32_t ObjectSystem::count() {
    if (Offsets::isUE423) {
        int64_t tuArray = getTUObjectArray();
        if (!tuArray) return 0;
        return Algorithm::ReadAs<uint32_t>(ph_,
            tuArray + Offsets::ObjArray::NumElements);
    } else {
        // Pre-4.23: FUObjectArray → TUObjectArray → NumElements
        int64_t fuArr = gObj_;
        // Handle deRef
        int64_t deref = Algorithm::ReadAs<int64_t>(ph_, fuArr);
        if (deref > 0x1000 && deref < 0x800000000000ULL)
            fuArr = deref;
        int64_t tuArray = Algorithm::ReadAs<int64_t>(ph_,
            fuArr + Offsets::ObjArray::TUObjectArray);
        if (!tuArray) return 0;
        return Algorithm::ReadAs<uint32_t>(ph_,
            tuArray + Offsets::ObjArray::NumElements);
    }
}

// ─── Get UObject at index ─────────────────────────────────────────────
inline int64_t ObjectSystem::getObject(uint32_t index) {
    if (Offsets::isUE423) {
        // Chunked: chunk[index / 65536] + (index % 65536) * FUObjectItemSize
        int64_t tuArray = getTUObjectArray();
        if (!tuArray) return 0;

        int64_t chunk = Algorithm::ReadAs<int64_t>(ph_,
            tuArray + (index / Offsets::ObjArray::ChunkSize) * Offsets::PointerSize);
        if (!chunk) return 0;

        return Algorithm::ReadAs<int64_t>(ph_,
            chunk + Offsets::FUObjectItemPadd +
            (index % Offsets::ObjArray::ChunkSize) * Offsets::FObjItem::Size +
            Offsets::FObjItem::Object);
    } else {
        // Pre-4.23: flat array, TUObjectArray + index * FUObjectItemSize
        int64_t fuArr = gObj_;
        int64_t deref = Algorithm::ReadAs<int64_t>(ph_, fuArr);
        if (deref > 0x1000 && deref < 0x800000000000ULL)
            fuArr = deref;
        int64_t tuArray = Algorithm::ReadAs<int64_t>(ph_,
            fuArr + Offsets::ObjArray::TUObjectArray);
        if (!tuArray) return 0;

        return Algorithm::ReadAs<int64_t>(ph_,
            tuArray + index * Offsets::FUObjectItemSize);
    }
}

// ─── Validity check ───────────────────────────────────────────────────
inline bool ObjectSystem::isValid(int64_t uobj) {
    if (!uobj || uobj < 0x1000 || uobj > 0x800000000000ULL) return false;

    // Check InternalIndex is reasonable
    int32_t idx = Algorithm::ReadAs<int32_t>(ph_, uobj + Offsets::UObj::InternalIndex);
    if (idx < 0 || idx > 10000000) return false;

    // Check ClassPrivate points to valid memory
    int64_t cls = Algorithm::ReadAs<int64_t>(ph_, uobj + Offsets::UObj::ClassPrivate);
    if (!cls || cls < 0x1000 || cls > 0x800000000000ULL) return false;

    return true;
}

// ─── Get name / class ─────────────────────────────────────────────────
inline std::string ObjectSystem::getObjectName(int64_t uobj) {
    if (!isValid(uobj)) return "";
    uint32_t nameIdx = Algorithm::ReadAs<uint32_t>(ph_,
        uobj + Offsets::UObj::FNameIndex);
    return names_->getName(nameIdx);
}

inline std::string ObjectSystem::getClassName(int64_t uobj) {
    if (!isValid(uobj)) return "";
    int64_t cls = Algorithm::ReadAs<int64_t>(ph_,
        uobj + Offsets::UObj::ClassPrivate);
    if (!cls) return "";
    return getObjectName(cls);
}

inline std::string ObjectSystem::getFullName(int64_t uobj) {
    std::string cn = getClassName(uobj);
    std::string on = getObjectName(uobj);
    if (cn.empty() || on.empty()) return "";
    return cn + " " + on;
}

// ─── Dump all objects ─────────────────────────────────────────────────
inline void ObjectSystem::dumpAll(const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) {
        fprintf(stderr, "[!] Cannot open %s\n", filepath.c_str());
        return;
    }
    uint32_t total = count();
    uint32_t valid = 0;

    printf("[*] Dumping %u objects to %s...\n", total, filepath.c_str());

    for (uint32_t i = 0; i < total; i++) {
        int64_t obj = getObject(i);
        if (!isValid(obj)) continue;

        std::string name = getObjectName(obj);
        std::string cls = getClassName(obj);
        if (name.empty()) continue;

        out << "[" << std::hex << i << "] " << cls << " " << name
            << " (0x" << obj << ")\n";
        valid++;

        if (valid % 5000 == 0)
            printf("[*] Dumped %u valid objects...\n", valid);
    }

    out.close();
    printf("[+] Dumped %u valid objects to %s\n", valid, filepath.c_str());
}
