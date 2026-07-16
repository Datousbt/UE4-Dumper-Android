/*
 * offsets.h - UE4 structure offsets (multiple versions & games)
 *
 * Sources:
 *   1. Original UE4-Function-Address-Finder (PotatoPie) - x86_64 Windows
 *   2. SDK/jni (UE4 4.18 ARM64) - FNameEntry, TUObjectArray, UObject
 *   3. BigWhiteTool (UE4 4.23+ ARM64) - FNamePool, UStruct, UFunction, FProperty
 */

#pragma once
#include <cstdint>

namespace Offsets {

// ─── Global settings ──────────────────────────────────────────────────
inline bool isUE423 = false;   // UE >= 4.23 (FNamePool era)
inline bool isUE422 = false;   // UE == 4.22
inline bool isUE418 = false;   // UE >= 4.18 (Chunked UObjectArray)
inline int  PointerSize = 8;   // 4=32bit, 8=64bit
inline int  FUObjectItemPadd = 0;
inline int  FUObjectItemSize = 0x18; // sizeof(FUObjectItem) on 64-bit

// ─── FNameEntry (pre-4.23 TNameEntryArray) ────────────────────────────
namespace FNameEntry_Old {
    inline int NameString = 0x10;  // offset to ANSI name string
    inline int Index     = 0x0;    // offset to FNameEntry index
    inline int HashNext  = 0x8;    // offset to hash/next pointer
}

// ─── FNamePool (UE 4.23+) ─────────────────────────────────────────────
namespace FNamePool {
    inline int Stride          = 2;     // sizeof(FNameEntry) stride
    inline int GNamesOffset    = 0x30;  // offset from GNames to FNamePool data
    inline int CurrentBlock    = 0x8;   // offset to current block index
    inline int CurrentByteCursor = 0xC; // offset to current byte cursor
    inline int Blocks          = 0x10;  // offset to blocks array
}

// ─── FNameEntry (UE 4.23+ FNamePool entry) ────────────────────────────
namespace FNameEntry_New {
    inline int LenBit   = 6;     // bit shift for length in header
    inline int ToString = 2;     // offset from entry to string data
    inline int HeaderSize = 2;   // sizeof(FNameEntryHeader) = 2 bytes
}

// ─── FUObjectArray / TUObjectArray ─────────────────────────────────────
namespace ObjArray {
    inline int TUObjectArray = 0x10;   // FUObjectArray → TUObjectArray
    inline int NumElements   = 0xC;    // pre-4.23: 0xC, 4.23+: 0x14
    inline int NumChunks     = 0x1C;   // pre-4.23: (not used), 4.23+: 0x1C
    inline int ChunkSize     = 0x10000;// entries per chunk (4.23+: 65536, pre: N/A)
    inline int TNameChunkSize = 0x4000;// entries per TNameEntryArray chunk
}

// ─── FUObjectItem ──────────────────────────────────────────────────────
namespace FObjItem {
    inline int Size   = 0x18;
    inline int Object = 0x0;     // offset to UObject* within item
}

// ─── UObject ───────────────────────────────────────────────────────────
namespace UObj {
    inline int InternalIndex = 0xC;
    inline int ClassPrivate  = 0x10;
    inline int FNameIndex    = 0x18;
    inline int OuterPrivate  = 0x20;
}

// ─── UStruct (4.23+) ──────────────────────────────────────────────────
namespace UStruct {
    inline int SuperStruct     = 0x40;
    inline int Children        = 0x48;
    inline int ChildProperties = 0x50;
    inline int PropertiesSize  = 0x58;
}

// ─── UFunction ─────────────────────────────────────────────────────────
namespace UFunc {
    inline int FunctionFlags = 0x88;  // pre-4.23: 0x88, 4.23+: 0xB0
    inline int Func          = 0xB0;  // pre-4.23: 0xB0, 4.23+: 0xD8
}

// ─── UProperty ─────────────────────────────────────────────────────────
namespace UProp {
    inline int ElementSize   = 0x34;  // pre-4.23: 0x34, 4.23+: 0x38
    inline int PropertyFlags = 0x38;  // pre-4.23: 0x38, 4.23+: 0x40
    inline int OffsetInternal = 0x44; // pre-4.23: 0x44, 4.23+: 0x4C
    inline int Size          = 0x70;  // pre-4.23: 0x70, 4.23+: 0x78
}

// ─── FField (UE 4.23+) ────────────────────────────────────────────────
namespace FField {
    inline int Class = 0x8;
    inline int Next  = 0x20;
    inline int Name  = 0x28;
}

// ─── UWorld / ULevel ──────────────────────────────────────────────────
namespace World {
    inline int PersistentLevel = 0x30;
}

namespace Level {
    inline int Actors      = 0x98;   // AActors array
    inline int ActorsCount = 0xA0;   // AActors count
}

// ═══════════════════════════════════════════════════════════════════════
//  Apply version-specific patches
// ═══════════════════════════════════════════════════════════════════════

inline void configure(int engineVersion) {
    isUE423 = (engineVersion / 100 >= 423);
    isUE422 = (engineVersion / 100 == 422);
    isUE418 = (engineVersion / 100 >= 418);

    if (isUE423) {
        // FNamePool era
        ObjArray::NumElements = 0x14;
        ObjArray::NumChunks   = 0x1C;
        UFunc::FunctionFlags  = 0xB0;  // or 0xC0 for Apex/Fortnite
        UFunc::Func           = 0xD8;  // or 0xE8
        UProp::ElementSize    = 0x38;
        UProp::PropertyFlags  = 0x40;
        UProp::OffsetInternal = 0x4C;
        UProp::Size           = 0x78;
        UStruct::SuperStruct  = 0x40;
        UStruct::ChildProperties = 0x50;
    } else {
        // TNameEntryArray era
        ObjArray::NumElements = 0xC;
        UFunc::FunctionFlags  = 0x88;
        UFunc::Func           = 0xB0;
        UProp::ElementSize    = 0x34;
        UProp::PropertyFlags  = 0x38;
        UProp::OffsetInternal = 0x44;
        UProp::Size           = 0x70;
        UStruct::SuperStruct  = 0x30;
        UStruct::Children     = 0x38;
        UStruct::ChildProperties = 0x44;

        if (isUE422) {
            // 4.22 boundary: FNameEntry layout changes
            FNameEntry_Old::Index    = 0x8;
            FNameEntry_Old::HashNext = 0x0;
            FNameEntry_Old::NameString = 0xC;
        }
    }

    printf("[*] UE4 offsets configured: %s, %s, %s\n",
           isUE423 ? "FNamePool" : "TNameEntryArray",
           isUE422 ? "4.22-layout" : (isUE423 ? "4.23+" : "pre-4.22"),
           isUE418 ? "ChunkedUObjectArray" : "FixedUObjectArray");
}

} // namespace Offsets
