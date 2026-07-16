/*
 * profile.h - Profile data and INI output
 *
 * Ported from ProfileGenerator/ProfileGenerator.h
 * Uses mINI library (header-only, cross-platform).
 */

#pragma once
#include <string>
#include <sstream>
#include <iostream>
#include <cstdint>

namespace mINI {
    // Forward declarations for the mini ini library
    class INIFile;
    class INIStructure;
}

class Profile {
public:
    int32_t EngineVersion = 0;
    bool IsUsing4_22 = false;
    bool UseFNamePool = false;
    bool IsUsingFChunkedFixedUObjectArray = false;

    int64_t GNameOffset = 0;
    int64_t GObjectOffset = 0;
    int64_t GWorldOffset = 0;

    int64_t GameStateInitOffset = 0;
    int64_t BeginPlayOffset = 0;
    int64_t StaticLoadObjectOffset = 0;
    int64_t SpawnActorFTransOffset = 0;
    int64_t CallFunctionByNameWithArgumentsOffset = 0;
    int64_t ProcessEventOffset = 0;

    // UE4 version helpers
    bool IsUE4_23_Plus() const { return EngineVersion / 100 >= 423; }
    bool IsUE4_18_Plus() const { return EngineVersion / 100 >= 418; }
};

// Global profile instance
inline Profile gProfile;

static std::string decToHex(int64_t dec) {
    std::stringstream ss;
    ss << "0x" << std::hex << dec;
    return ss.str();
}

// Generate output .profile INI file
// The original uses mINI which is header-only and cross-platform
// We include it from mini/ini.h
inline bool genProfile(const std::string& profileName) {
    // We'll write the profile manually to avoid depending on mINI at build time
    // (mINI is C++17 compatible and works, but for simplicity let's write directly)
    std::string filename = profileName + ".profile";

    FILE* f = fopen(filename.c_str(), "w");
    if (!f) {
        fprintf(stderr, "[!] Failed to create profile file: %s\n", filename.c_str());
        return false;
    }

    fprintf(f, "[GameInfo]\n");
    fprintf(f, "UsesFNamePool=%d\n", gProfile.UseFNamePool ? 1 : 0);
    fprintf(f, "IsUsingFChunkedFixedUObjectArray=%d\n", gProfile.IsUsingFChunkedFixedUObjectArray ? 1 : 0);
    fprintf(f, "IsUsing4_22=%d\n", gProfile.IsUsing4_22 ? 1 : 0);
    fprintf(f, "\n");

    fprintf(f, "[GInfo]\n");
    fprintf(f, "IsGInfoPatterns=0\n");
    fprintf(f, "GName=%s\n", decToHex(gProfile.GNameOffset).c_str());
    fprintf(f, "GObject=%s\n", decToHex(gProfile.GObjectOffset).c_str());
    fprintf(f, "GWorld=%s\n", decToHex(gProfile.GWorldOffset).c_str());
    fprintf(f, "\n");

    fprintf(f, "[FunctionInfo]\n");
    fprintf(f, "IsFunctionPatterns=0\n");
    fprintf(f, "GameStateInit=%s\n", decToHex(gProfile.GameStateInitOffset).c_str());
    fprintf(f, "BeginPlay=%s\n", decToHex(gProfile.BeginPlayOffset).c_str());
    fprintf(f, "StaticLoadObject=%s\n", decToHex(gProfile.StaticLoadObjectOffset).c_str());
    fprintf(f, "SpawnActorFTrans=%s\n", decToHex(gProfile.SpawnActorFTransOffset).c_str());
    fprintf(f, "CallFunctionByNameWithArguments=%s\n", decToHex(gProfile.CallFunctionByNameWithArgumentsOffset).c_str());
    fprintf(f, "ProcessEvent=%s\n", decToHex(gProfile.ProcessEventOffset).c_str());

    fclose(f);
    printf("[*] Profile saved as %s\n", filename.c_str());
    return true;
}
