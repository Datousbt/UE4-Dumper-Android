/*
 * main.cpp - UE4 Dumper for Android/Linux
 *
 * Entry point. Attaches to a running UE4 game process, scans memory
 * for engine internals, and outputs a .profile file for SDK generation.
 *
 * Usage:
 *   ./ue4_dumper <PID> [--ue4-version <ver>] [--output <name>]
 *
 * Examples:
 *   ./ue4_dumper 12345
 *   ./ue4_dumper 12345 --ue4-version 426
 *   ./ue4_dumper 12345 --ue4-version 426 --output MyGame
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>

#include "linux_memory.h"
#include "algorithm.h"
#include "profile.h"
#include "ue4_scanner.h"

static void printBanner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║         UE4 Function Address Finder                  ║\n");
    printf("║         Android / Linux Edition v1.0                  ║\n");
    printf("║         Ported from PotatoPie's UnrealScan            ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void printUsage(const char* prog) {
    printf("Usage: %s <PID> [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --ue4-version <ver>   UE4 engine version (e.g. 426 for 4.26)\n");
    printf("  --output <name>       Output profile name (default: game profile)\n");
    printf("  --list                 List processes (find UE4 game PID)\n");
    printf("  --help                 Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s 12345                          # Auto-detect version\n", prog);
    printf("  %s 12345 --ue4-version 426        # Specify UE 4.26\n", prog);
    printf("  %s 12345 --output MyGame          # Custom output name\n", prog);
    printf("\n");
    printf("Note: ROOT is required to read other process memory.\n");
    printf("      Run as: su -c '%s <PID>'\n", prog);
    printf("\n");
}

static void listProcesses() {
    printf("[*] Scanning for UE4 game processes...\n");
    printf("[*] Looking for libUE4.so in /proc/*/maps ...\n\n");

    DIR* proc = opendir("/proc");
    if (!proc) {
        fprintf(stderr, "[!] Cannot open /proc\n");
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        // Check if directory name is numeric (PID)
        bool isPid = true;
        for (char* p = entry->d_name; *p; p++) {
            if (*p < '0' || *p > '9') { isPid = false; break; }
        }
        if (!isPid) continue;

        // Check /proc/<pid>/maps for libUE4.so
        char mapsPath[256];
        snprintf(mapsPath, sizeof(mapsPath), "/proc/%s/maps", entry->d_name);

        FILE* f = fopen(mapsPath, "r");
        if (!f) continue;

        char line[512];
        bool found = false;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "libUE4.so") || strstr(line, "libUnreal.so")) {
                found = true;

                // Also read cmdline to get process name
                char cmdPath[256], cmdline[256] = {};
                snprintf(cmdPath, sizeof(cmdPath), "/proc/%s/cmdline", entry->d_name);
                FILE* cf = fopen(cmdPath, "r");
                if (cf) {
                    fread(cmdline, 1, sizeof(cmdline) - 1, cf);
                    fclose(cf);
                }

                printf("  PID: %-8s  Name: %s\n", entry->d_name,
                       cmdline[0] ? cmdline : "(unknown)");
                break;
            }
        }
        fclose(f);
    }
    closedir(proc);
}

int main(int argc, char* argv[]) {
    printBanner();

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // Check for --help
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printUsage(argv[0]);
        return 0;
    }

    // Check for --list
    if (strcmp(argv[1], "--list") == 0) {
        listProcesses();
        return 0;
    }

    // Parse PID
    int pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "[!] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    // Parse optional arguments
    int engineVersion = 0;
    std::string outputName = "ue4_game";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--ue4-version") == 0 && i + 1 < argc) {
            engineVersion = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            outputName = argv[i + 1];
            i++;
        }
    }

    // Check root
    if (getuid() != 0) {
        printf("[!] WARNING: Not running as root. Process memory access will likely fail.\n");
        printf("[!] If the tool fails, try: su -c '%s %d'\n\n", argv[0], pid);
    }

    // Open the target process
    printf("[*] Attaching to PID %d...\n", pid);

    // Verify the process exists
    char procPath[64];
    snprintf(procPath, sizeof(procPath), "/proc/%d", pid);
    if (access(procPath, F_OK) != 0) {
        fprintf(stderr, "[!] Process %d does not exist\n", pid);
        return 1;
    }

    ProcessHandle ph;
    if (!ph.open(pid)) {
        fprintf(stderr, "[!] Failed to open process %d. Are you root?\n", pid);
        return 1;
    }

    // Find the UE4 module
    auto* mod = ph.findUE4Module();
    if (!mod) {
        fprintf(stderr, "[!] No UE4 module found in process %d\n", pid);
        fprintf(stderr, "[!] Is this a UE4 game process?\n");
        fprintf(stderr, "[!] Run with --list to see available processes.\n");
        return 1;
    }

    printf("[+] Found UE4 module: %s\n", mod->name.c_str());
    printf("[+] Base address: 0x%lx\n", mod->baseAddress);
    printf("[+] Module size:  0x%zx (%.1f MB)\n", mod->size, mod->size / 1048576.0);

#if PLATFORM_ARM64
    printf("[*] Architecture: ARM64 (AArch64)\n");
#else
    printf("[*] Architecture: x86_64\n");
#endif

    printf("\n");

    // Run the scanner
    if (!scanUE4(ph, engineVersion)) {
        fprintf(stderr, "[!] Scan failed or incomplete\n");
        ph.close();
        return 1;
    }

    // Generate output
    printf("\n[*] Generating profile...\n");
    genProfile(outputName);

    // Summary
    printf("\n");
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║                 SCAN RESULTS                       ║\n");
    printf("╠═══════════════════════════════════════════════════╣\n");
    printf("║  GNames:    0x%-16lx                      ║\n", gProfile.GNameOffset);
    printf("║  GObjects:  0x%-16lx                      ║\n", gProfile.GObjectOffset);
    printf("║  GWorld:    0x%-16lx                      ║\n", gProfile.GWorldOffset);
    printf("║  ProcessEv: 0x%-16lx                      ║\n", gProfile.ProcessEventOffset);
    printf("║  StaticLO:  0x%-16lx                      ║\n", gProfile.StaticLoadObjectOffset);
    printf("║  SpawnAct:  0x%-16lx                      ║\n", gProfile.SpawnActorFTransOffset);
    printf("║  CallFunc:  0x%-16lx                      ║\n", gProfile.CallFunctionByNameWithArgumentsOffset);
    printf("║  InitGame:  0x%-16lx                      ║\n", gProfile.GameStateInitOffset);
    printf("║  BeginPlay: 0x%-16lx                      ║\n", gProfile.BeginPlayOffset);
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("\n[+] Output saved to: %s.profile\n", outputName.c_str());

    ph.close();
    return 0;
}
