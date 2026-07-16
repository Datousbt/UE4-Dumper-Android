cmake_minimum_required(VERSION 3.10)
project(ue4_dumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimize for size (important for mobile deployment)
set(CMAKE_CXX_FLAGS_RELEASE "-Os -ffunction-sections -fdata-sections -flto")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,--gc-sections -Wl,--strip-all -flto")

# Position-independent code (needed for some Android targets)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Source files (header-only mostly, just one cpp)
add_executable(ue4_dumper
    src/main.cpp
)

# Include the src directory for header resolution
target_include_directories(ue4_dumper PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

# Link against pthread (for std::thread)
find_package(Threads REQUIRED)
target_link_libraries(ue4_dumper PRIVATE Threads::Threads)

# Static link libc++ and libgcc (avoids runtime dependency issues on Android)
if(ANDROID)
    target_link_libraries(ue4_dumper PRIVATE -static-libstdc++ -static-libgcc)
endif()

# Platform-specific compiler flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    message(STATUS "Building for ARM64 (AArch64)")
    target_compile_definitions(ue4_dumper PRIVATE PLATFORM_ARM64=1 PLATFORM_X86_64=0)
    # For ARM64, we need to handle the fact that we're building on x86 but targeting ARM
    # The PLATFORM macros in linux_memory.h handle this correctly based on compiler defines
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    message(STATUS "Building for x86_64")
    target_compile_definitions(ue4_dumper PRIVATE PLATFORM_ARM64=0 PLATFORM_X86_64=1)
else()
    message(WARNING "Unknown target architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Allow easy cross-compilation via toolchain files
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=android.toolchain.cmake ...
