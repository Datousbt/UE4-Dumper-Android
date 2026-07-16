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

# Architecture is auto-detected via compiler builtins (__aarch64__ / __x86_64__)
# in src/linux_memory.h. DO NOT set PLATFORM_* here.

# Source files
add_executable(ue4_dumper
    src/main.cpp
)

target_include_directories(ue4_dumper PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

# Link against pthread (for std::thread)
find_package(Threads REQUIRED)
target_link_libraries(ue4_dumper PRIVATE Threads::Threads)

# Static link libc++ and libgcc on Android
if(ANDROID)
    target_link_libraries(ue4_dumper PRIVATE -static-libstdc++ -static-libgcc)
endif()
