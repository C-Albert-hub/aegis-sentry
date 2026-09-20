cmake_minimum_required(VERSION 3.22.1)

project("seclibrary")

add_library(${CMAKE_PROJECT_NAME} SHARED
        native_security.cpp
        native_scanner.cpp
        scanners/proc_scanner.cpp
        scanners/thread_scanner.cpp
        scanners/scanner_utils.cpp
        scanners/scanner_utils.h
        scanners/fd_scanner.cpp
        scanners/debug_scanner.cpp
        scanners/memory_scanner.cpp
        scanners/elf_scanner.cpp
        scanners/integrity_scanner.cpp
        scanners/app_scanner.cpp
        scanners/root_scanner.cpp
        scanners/environment_scanner.cpp
)

target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_17)

# 编译时基准（先填 0，走运行时记录分支）
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
        EXPECTED_TEXT_HASH=0ULL
        EXPECTED_RODATA_HASH=0ULL
        EXPECTED_GOT_HASH=0ULL
        EXPECTED_APK_HASH=0ULL
)

target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
        -Wl,-z,now
        -Wl,-z,relro
)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        dl
)