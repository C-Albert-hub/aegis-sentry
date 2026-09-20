#ifndef AWESOME_NATIVE_SCANNER_H
#define AWESOME_NATIVE_SCANNER_H

#include <string>
#include <vector>

enum class NativeModule {
    ROOT        = 0,
    DEBUG       = 1,
    THREAD      = 2,
    FD          = 3,
    MEMORY      = 4,
    ELF         = 5,
    INTEGRITY   = 6,
    APP         = 7,
    ENVIRONMENT = 8,
    PROC        = 9
};

std::vector<std::string> scanNativeModule(NativeModule module);
std::vector<std::string> scanNativeModule(NativeModule module, const std::string& apkPath);

bool nativeRootDetected();
bool nativeFridaDetected();

// ---- Runtime baseline ----
bool nativeRecordBaseline();
void nativeClearBaseline();

#endif