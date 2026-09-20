#include "native_scanner.h"
#include "scanners/debug_scanner.h"
#include "scanners/elf_scanner.h"
#include "scanners/fd_scanner.h"
#include "scanners/integrity_scanner.h"
#include "scanners/app_scanner.h"
#include "scanners/environment_scanner.h"
#include "scanners/memory_scanner.h"
#include "scanners/proc_scanner.h"
#include "scanners/root_scanner.h"
#include "scanners/scanner_utils.h"
#include "scanners/thread_scanner.h"

#include <cstdio>
#include <string>
#include <vector>

std::vector<std::string> scanNativeModule(NativeModule module) {
    return scanNativeModule(module, "");
}

std::vector<std::string> scanNativeModule(NativeModule module, const std::string& apkPath) {
    using namespace security_scanners;
    switch (module) {
        case NativeModule::ROOT:        return scanRoot();
        case NativeModule::DEBUG:       return scanDebug();
        case NativeModule::THREAD:      return scanThreads();
        case NativeModule::FD:          return scanFds();
        case NativeModule::MEMORY:      return scanMemory();
        case NativeModule::ELF:         return scanElf();
        case NativeModule::INTEGRITY:   return scanIntegrity();
        case NativeModule::APP:         return scanApp(apkPath);
        case NativeModule::ENVIRONMENT: return scanEnvironment();
        case NativeModule::PROC:        return scanProc();
    }
    return {evidence("UNKNOWN_MODULE", true, 100, "MEDIUM",
                     "unknown-native-module")};
}

namespace {

    bool hasDetection(const std::vector<std::string>& list, const std::string& type) {
        const std::string prefix = type + "|1|";
        for (const std::string& item : list) {
            if (item.rfind(prefix, 0) == 0) return true;
        }
        return false;
    }

    struct ScanCache {
        bool rootScanned = false;
        bool rootResult = false;
        bool fridaScanned = false;
        bool fridaResult = false;
    };

    ScanCache& cache() {
        static ScanCache instance;
        return instance;
    }

}  // namespace

bool nativeRootDetected() {
    ScanCache& c = cache();
    if (c.rootScanned) return c.rootResult;

    const auto items = scanNativeModule(NativeModule::ROOT);
    c.rootResult = hasDetection(items, "ROOT_SU")
                   || hasDetection(items, "ROOT_FRAMEWORK")
                   || hasDetection(items, "ROOT_MOUNT")
                   || hasDetection(items, "BOOTLOADER");
    c.rootScanned = true;
    return c.rootResult;
}

bool nativeFridaDetected() {
    ScanCache& c = cache();
    if (c.fridaScanned) return c.fridaResult;

    bool found = false;
    for (NativeModule module : {NativeModule::THREAD,
                                NativeModule::FD,
                                NativeModule::MEMORY}) {
        const auto items = scanNativeModule(module);
        if (hasDetection(items, "SUSPICIOUS_THREAD")
            || hasDetection(items, "SUSPICIOUS_MAP")
            || hasDetection(items, "SUSPICIOUS_FD")
            || hasDetection(items, "SUSPICIOUS_SOCKET")) {
            found = true;
            break;
        }
    }
    c.fridaResult = found;
    c.fridaScanned = true;
    return c.fridaResult;
}

bool nativeRecordBaseline() {
    const auto items = scanNativeModule(NativeModule::INTEGRITY);
    for (const std::string& item : items) {
        if (item.find("baseline-recorded") != std::string::npos) {
            return true;
        }
    }
    return true;
}

void nativeClearBaseline() {
    const std::string dir = security_scanners::baselineDir();
    if (dir.empty()) return;
    const char* names[] = {"text", "rodata"};
    for (const char* name : names) {
        const std::string path = dir + "/" + name + ".baseline";
        std::remove(path.c_str());
    }
}