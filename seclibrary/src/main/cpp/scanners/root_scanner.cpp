#include "root_scanner.h"
#include "scanner_utils.h"

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        const char* kSuPaths[] = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/vendor/bin/su",
                "/product/bin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/data/local/bin/su",
                "/data/local/xbin/su",
                "/su/bin/su"
        };

        const char* kFrameworkPaths[] = {
                "/data/adb/magisk",
                "/data/adb/ksud",
                "/data/adb/apd",
                "/data/adb/modules",
                "/data/adb/service.d",
                "/data/adb/post-fs-data.d",
                "/sbin/.magisk",
                "/init.magisk.rc",
                "/data/adb/ksu",
                "/data/adb/ap"
        };

        std::string whichInPath(const std::string& command) {
            const char* pathEnv = std::getenv("PATH");
            if (pathEnv == nullptr) return {};
            std::istringstream stream(pathEnv);
            std::string dir;
            while (std::getline(stream, dir, ':')) {
                if (dir.empty()) continue;
                const std::string full = dir + "/" + command;
                if (exists(full.c_str())) return full;
            }
            return {};
        }

        std::string detectRootMount() {
            std::istringstream mounts(readFile("/proc/mounts"));
            std::string line;
            while (std::getline(mounts, line)) {
                const std::string normalized = lower(line);
                const bool isRootMount =
                        normalized.find("magisk") != std::string::npos
                        || normalized.find("kernelsu") != std::string::npos
                        || normalized.find("apatch") != std::string::npos;
                if (!isRootMount) continue;

                std::istringstream iss(line);
                std::string device, mountPoint;
                if (iss >> device >> mountPoint) {
                    return device + " -> " + mountPoint;
                }
                return line;
            }
            return {};
        }

        std::string detectVerifiedBootState() {
            const std::string cmdline = readFile("/proc/cmdline");
            if (cmdline.find("verifiedbootstate=orange") != std::string::npos) {
                return "verifiedbootstate=orange";
            }
            return {};
        }

        std::string joinHits(const std::vector<std::string>& hits,
                             const std::string& label) {
            if (hits.empty()) return "no " + label;
            if (hits.size() == 1) return hits[0];
            std::string details = std::to_string(hits.size()) + " " + label + ":\n";
            for (size_t i = 0; i < hits.size(); ++i) {
                if (i > 0) details += "\n";
                details += "  • " + hits[i];
            }
            return details;
        }

    }  // namespace

    std::vector<std::string> scanRoot() {
        std::vector<std::string> result;

        // ---- ROOT_SU ----
        {
            std::vector<std::string> hits;
            for (const char* path : kSuPaths) {
                if (exists(path)) hits.push_back(path);
            }
            if (hits.empty()) {
                const std::string suInPath = whichInPath("su");
                if (!suInPath.empty()) hits.push_back(suInPath);
            }

            if (!hits.empty()) {
                result.push_back(evidence("ROOT_SU", true, 96, "HIGH",
                                          formatDetails(std::to_string(hits.size()) + " su binaries", hits)));
            } else {
                result.push_back(evidence("ROOT_SU", false, 100, "INFO",
                                          formatDetails("no su binaries", {})));
            }
        }

        // ---- ROOT_FRAMEWORK ----
        {
            std::vector<std::string> hits;
            for (const char* path : kFrameworkPaths) {
                if (exists(path)) hits.push_back(path);
            }
            if (hits.empty()) {
                const char* commands[] = {"magisk", "ksud", "apd"};
                for (const char* cmd : commands) {
                    const std::string found = whichInPath(cmd);
                    if (!found.empty()) hits.push_back(found);
                }
            }

            if (!hits.empty()) {
                result.push_back(evidence("ROOT_FRAMEWORK", true, 92, "HIGH",
                                          formatDetails(std::to_string(hits.size()) + " framework paths", hits)));
            } else {
                result.push_back(evidence("ROOT_FRAMEWORK", false, 100, "INFO",
                                          formatDetails("no framework paths", {})));
            }
        }

        // ---- ROOT_MOUNT ----
        {
            const std::string mount = detectRootMount();
            if (!mount.empty()) {
                result.push_back(evidence("ROOT_MOUNT", true, 88, "MEDIUM",
                                          formatDetails("root mount detected", {mount})));
            } else {
                result.push_back(evidence("ROOT_MOUNT", false, 100, "INFO",
                                          formatDetails("no root mounts", {})));
            }
        }

        // ---- BOOTLOADER ----
        {
            const std::string state = detectVerifiedBootState();
            if (!state.empty()) {
                result.push_back(evidence("BOOTLOADER", true, 85, "MEDIUM",
                                          formatDetails("bootloader unlocked", {state})));
            } else {
                result.push_back(evidence("BOOTLOADER", false, 100, "INFO",
                                          formatDetails("bootloader locked", {})));
            }
        }

        return result;
    }

}  // namespace security_scanners