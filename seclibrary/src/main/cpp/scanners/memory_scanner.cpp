#include "memory_scanner.h"
#include "scanner_utils.h"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        const std::vector<std::string> kSuspiciousMapKeywords = {
                "frida", "xposed", "lsposed", "substrate", "zygisk", "riru",
                "magisk", "linjector", "gum-js-loop", "gadget"
        };

        bool isAnonymousPath(const std::string& path) {
            if (path.empty()) return true;
            size_t start = path.find_first_not_of(" \t");
            if (start == std::string::npos) return true;
            const std::string trimmed = path.substr(start);
            return trimmed[0] == '[';
        }

    }  // namespace

    std::vector<std::string> scanMemory() {
        std::vector<std::string> result;

        std::ifstream maps("/proc/self/maps");
        if (!maps) {
            result.push_back(evidence("SUSPICIOUS_MAP", true, 96, "HIGH",
                                      formatDetails("maps unreadable", {})));
            result.push_back(evidence("ANONYMOUS_EXECUTABLE_MEMORY", false, 86, "HIGH",
                                      formatDetails("maps unreadable", {})));
            result.push_back(evidence("RWX_MEMORY", false, 94, "HIGH",
                                      formatDetails("maps unreadable", {})));
            result.push_back(evidence("EXECUTABLE_MEMORY", false, 86, "HIGH",
                                      formatDetails("maps unreadable", {})));
            return result;
        }

        bool suspiciousMapFound = false;
        bool anonymousExecutable = false;
        bool anonymousExecutableWritable = false;
        bool rwxFound = false;
        bool rxAnonymousFound = false;

        std::string suspiciousLine;
        std::string rwxLine;
        std::string anonExecLine;

        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream fields(line);
            std::string address, permissions, offset, device, inode, path;
            fields >> address >> permissions >> offset >> device >> inode;
            std::getline(fields, path);

            if (!suspiciousMapFound && containsAny(line, kSuspiciousMapKeywords)) {
                suspiciousMapFound = true;
                suspiciousLine = line;
            }

            const bool readable   = permissions.find('r') != std::string::npos;
            const bool writable   = permissions.find('w') != std::string::npos;
            const bool executable = permissions.find('x') != std::string::npos;

            const bool anonymous = isAnonymousPath(path);

            if (executable && anonymous) {
                anonymousExecutable = true;
                if (anonExecLine.empty()) anonExecLine = line;
                if (writable) anonymousExecutableWritable = true;
                else rxAnonymousFound = true;
            }

            if (readable && writable && executable) {
                if (!rwxFound) {
                    rwxFound = true;
                    rwxLine = line;
                }
            }
        }

        // ---- SUSPICIOUS_MAP ----
        if (suspiciousMapFound) {
            result.push_back(evidence("SUSPICIOUS_MAP", true, 96, "HIGH",
                                      formatDetails("suspicious map", {suspiciousLine})));
        } else {
            result.push_back(evidence("SUSPICIOUS_MAP", false, 100, "INFO",
                                      formatDetails("map signals normal", {})));
        }

        // ---- ANONYMOUS_EXECUTABLE_MEMORY ----
        if (anonymousExecutableWritable) {
            result.push_back(evidence("ANONYMOUS_EXECUTABLE_MEMORY", true, 86, "HIGH",
                                      formatDetails("anonymous rwx executable", {anonExecLine})));
        } else if (anonymousExecutable) {
            result.push_back(evidence("ANONYMOUS_EXECUTABLE_MEMORY", false, 86, "HIGH",
                                      formatDetails("anonymous rx only", {"informational"})));
        } else {
            result.push_back(evidence("ANONYMOUS_EXECUTABLE_MEMORY", false, 86, "HIGH",
                                      formatDetails("none", {})));
        }

        // ---- RWX_MEMORY ----
        if (rwxFound) {
            result.push_back(evidence("RWX_MEMORY", true, 94, "HIGH",
                                      formatDetails("rwx mapping", {rwxLine})));
        } else {
            result.push_back(evidence("RWX_MEMORY", false, 100, "INFO",
                                      formatDetails("no rwx mapping", {})));
        }

        // ---- EXECUTABLE_MEMORY ----
        if (anonymousExecutableWritable) {
            result.push_back(evidence("EXECUTABLE_MEMORY", true, 86, "HIGH",
                                      formatDetails("writable executable mapping", {anonExecLine})));
        } else if (rxAnonymousFound) {
            result.push_back(evidence("EXECUTABLE_MEMORY", false, 86, "HIGH",
                                      formatDetails("rx anonymous only", {"informational"})));
        } else {
            result.push_back(evidence("EXECUTABLE_MEMORY", false, 86, "HIGH",
                                      formatDetails("normal", {})));
        }

        return result;
    }

}  // namespace security_scanners