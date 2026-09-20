#include "environment_scanner.h"
#include "scanner_utils.h"

#include <sys/system_properties.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        std::string property(const char* name) {
            char value[PROP_VALUE_MAX] = {};
            __system_property_get(name, value);
            return value;
        }

        std::string trimTrailingWhitespace(std::string value) {
            while (!value.empty() &&
                   (value.back() == '\n' || value.back() == '\r' ||
                    value.back() == ' '  || value.back() == '\t')) {
                value.pop_back();
            }
            return value;
        }

        bool hasRwOption(const std::string& options) {
            std::istringstream stream(options);
            std::string opt;
            while (std::getline(stream, opt, ',')) {
                if (opt == "rw") return true;
            }
            return false;
        }

        bool isSystemMountPoint(const std::string& mountPoint) {
            return mountPoint == "/system"
                   || mountPoint == "/system_ext"
                   || mountPoint == "/vendor"
                   || mountPoint == "/product"
                   || mountPoint == "/odm";
        }

    }  // namespace

    std::vector<std::string> scanEnvironment() {
        std::vector<std::string> result;

        const std::string debuggable  = trimTrailingWhitespace(property("ro.debuggable"));
        const std::string secure      = trimTrailingWhitespace(property("ro.secure"));
        const std::string tags        = trimTrailingWhitespace(property("ro.build.tags"));
        const std::string fingerprint = trimTrailingWhitespace(property("ro.build.fingerprint"));
        const std::string hardware    = trimTrailingWhitespace(property("ro.hardware"));
        const std::string qemu        = trimTrailingWhitespace(property("ro.kernel.qemu"));

        // ---- SYSTEM_PROPERTY ----
        {
            std::vector<std::string> hits;
            if (debuggable == "1") hits.push_back("ro.debuggable=1");
            if (secure == "0")     hits.push_back("ro.secure=0");

            if (!hits.empty()) {
                result.push_back(evidence("SYSTEM_PROPERTY", true, 90, "MEDIUM",
                                          formatDetails(std::to_string(hits.size()) + " properties", hits)));
            } else {
                result.push_back(evidence("SYSTEM_PROPERTY", false, 100, "INFO",
                                          formatDetails("properties normal", {})));
            }
        }

        // ---- TEST_KEYS ----
        result.push_back(evidence("TEST_KEYS", containsAny(tags, {"test-keys"}), 88, "MEDIUM",
                                  formatDetails(containsAny(tags, {"test-keys"}) ? "test-keys" : "release-keys",
                                                {"ro.build.tags=" + tags})));

        // ---- SELINUX ----
        {
            const std::string selinux = trimTrailingWhitespace(
                    readFile("/sys/fs/selinux/enforce"));
            const bool permissive = !selinux.empty() && selinux == "0";
            result.push_back(evidence("SELINUX", permissive, 94, "HIGH",
                                      formatDetails(permissive ? "permissive" : "enforcing",
                                                    {"enforce=" + selinux})));
        }

        // ---- EMULATOR ----
        {
            const bool emulator =
                    qemu == "1"
                    || containsAny(hardware, {"goldfish", "ranchu", "vbox"})
                    || containsAny(fingerprint, {"generic", "emulator", "sdk_gphone"});
            result.push_back(evidence("EMULATOR", emulator, 78, "MEDIUM",
                                      formatDetails(emulator ? "emulator detected" : "real device",
                                                    {"qemu=" + qemu, "hardware=" + hardware})));
        }

        // ---- MOUNT_STATE ----
        {
            std::ifstream mounts("/proc/self/mountinfo");
            if (!mounts) {
                result.push_back(evidence("MOUNT_STATE", true, 90, "HIGH",
                                          "mountinfo-unreadable"));
            } else {
                bool writableSystem = false;
                std::string hitLine;
                std::string line;
                while (std::getline(mounts, line)) {
                    const std::string normalized = lower(line);
                    const size_t separator = normalized.find(" - ");
                    const std::string mountFields = separator == std::string::npos
                                                    ? normalized
                                                    : normalized.substr(0, separator);

                    std::istringstream iss(mountFields);
                    std::string token;
                    std::vector<std::string> fields;
                    while (iss >> token) fields.push_back(token);
                    if (fields.size() < 6) continue;

                    const std::string& mountPoint = fields[4];
                    const std::string& options = fields[5];

                    if (hasRwOption(options) && isSystemMountPoint(mountPoint)) {
                        writableSystem = true;
                        hitLine = line;
                        break;
                    }
                }
                if (writableSystem) {
                    result.push_back(evidence("MOUNT_STATE", true, 92, "HIGH",
                                              formatDetails("writable system mount", {hitLine})));
                } else {
                    result.push_back(evidence("MOUNT_STATE", false, 100, "INFO",
                                              formatDetails("system mounts normal", {})));
                }
            }
        }

        return result;
    }

}  // namespace security_scanners