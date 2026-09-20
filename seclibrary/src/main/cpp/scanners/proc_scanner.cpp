#include "proc_scanner.h"
#include "scanner_utils.h"

#include <sstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        std::string parseStatusField(const std::string& status, const std::string& key) {
            std::istringstream input(status);
            std::string line;
            const std::string prefix = key + ":";
            while (std::getline(input, line)) {
                if (line.rfind(prefix, 0) == 0) {
                    const size_t separator = line.find(':');
                    if (separator == std::string::npos) return {};
                    std::string value = line.substr(separator + 1);
                    const size_t start = value.find_first_not_of(" \t");
                    if (start == std::string::npos) return {};
                    return value.substr(start);
                }
            }
            return {};
        }

        char parseProcState(const std::string& stat) {
            const size_t closing = stat.rfind(')');
            if (closing == std::string::npos) return '\0';
            if (stat.size() <= closing + 2) return '\0';
            return stat[closing + 2];
        }

        bool isSuspiciousProcState(char state) {
            return state == 't' || state == 'T' || state == 'Z' || state == 'D';
        }

        std::string detectSuspiciousCmdline() {
            const std::string cmdline = readFile("/proc/self/cmdline");
            if (cmdline.empty()) return {};
            const std::string normalized = lower(cmdline);
            if (normalized.find("frida") != std::string::npos) return "cmdline:frida";
            if (normalized.find("gdb") != std::string::npos) return "cmdline:gdb";
            if (normalized.find("lldb") != std::string::npos) return "cmdline:lldb";
            if (normalized.find("xposed") != std::string::npos) return "cmdline:xposed";
            return {};
        }

        std::string detectSuspiciousEnviron() {
            const std::string environ = readFile("/proc/self/environ");
            if (environ.empty()) return {};
            const std::string normalized = lower(environ);
            if (normalized.find("frida") != std::string::npos) return "environ:frida";
            if (normalized.find("xposed") != std::string::npos) return "environ:xposed";
            if (normalized.find("ld_preload") != std::string::npos) return "environ:LD_PRELOAD";
            return {};
        }

    }  // namespace

    std::vector<std::string> scanProc() {
        std::vector<std::string> result;

        // ---- PROCESS_STATUS ----
        {
            const std::string status = readFile("/proc/self/status");
            bool suspicious = false;
            std::string summary;
            std::vector<std::string> items;

            if (status.empty()) {
                suspicious = true;
                summary = "self status unreadable";
            } else {
                const std::string tracerPid = parseStatusField(status, "TracerPid");
                const std::string seccomp = parseStatusField(status, "Seccomp");

                if (!tracerPid.empty() && tracerPid != "0") {
                    suspicious = true;
                    summary = "process traced";
                } else {
                    summary = "process not traced";
                }

                if (!tracerPid.empty()) items.push_back("tracer-pid=" + tracerPid);
                if (!seccomp.empty())   items.push_back("seccomp=" + seccomp);
            }

            result.push_back(evidence("PROCESS_STATUS", suspicious, 95, "HIGH",
                                      formatDetails(summary, items)));
        }

        // ---- PROCESS_STATE ----
        {
            const std::string stat = readFile("/proc/self/stat");
            bool suspicious = false;
            std::string summary;
            std::vector<std::string> items;

            if (stat.empty()) {
                suspicious = true;
                summary = "self stat unreadable";
            } else {
                const char state = parseProcState(stat);
                if (state == '\0') {
                    suspicious = true;
                    summary = "self stat malformed";
                } else {
                    suspicious = isSuspiciousProcState(state);
                    summary = suspicious ? "process state suspicious"
                                         : "process state normal";
                    items.push_back("state=" + std::string(1, state));
                }
            }

            result.push_back(evidence("PROCESS_STATE", suspicious, 90, "MEDIUM",
                                      formatDetails(summary, items)));
        }

        // ---- PROCESS_CMDLINE ----
        {
            const std::string hit = detectSuspiciousCmdline();
            const bool detected = !hit.empty();
            std::vector<std::string> items;
            if (detected) items.push_back(hit);
            result.push_back(evidence("PROCESS_CMDLINE", detected, 88, "HIGH",
                                      formatDetails(detected ? "cmdline suspicious"
                                                             : "cmdline clean",
                                                    items)));
        }

        // ---- PROCESS_ENVIRON ----
        {
            const std::string hit = detectSuspiciousEnviron();
            const bool detected = !hit.empty();
            std::vector<std::string> items;
            if (detected) items.push_back(hit);
            result.push_back(evidence("PROCESS_ENVIRON", detected, 86, "MEDIUM",
                                      formatDetails(detected ? "environ suspicious"
                                                             : "environ clean",
                                                    items)));
        }

        return result;
    }

}  // namespace security_scanners