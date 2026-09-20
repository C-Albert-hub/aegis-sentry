#include "thread_scanner.h"
#include "scanner_utils.h"

#include <dirent.h>
#include <sstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        const std::vector<std::string> kSuspiciousThreadNames = {
                "frida", "gum-js-loop", "gmain", "xposed", "substrate",
                "pool-frida", "gdbus", "magisk", "riru", "zygisk"
        };

        std::string parseTracerPid(const std::string& status) {
            std::istringstream input(status);
            std::string line;
            while (std::getline(input, line)) {
                if (line.rfind("TracerPid:", 0) == 0) {
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

        char parseThreadState(const std::string& stat) {
            const size_t closing = stat.rfind(')');
            if (closing == std::string::npos) return '\0';
            if (stat.size() <= closing + 2) return '\0';
            return stat[closing + 2];
        }

        bool isSuspiciousState(char state) {
            return state == 't' || state == 'T' || state == 'Z' || state == 'D';
        }

        std::string trimTrailingWhitespace(std::string value) {
            while (!value.empty() &&
                   (value.back() == '\n' || value.back() == '\r' ||
                    value.back() == ' '  || value.back() == '\t')) {
                value.pop_back();
            }
            return value;
        }

    }  // namespace

    std::vector<std::string> scanThreads() {
        std::vector<std::string> result;

        std::vector<std::string> suspiciousThreads;
        bool tracedFound = false;

        DIR* tasks = opendir("/proc/self/task");
        if (tasks != nullptr) {
            dirent* entry;
            while ((entry = readdir(tasks)) != nullptr) {
                if (entry->d_name[0] == '.') continue;

                const std::string id = entry->d_name;
                const std::string taskBase = "/proc/self/task/" + id + "/";

                std::string name = trimTrailingWhitespace(readFile(taskBase + "comm"));
                const std::string stat = readFile(taskBase + "stat");
                const std::string status = readFile(taskBase + "status");

                const char state = parseThreadState(stat);
                const bool tracedState = isSuspiciousState(state);

                const std::string tracerPid = parseTracerPid(status);
                const bool tracedByPid = !tracerPid.empty() && tracerPid != "0";

                if (containsAny(name, kSuspiciousThreadNames) || tracedState || tracedByPid) {
                    std::string detail = name.empty() ? id : (name + "(" + id + ")");
                    if (tracedState) detail += " state=" + std::string(1, state);
                    if (tracedByPid) detail += " tracer=" + tracerPid;
                    suspiciousThreads.push_back(detail);

                    if (tracedState || tracedByPid) tracedFound = true;
                }
            }
            closedir(tasks);
        }

        // ---- SUSPICIOUS_THREAD ----
        if (!suspiciousThreads.empty()) {
            const std::string summary = std::to_string(suspiciousThreads.size())
                                        + " suspicious threads";
            const std::string details = formatDetails(summary, suspiciousThreads);
            result.push_back(evidence("SUSPICIOUS_THREAD", true, 93, "HIGH", details));
        } else {
            result.push_back(evidence("SUSPICIOUS_THREAD", false, 100, "INFO",
                                      formatDetails("no suspicious threads", {})));
        }

        // ---- THREAD_STATE ----
        if (tracedFound) {
            result.push_back(evidence("THREAD_STATE", true, 88, "MEDIUM",
                                      formatDetails("traced threads detected", {})));
        } else {
            result.push_back(evidence("THREAD_STATE", false, 100, "INFO",
                                      formatDetails("thread states normal", {})));
        }

        return result;
    }

}// namespace security_scanners