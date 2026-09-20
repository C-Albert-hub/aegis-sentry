#include "debug_scanner.h"
#include "scanner_utils.h"

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        std::string parseStatusField(const std::string& status, const std::string& key) {
            const std::string prefix = key + ":";
            std::istringstream input(status);
            std::string line;
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

        long parseTracerPid(const std::string& status) {
            if (status.empty()) return -1;
            const std::string value = parseStatusField(status, "TracerPid");
            if (value.empty()) return -1;
            return std::strtol(value.c_str(), nullptr, 10);
        }

        std::string tracerProcessName(long tracerPid) {
            if (tracerPid <= 0) return {};
            std::string result = readFile(
                    "/proc/" + std::to_string(tracerPid) + "/comm");
            while (!result.empty() &&
                   (result.back() == '\n' || result.back() == '\r')) {
                result.pop_back();
            }
            return result;
        }

    }  // namespace

    std::vector<std::string> scanDebug() {
        std::vector<std::string> result;

        const std::string status = readFile("/proc/self/status");
        const long tracer = parseTracerPid(status);

        // ---- TRACER_PID ----
        if (tracer < 0) {
            result.push_back(evidence("TRACER_PID", true, 95, "HIGH",
                                      formatDetails("self status unreadable", {})));
        } else {
            result.push_back(evidence("TRACER_PID", tracer > 0, 99, "HIGH",
                                      formatDetails(tracer > 0 ? "process traced"
                                                               : "process not traced",
                                                    {"tracer-pid=" + std::to_string(tracer)})));
        }

        // ---- TRACER_PARENT ----
        if (tracer > 0) {
            const std::string tracerStatus = readFile(
                    "/proc/" + std::to_string(tracer) + "/status");
            const std::string parent = parseStatusField(tracerStatus, "PPid");
            const std::string name = tracerProcessName(tracer);

            std::vector<std::string> items;
            items.push_back("tracer-pid=" + std::to_string(tracer));
            if (!parent.empty()) items.push_back("tracer-ppid=" + parent);
            if (!name.empty())   items.push_back("tracer-name=" + name);

            result.push_back(evidence("TRACER_PARENT", true, 90, "HIGH",
                                      formatDetails("tracer parent resolved", items)));
            result.push_back(evidence("PROCESS_PARENT", true, 90, "HIGH",
                                      formatDetails("tracer process resolved", items)));
        } else {
            result.push_back(evidence("TRACER_PARENT", false, 100, "INFO",
                                      formatDetails("no tracer attached", {})));
            result.push_back(evidence("PROCESS_PARENT", false, 100, "INFO",
                                      formatDetails("no tracer attached", {})));
        }

        return result;
    }

}  // namespace security_scanners