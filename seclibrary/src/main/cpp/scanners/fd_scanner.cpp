#include "fd_scanner.h"
#include "scanner_utils.h"

#include <dirent.h>
#include <limits.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace security_scanners {

    namespace {

        const std::vector<std::string> kSuspiciousFdKeywords = {
                "frida", "xposed", "lsposed", "substrate", "zygisk", "riru",
                "magisk", "/data/local/tmp", "/dev/frida", "/data/adb"
        };

        const std::vector<std::string> kSuspiciousSocketKeywords = {
                "frida", "gum", "gmain", "gadget", "linjector", "xposed", "substrate"
        };

        std::unordered_map<std::string, std::string> loadUnixSocketPaths() {
            std::unordered_map<std::string, std::string> result;
            std::istringstream input(readFile("/proc/net/unix"));
            std::string line;
            bool first = true;
            while (std::getline(input, line)) {
                if (first) { first = false; continue; }
                std::istringstream fields(line);
                std::string num, refCount, protocol, flags, type, st, inode, path;
                if (!(fields >> num >> refCount >> protocol >> flags >> type >> st >> inode)) {
                    continue;
                }
                std::getline(fields, path);
                const size_t start = path.find_first_not_of(" \t");
                path = (start != std::string::npos) ? path.substr(start) : "";
                result[inode] = path;
            }
            return result;
        }

        std::string extractSocketInode(const std::string& value) {
            if (value.rfind("socket:[", 0) != 0) return {};
            const size_t end = value.find(']');
            if (end == std::string::npos || end <= 8) return {};
            return value.substr(8, end - 8);
        }

        std::string joinDetails(const std::vector<std::string>& hits,
                                const std::string& header) {
            if (hits.empty()) return header;
            if (hits.size() == 1) return hits[0];
            std::string details = std::to_string(hits.size()) + " " + header + ":\n";
            for (size_t i = 0; i < hits.size(); ++i) {
                if (i > 0) details += "\n";
                details += "  • " + hits[i];
            }
            return details;
        }

    }  // namespace

    std::vector<std::string> scanFds() {
        std::vector<std::string> result;

        std::vector<std::string> fdHits;
        std::vector<std::string> socketHits;

        const auto unixSocketPaths = loadUnixSocketPaths();

        DIR* fds = opendir("/proc/self/fd");
        if (fds != nullptr) {
            dirent* entry;
            char target[PATH_MAX];
            while ((entry = readdir(fds)) != nullptr) {
                if (entry->d_name[0] == '.') continue;

                const std::string path = "/proc/self/fd/" + std::string(entry->d_name);
                const ssize_t length = readlink(path.c_str(), target, sizeof(target) - 1);
                if (length <= 0) continue;
                target[length] = '\0';
                const std::string value = target;

                if (containsAny(value, kSuspiciousFdKeywords)) {
                    fdHits.push_back(value);
                }

                const std::string inode = extractSocketInode(value);
                if (!inode.empty()) {
                    const auto it = unixSocketPaths.find(inode);
                    if (it != unixSocketPaths.end() && !it->second.empty()
                        && containsAny(it->second, kSuspiciousSocketKeywords)) {
                        socketHits.push_back(value + " -> " + it->second);
                    }
                }
            }
            closedir(fds);
        }

        if (!fdHits.empty()) {
            result.push_back(evidence("SUSPICIOUS_FD", true, 94, "HIGH",
                                      formatDetails(std::to_string(fdHits.size()) + " suspicious fds", fdHits)));
        } else {
            result.push_back(evidence("SUSPICIOUS_FD", false, 100, "INFO",
                                      formatDetails("fd-signals-normal", {})));
        }

        if (!socketHits.empty()) {
            result.push_back(evidence("SUSPICIOUS_SOCKET", true, 92, "HIGH",
                                      formatDetails(std::to_string(socketHits.size()) + " suspicious sockets", socketHits)));
        } else {
            result.push_back(evidence("SUSPICIOUS_SOCKET", false, 100, "INFO",
                                      formatDetails("socket-signals-normal", {})));
        }

        return result;
    }

}  // namespace security_scanners