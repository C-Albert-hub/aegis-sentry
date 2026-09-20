#ifndef AWESOME_SCANNER_UTILS_H
#define AWESOME_SCANNER_UTILS_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace security_scanners {

    inline std::string lower(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    inline std::string clean(std::string value) {
        for (char &c : value) {
            if (c == '|') c = '_';
        }
        return value;
    }

    inline std::string evidence(const char *type, bool detected, int confidence,
                                const char *severity, const std::string &value) {
        std::ostringstream out;
        out << type << '|' << (detected ? '1' : '0') << '|' << confidence << '|'
            << severity << '|' << clean(value);
        return out.str();
    }

    inline bool containsAny(const std::string &value, const std::vector<std::string> &keywords) {
        std::string normalized = lower(value);
        for (const std::string &keyword : keywords) {
            if (normalized.find(lower(keyword)) != std::string::npos) return true;
        }
        return false;
    }

    inline bool exists(const char *path) {
        return access(path, F_OK) == 0;
    }

    inline std::string readFile(const std::string &path) {
        std::ifstream input(path);
        if (!input) return {};
        std::ostringstream content;
        content << input.rdbuf();
        return content.str();
    }

    inline std::string statusValue(const std::string &status, const std::string &key) {
        std::istringstream input(status);
        std::string line;
        while (std::getline(input, line)) {
            if (line.rfind(key, 0) == 0) {
                size_t separator = line.find(':');
                return separator == std::string::npos ? "" : line.substr(separator + 1);
            }
        }
        return {};
    }

    // ---- dladdr-based self introspection ----
    uintptr_t selfBase();
    std::string selfPath();
    bool isAddressInSelf(uintptr_t addr);

    inline std::string toHex(uintptr_t value) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%zx", static_cast<size_t>(value));
        return std::string(buf);
    }

    // ---- 统一的 details 格式 ----
    inline std::string formatDetails(const std::string& summary,
                                     const std::vector<std::string>& items) {
        std::string result;
        if (!summary.empty()) {
            result = summary;
        }
        if (!items.empty()) {
            if (!result.empty()) result += "\n";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i > 0) result += "\n";
                result += "    • " + items[i];
            }
        }
        return result;
    }

    // ---- ELF address translation + hashing ----
    uintptr_t fileOffsetToVaddr(uintptr_t base, uint64_t fileOffset);
    uint64_t computeHash(const uint8_t *data, size_t size);

    // ---- Runtime baseline storage ----
    void setBaselineDir(const std::string &dir);
    std::string baselineDir();
    uint64_t loadBaseline(const std::string &name);
    bool saveBaseline(const std::string &name, uint64_t hash);

}  // namespace security_scanners

#endif