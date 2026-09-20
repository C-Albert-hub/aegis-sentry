#include "scanner_utils.h"

#include <dlfcn.h>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <mutex>

namespace security_scanners {

    uintptr_t selfBase() {
        Dl_info info;
        if (dladdr(reinterpret_cast<void*>(&selfBase), &info) != 0
            && info.dli_fbase != nullptr) {
            return reinterpret_cast<uintptr_t>(info.dli_fbase);
        }
        return 0;
    }

    std::string selfPath() {
        Dl_info info;
        if (dladdr(reinterpret_cast<void*>(&selfBase), &info) != 0
            && info.dli_fname != nullptr) {
            return std::string(info.dli_fname);
        }
        return std::string();
    }

    bool isAddressInSelf(uintptr_t addr) {
        const uintptr_t self = selfBase();
        if (self == 0 || addr == 0) return false;
        Dl_info info;
        if (dladdr(reinterpret_cast<void*>(addr), &info) == 0) return false;
        return reinterpret_cast<uintptr_t>(info.dli_fbase) == self;
    }

    uintptr_t fileOffsetToVaddr(uintptr_t base, uint64_t fileOffset) {
        if (base == 0) return 0;

        const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
        if (std::memcmp(p, ELFMAG, SELFMAG) != 0) return 0;

        const unsigned char elfClass = p[EI_CLASS];

        if (elfClass == ELFCLASS64) {
            const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
            const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(base + ehdr->e_phoff);
            for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                if (phdrs[i].p_type != PT_LOAD) continue;
                const uint64_t start = phdrs[i].p_offset;
                const uint64_t end   = phdrs[i].p_offset + phdrs[i].p_filesz;
                if (fileOffset >= start && fileOffset < end) {
                    return base + phdrs[i].p_vaddr + (fileOffset - start);
                }
            }
        } else if (elfClass == ELFCLASS32) {
            const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);
            const Elf32_Phdr* phdrs = reinterpret_cast<const Elf32_Phdr*>(base + ehdr->e_phoff);
            for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                if (phdrs[i].p_type != PT_LOAD) continue;
                const uint64_t start = phdrs[i].p_offset;
                const uint64_t end   = phdrs[i].p_offset + phdrs[i].p_filesz;
                if (fileOffset >= start && fileOffset < end) {
                    return base + phdrs[i].p_vaddr + (fileOffset - start);
                }
            }
        }
        return 0;
    }

    uint64_t computeHash(const uint8_t* data, size_t size) {
        uint64_t h = 1469598103934665603ULL;
        for (size_t i = 0; i < size; ++i) {
            h ^= data[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    // ---- Runtime baseline ----
    namespace {
        std::string g_baselineDir;
        std::mutex g_baselineMutex;

        std::string baselineFilePath(const std::string& name) {
            if (g_baselineDir.empty()) return {};
            return g_baselineDir + "/" + name + ".baseline";
        }
    }

    void setBaselineDir(const std::string& dir) {
        std::lock_guard<std::mutex> lock(g_baselineMutex);
        g_baselineDir = dir;
    }

    std::string baselineDir() {
        std::lock_guard<std::mutex> lock(g_baselineMutex);
        return g_baselineDir;
    }

    uint64_t loadBaseline(const std::string& name) {
        std::lock_guard<std::mutex> lock(g_baselineMutex);
        const std::string path = baselineFilePath(name);
        if (path.empty()) return 0;

        std::ifstream input(path);
        if (!input) return 0;

        uint64_t value = 0;
        input >> value;
        return input ? value : 0;
    }

    bool saveBaseline(const std::string& name, uint64_t hash) {
        std::lock_guard<std::mutex> lock(g_baselineMutex);
        const std::string path = baselineFilePath(name);
        if (path.empty()) return false;

        std::ofstream output(path, std::ios::trunc);
        if (!output) return false;

        output << hash;
        return output.good();
    }

}  // namespace security_scanners