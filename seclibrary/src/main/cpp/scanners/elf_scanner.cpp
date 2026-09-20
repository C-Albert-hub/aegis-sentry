#include "elf_scanner.h"
#include "scanner_utils.h"

#include <elf.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

        bool readInMemoryElfHeader(uintptr_t base,
                                   unsigned char ident[EI_NIDENT],
                                   uint64_t* outShOff,
                                   uint16_t* outShNum) {
            if (base == 0) return false;

            const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
            std::memcpy(ident, p, EI_NIDENT);
            if (std::memcmp(ident, ELFMAG, SELFMAG) != 0) return false;

            if (ident[EI_CLASS] == ELFCLASS64) {
                const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
                *outShOff = ehdr->e_shoff;
                *outShNum = ehdr->e_shnum;
            } else if (ident[EI_CLASS] == ELFCLASS32) {
                const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);
                *outShOff = ehdr->e_shoff;
                *outShNum = ehdr->e_shnum;
            } else {
                return false;
            }
            return true;
        }

    }  // namespace

    std::vector<std::string> scanElf() {
        std::vector<std::string> result;

        const uintptr_t base = selfBase();
        if (base == 0) {
            result.push_back(evidence("ELF_HEADER", false, 100, "INFO",
                                      formatDetails("self base unavailable", {})));
            result.push_back(evidence("NATIVE_PATH", false, 100, "INFO",
                                      formatDetails("self base unavailable", {})));
            result.push_back(evidence("ELF_SECTION", false, 100, "INFO",
                                      formatDetails("self base unavailable", {})));
            return result;
        }

        unsigned char ident[EI_NIDENT] = {};
        uint64_t shoff = 0;
        uint16_t shnum = 0;
        const bool valid = readInMemoryElfHeader(base, ident, &shoff, &shnum);

        const std::string path = selfPath();
        const std::string pathForReport = path.empty() ? "in-memory" : path;

        // ---- ELF_HEADER ----
        {
            std::vector<std::string> items = {
                    "base=" + toHex(base),
                    "class=" + std::to_string(valid ? ident[EI_CLASS] : 0),
                    "data=" + std::to_string(valid ? ident[EI_DATA] : 0)
            };
            result.push_back(evidence("ELF_HEADER", !valid, 95, "HIGH",
                                      formatDetails(valid ? "elf header verified"
                                                          : "elf header invalid",
                                                    items)));
        }

        // ---- NATIVE_PATH ----
        result.push_back(evidence("NATIVE_PATH", false, 100, "INFO",
                                  formatDetails("native path resolved", {pathForReport})));

        // ---- ELF_SECTION ----
        {
            const bool sectionsPresent = valid && shoff != 0 && shnum != 0;
            if (!valid) {
                result.push_back(evidence("ELF_SECTION", true, 90, "MEDIUM",
                                          formatDetails("elf invalid", {})));
            } else if (!sectionsPresent) {
                result.push_back(evidence("ELF_SECTION", false, 90, "MEDIUM",
                                          formatDetails("section table stripped",
                                                        {"normal for release"})));
            } else {
                result.push_back(evidence("ELF_SECTION", false, 90, "MEDIUM",
                                          formatDetails("section table present",
                                                        {"shoff=" + toHex(shoff),
                                                         "shnum=" + std::to_string(shnum)})));
            }
        }

        return result;
    }

}  // namespace security_scanners