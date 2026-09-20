#include "integrity_scanner.h"
#include "scanner_utils.h"

#include <elf.h>
#include <dlfcn.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

#ifndef EXPECTED_TEXT_HASH
#define EXPECTED_TEXT_HASH 0ULL
#endif
#ifndef EXPECTED_RODATA_HASH
#define EXPECTED_RODATA_HASH 0ULL
#endif
#ifndef EXPECTED_GOT_HASH
#define EXPECTED_GOT_HASH 0ULL
#endif

        struct Segment {
            uintptr_t addr;
            size_t size;
            uint32_t flags;
        };

        bool collectLoadSegments(uintptr_t base, std::vector<Segment>& out) {
            if (base == 0) return false;

            const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
            if (std::memcmp(p, ELFMAG, SELFMAG) != 0) return false;

            const unsigned char elfClass = p[EI_CLASS];

            if (elfClass == ELFCLASS64) {
                const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
                if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return false;

                const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(
                        base + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                    if (phdrs[i].p_type != PT_LOAD) continue;
                    if (phdrs[i].p_filesz == 0) continue;
                    out.push_back({
                                          static_cast<uintptr_t>(base)
                                          + static_cast<uintptr_t>(phdrs[i].p_vaddr),
                                          static_cast<size_t>(phdrs[i].p_filesz),
                                          phdrs[i].p_flags
                                  });
                }
            } else if (elfClass == ELFCLASS32) {
                const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);
                if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return false;

                const Elf32_Phdr* phdrs = reinterpret_cast<const Elf32_Phdr*>(
                        base + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                    if (phdrs[i].p_type != PT_LOAD) continue;
                    if (phdrs[i].p_filesz == 0) continue;
                    out.push_back({
                                          static_cast<uintptr_t>(base)
                                          + static_cast<uintptr_t>(phdrs[i].p_vaddr),
                                          static_cast<size_t>(phdrs[i].p_filesz),
                                          phdrs[i].p_flags
                                  });
                }
            } else {
                return false;
            }
            return !out.empty();
        }

        bool findSegment(const std::vector<Segment>& segments,
                         bool requireExec,
                         bool requireWrite,
                         bool requireReadOnly,
                         Segment* out) {
            for (const Segment& seg : segments) {
                const bool exec  = (seg.flags & PF_X) != 0;
                const bool write = (seg.flags & PF_W) != 0;
                const bool read  = (seg.flags & PF_R) != 0;

                if (requireExec && !exec) continue;
                if (requireWrite && !write) continue;
                if (requireReadOnly && (!read || write || exec)) continue;

                *out = seg;
                return true;
            }
            return false;
        }

        struct HashCheck {
            bool tampered;
            std::string details;
        };

        HashCheck checkSegmentHash(const char* label,
                                   const char* baselineName,
                                   const Segment& seg,
                                   uint64_t compileTimeExpected) {
            HashCheck result{false, {}};

            if (seg.addr == 0 || seg.size == 0) {
                result.tampered = true;
                result.details = formatDetails(std::string(label) + " segment missing", {});
                return result;
            }

            const uint64_t actual = computeHash(
                    reinterpret_cast<const uint8_t*>(seg.addr), seg.size);

            uint64_t expected = compileTimeExpected;
            bool fromRuntimeBaseline = false;

            if (expected == 0ULL) {
                expected = loadBaseline(baselineName);
                fromRuntimeBaseline = (expected != 0ULL);
            }

            if (expected == 0ULL) {
                saveBaseline(baselineName, actual);
                result.tampered = false;
                result.details = formatDetails(
                        std::string(label) + " baseline recorded",
                        {"actual=" + toHex(actual),
                         "size=" + std::to_string(seg.size)});
                return result;
            }

            result.tampered = (actual != expected);
            std::vector<std::string> items = {
                    "expected=" + toHex(expected),
                    "actual=" + toHex(actual),
                    "size=" + std::to_string(seg.size),
                    std::string("baseline=") + (fromRuntimeBaseline ? "runtime" : "compile")
            };
            result.details = formatDetails(
                    result.tampered ? std::string(label) + " tampered"
                                    : std::string(label) + " verified",
                    items);
            return result;
        }

// ---------------------------------------------------------------------
// Dynamic section helpers
// ---------------------------------------------------------------------

/**
 * 从 PT_DYNAMIC 找 tag，返回 d_un.d_val（整数）。
 * 用于 DT_PLTRELSZ / DT_PLTREL 等"值"型 tag。
 */
        uintptr_t findDynamicValue(uintptr_t base, int64_t tag) {
            if (base == 0) return 0;

            const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
            if (std::memcmp(p, ELFMAG, SELFMAG) != 0) return 0;

            const unsigned char elfClass = p[EI_CLASS];

            if (elfClass == ELFCLASS64) {
                const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
                if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return 0;

                const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(
                        base + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                    if (phdrs[i].p_type != PT_DYNAMIC) continue;

                    const Elf64_Dyn* dyn = reinterpret_cast<const Elf64_Dyn*>(
                            base + phdrs[i].p_vaddr);
                    for (; dyn->d_tag != DT_NULL; ++dyn) {
                        if (dyn->d_tag == tag) {
                            return dyn->d_un.d_val;
                        }
                    }
                }
            } else if (elfClass == ELFCLASS32) {
                const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);
                if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return 0;

                const Elf32_Phdr* phdrs = reinterpret_cast<const Elf32_Phdr*>(
                        base + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                    if (phdrs[i].p_type != PT_DYNAMIC) continue;

                    const Elf32_Dyn* dyn = reinterpret_cast<const Elf32_Dyn*>(
                            base + phdrs[i].p_vaddr);
                    for (; dyn->d_tag != DT_NULL; ++dyn) {
                        if (dyn->d_tag == tag) {
                            return dyn->d_un.d_val;
                        }
                    }
                }
            }
            return 0;
        }

/**
 * 从 PT_DYNAMIC 找 tag，返回 base + d_un.d_ptr（运行时绝对地址）。
 * 用于 DT_JMPREL / DT_SYMTAB / DT_STRTAB 等"指针"型 tag。
 */
        uintptr_t findDynamicPointer(uintptr_t base, int64_t tag) {
            if (base == 0) return 0;

            const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
            if (std::memcmp(p, ELFMAG, SELFMAG) != 0) return 0;

            const unsigned char elfClass = p[EI_CLASS];

            if (elfClass == ELFCLASS64) {
                const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
                if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return 0;

                const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(
                        base + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                    if (phdrs[i].p_type != PT_DYNAMIC) continue;

                    const Elf64_Dyn* dyn = reinterpret_cast<const Elf64_Dyn*>(
                            base + phdrs[i].p_vaddr);
                    for (; dyn->d_tag != DT_NULL; ++dyn) {
                        if (dyn->d_tag == tag) {
                            return base + dyn->d_un.d_ptr;
                        }
                    }
                }
            } else if (elfClass == ELFCLASS32) {
                const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(base);
                if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return 0;

                const Elf32_Phdr* phdrs = reinterpret_cast<const Elf32_Phdr*>(
                        base + ehdr->e_phoff);
                for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
                    if (phdrs[i].p_type != PT_DYNAMIC) continue;

                    const Elf32_Dyn* dyn = reinterpret_cast<const Elf32_Dyn*>(
                            base + phdrs[i].p_vaddr);
                    for (; dyn->d_tag != DT_NULL; ++dyn) {
                        if (dyn->d_tag == tag) {
                            return base + dyn->d_un.d_ptr;
                        }
                    }
                }
            }
            return 0;
        }

/**
 * 判断一个地址是否在"已加载的共享库"里。
 */
        bool isAddressInKnownLibrary(uintptr_t addr) {
            if (addr == 0) return false;
            Dl_info info;
            if (dladdr(reinterpret_cast<void*>(addr), &info) == 0) return false;
            return info.dli_fname != nullptr;
        }

        struct GotCheck {
            bool tampered;
            std::string details;
        };

/**
 * 遍历 .rela.plt（或 .rel.plt），读每个 GOT 项的值，
 * 校验指向地址是否属于已加载的共享库。
 */
        GotCheck checkGotIntegrity(uintptr_t base) {
            GotCheck result{false, {}};

            if (base == 0) {
                result.details = formatDetails("self base unavailable", {});
                return result;
            }

            const uintptr_t jmprelAddr = findDynamicPointer(base, DT_JMPREL);
            const uintptr_t pltrelsz   = findDynamicValue(base, DT_PLTRELSZ);
            const uintptr_t pltrel     = findDynamicValue(base, DT_PLTREL);

            if (jmprelAddr == 0 || pltrelsz == 0) {
                result.details = formatDetails("got no jmprel", {});
                return result;
            }

            std::vector<std::string> suspicious;
            size_t checked = 0;

            // 同时支持 RELA / REL；pltrel 缺失时默认按 RELA 处理
            if (pltrel == DT_REL) {
                const Elf64_Rel* rels = reinterpret_cast<const Elf64_Rel*>(jmprelAddr);
                const size_t count = pltrelsz / sizeof(Elf64_Rel);
                for (size_t i = 0; i < count; ++i) {
                    const uintptr_t gotAddr = base + rels[i].r_offset;
                    const uintptr_t target  = *reinterpret_cast<const uintptr_t*>(gotAddr);
                    if (target == 0) continue;
                    checked++;
                    if (!isAddressInKnownLibrary(target)) {
                        suspicious.push_back("got[#" + std::to_string(i) + "]=0x"
                                             + toHex(target) + " unknown");
                    }
                }
            } else {
                // DT_RELA 或未提供 DT_PLTREL
                const Elf64_Rela* relas = reinterpret_cast<const Elf64_Rela*>(jmprelAddr);
                const size_t count = pltrelsz / sizeof(Elf64_Rela);
                for (size_t i = 0; i < count; ++i) {
                    const uintptr_t gotAddr = base + relas[i].r_offset;
                    const uintptr_t target  = *reinterpret_cast<const uintptr_t*>(gotAddr);
                    if (target == 0) continue;
                    checked++;
                    if (!isAddressInKnownLibrary(target)) {
                        suspicious.push_back("got[#" + std::to_string(i) + "]=0x"
                                             + toHex(target) + " unknown");
                    }
                }
            }

            if (suspicious.empty()) {
                result.tampered = false;
                result.details = formatDetails("got verified",
                                               {std::to_string(checked) + " entries checked"});
            } else {
                result.tampered = true;
                result.details = formatDetails("got tampered", suspicious);
            }
            return result;
        }

    }  // namespace

    std::vector<std::string> scanIntegrity() {
        std::vector<std::string> result;

        const uintptr_t base = selfBase();
        if (base == 0) {
            result.push_back(evidence("TEXT_HASH", false, 85, "HIGH",
                                      formatDetails("self base unavailable", {})));
            result.push_back(evidence("RODATA_HASH", false, 80, "MEDIUM",
                                      formatDetails("self base unavailable", {})));
            result.push_back(evidence("GOT_INTEGRITY", false, 75, "INFO",
                                      formatDetails("self base unavailable", {})));
            result.push_back(evidence("FUNCTION_ENTRY", false, 70, "INFO",
                                      formatDetails("self base unavailable", {})));
            result.push_back(evidence("MEMORY_ELF_MISMATCH", false, 90, "HIGH",
                                      formatDetails("self base unavailable", {})));
            return result;
        }

        std::vector<Segment> segments;
        if (!collectLoadSegments(base, segments)) {
            result.push_back(evidence("TEXT_HASH", false, 85, "HIGH",
                                      formatDetails("no load segments", {})));
            result.push_back(evidence("RODATA_HASH", false, 80, "MEDIUM",
                                      formatDetails("no load segments", {})));
            result.push_back(evidence("GOT_INTEGRITY", false, 75, "INFO",
                                      formatDetails("no load segments", {})));
            result.push_back(evidence("FUNCTION_ENTRY", false, 70, "INFO",
                                      formatDetails("no load segments", {})));
            result.push_back(evidence("MEMORY_ELF_MISMATCH", false, 90, "HIGH",
                                      formatDetails("no load segments", {})));
            return result;
        }

        // ---- TEXT_HASH ----
        {
            Segment textSeg{};
            if (findSegment(segments, true, false, false, &textSeg)) {
                const HashCheck check = checkSegmentHash(
                        "text", "text", textSeg, EXPECTED_TEXT_HASH);
                result.push_back(evidence("TEXT_HASH", check.tampered, 85, "HIGH",
                                          check.details));
            } else {
                result.push_back(evidence("TEXT_HASH", true, 85, "HIGH",
                                          formatDetails("executable segment missing", {})));
            }
        }

        // ---- RODATA_HASH ----
        {
            Segment rodataSeg{};
            bool found = findSegment(segments, false, false, true, &rodataSeg);
            bool usingExecSegment = false;
            if (!found) {
                found = findSegment(segments, true, false, false, &rodataSeg);
                usingExecSegment = found;
            }
            if (found) {
                const HashCheck check = checkSegmentHash(
                        "rodata", "rodata", rodataSeg, EXPECTED_RODATA_HASH);
                std::string details = check.details;
                if (usingExecSegment) {
                    details += "\n  • shared with executable segment";
                }
                result.push_back(evidence("RODATA_HASH", check.tampered, 80, "MEDIUM",
                                          details));
            } else {
                result.push_back(evidence("RODATA_HASH", false, 100, "INFO",
                                          formatDetails("no readonly segment", {})));
            }
        }

        // ---- GOT_INTEGRITY ----
        {
            const GotCheck check = checkGotIntegrity(base);
            result.push_back(evidence("GOT_INTEGRITY", check.tampered, 75, "INFO",
                                      check.details));
        }

        // ---- FUNCTION_ENTRY ----
        {
            const uintptr_t entry = reinterpret_cast<uintptr_t>(&scanIntegrity);
            if (entry == 0) {
                result.push_back(evidence("FUNCTION_ENTRY", false, 70, "INFO",
                                          formatDetails("entry unavailable", {})));
            } else {
                const uint8_t* code = reinterpret_cast<const uint8_t*>(entry);
                bool allZero = true, allF = true;
                for (int i = 0; i < 8; ++i) {
                    if (code[i] != 0x00) allZero = false;
                    if (code[i] != 0xFF) allF = false;
                }
                const bool tampered = allZero || allF;
                result.push_back(evidence("FUNCTION_ENTRY", tampered, 70, "INFO",
                                          formatDetails(
                                                  tampered ? "function entry abnormal"
                                                           : "function entry verified",
                                                  {"entry=" + toHex(entry)})));
            }
        }

        // ---- MEMORY_ELF_MISMATCH ----
        {
            const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
            const bool elfOk   = std::memcmp(p, ELFMAG, SELFMAG) == 0;
            const bool classOk = (p[EI_CLASS] == ELFCLASS32 || p[EI_CLASS] == ELFCLASS64);
            const bool dataOk  = (p[EI_DATA] == ELFDATA2LSB || p[EI_DATA] == ELFDATA2MSB);
            const bool valid = elfOk && classOk && dataOk;
            std::vector<std::string> items = {
                    "magic=" + toHex(p[0]),
                    "class=" + std::to_string(p[EI_CLASS]),
                    "data=" + std::to_string(p[EI_DATA])
            };
            result.push_back(evidence("MEMORY_ELF_MISMATCH", !valid, 90, "HIGH",
                                      formatDetails(valid ? "elf header verified"
                                                          : "elf header mismatch",
                                                    items)));
        }

        return result;
    }

}  // namespace security_scanners