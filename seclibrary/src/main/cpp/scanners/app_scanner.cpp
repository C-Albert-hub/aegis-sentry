#include "app_scanner.h"
#include "scanner_utils.h"

#include <fstream>
#include <string>
#include <vector>

namespace security_scanners {

    namespace {

#ifndef EXPECTED_APK_HASH
#define EXPECTED_APK_HASH 0ULL
#endif

        uint64_t hashFile(const std::string& path, std::streamoff* outSize) {
            std::ifstream input(path, std::ios::binary);
            if (!input) {
                if (outSize) *outSize = -1;
                return 0;
            }

            input.seekg(0, std::ios::end);
            const std::streamoff size = input.tellg();
            input.seekg(0, std::ios::beg);
            if (outSize) *outSize = size;

            if (size <= 0) return 0;

            uint64_t h = 1469598103934665603ULL;
            constexpr size_t kChunkSize = 64 * 1024;
            std::vector<char> buffer(kChunkSize);

            while (input) {
                input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                const std::streamsize got = input.gcount();
                for (std::streamsize i = 0; i < got; ++i) {
                    h ^= static_cast<uint8_t>(buffer[static_cast<size_t>(i)]);
                    h *= 1099511628211ULL;
                }
                if (got < static_cast<std::streamsize>(buffer.size())) break;
            }
            return h;
        }

    }  // namespace

    std::vector<std::string> scanApp(const std::string& apkPath) {
        std::vector<std::string> result;

        // ---- APK_PATH ----
        const bool available = !apkPath.empty() && exists(apkPath.c_str());
        if (available) {
            result.push_back(evidence("APK_PATH", false, 100, "HIGH",
                                      formatDetails("apk path resolved", {apkPath})));
        } else {
            result.push_back(evidence("APK_PATH", true, 100, "HIGH",
                                      formatDetails("apk path unavailable", {})));
            result.push_back(evidence("APK_HASH", true, 100, "HIGH",
                                      formatDetails("apk unavailable", {})));
            result.push_back(evidence("DEX_HASH", false, 100, "INFO",
                                      formatDetails("dex hash delegated",
                                                    {"apk unavailable"})));
            result.push_back(evidence("APK_SIGNATURE", false, 100, "INFO",
                                      formatDetails("apk signature delegated",
                                                    {"apk unavailable"})));
            return result;
        }

        // ---- APK_HASH ----
        {
            std::streamoff size = -1;
            const uint64_t actual = hashFile(apkPath, &size);

            if (actual == 0) {
                result.push_back(evidence("APK_HASH", true, 95, "HIGH",
                                          formatDetails("apk hash unreadable", {})));
            } else if (EXPECTED_APK_HASH == 0ULL) {
                result.push_back(evidence("APK_HASH", false, 95, "HIGH",
                                          formatDetails("apk hash baseline not injected",
                                                        {"actual=" + toHex(actual),
                                                         "bytes=" + std::to_string(size)})));
            } else {
                const bool tampered = (actual != EXPECTED_APK_HASH);
                result.push_back(evidence("APK_HASH", tampered, 95, "HIGH",
                                          formatDetails(tampered ? "apk hash tampered"
                                                                 : "apk hash verified",
                                                        {"expected=" + toHex(EXPECTED_APK_HASH),
                                                         "actual=" + toHex(actual),
                                                         "bytes=" + std::to_string(size)})));
            }
        }

        // ---- DEX_HASH ----
        result.push_back(evidence("DEX_HASH", false, 100, "INFO",
                                  formatDetails("dex hash delegated",
                                                {"native side not implemented"})));

        // ---- APK_SIGNATURE ----
        result.push_back(evidence("APK_SIGNATURE", false, 100, "INFO",
                                  formatDetails("apk signature delegated",
                                                {"native side not implemented"})));

        return result;
    }

}  // namespace security_scanners