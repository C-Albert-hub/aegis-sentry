# Aegis Sentry · m4c4r0n1

> Android security detection SDK — Shield your systems.

Android 安全检测 SDK，覆盖 Root、调试、Hook、注入、完整性等 10 类检测模块。

---

环境要求：Android Studio 4.0+ / NDK 25+ / CMake 3.22+ / JDK 17

## 功能

| # | 模块 | 检测项 |
|---|---|---|
| 0 | Root | ROOT_SU / ROOT_FRAMEWORK / ROOT_MOUNT / BOOTLOADER |
| 1 | Debug | TRACER_PID / TRACER_PARENT / PROCESS_PARENT |
| 2 | Thread | SUSPICIOUS_THREAD / THREAD_STATE |
| 3 | FD | SUSPICIOUS_FD / SUSPICIOUS_SOCKET |
| 4 | Memory | SUSPICIOUS_MAP / RWX_MEMORY / ANONYMOUS_EXECUTABLE_MEMORY / EXECUTABLE_MEMORY |
| 5 | ELF | ELF_HEADER / NATIVE_PATH / ELF_SECTION |
| 6 | Integrity | TEXT_HASH / RODATA_HASH / GOT_INTEGRITY / FUNCTION_ENTRY / MEMORY_ELF_MISMATCH |
| 7 | APK | APK_PATH / APK_HASH / DEX_HASH / APK_SIGNATURE |
| 8 | Environment | SYSTEM_PROPERTY / TEST_KEYS / SELINUX / EMULATOR / MOUNT_STATE |
| 9 | Process | PROCESS_STATUS / PROCESS_STATE / PROCESS_CMDLINE / PROCESS_ENVIRON |

**合计**：10 个模块、30+ 检测项。

---

## 架构

| 层 | 目录 | 职责 |
|---|---|---|
| UI | `app/` | 界面、结果展示、动画 |
| SDK | `seclibrary/java/` | Java 封装、`SecuritySDK` 统一接口 |
| Native | `seclibrary/cpp/` | 检测引擎、JNI 入口、10 个检测模块 |
