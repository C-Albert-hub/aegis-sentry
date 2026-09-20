#include <jni.h>

#include "native_scanner.h"
#include "scanners/scanner_utils.h"

#include <dlfcn.h>
#include <string>
#include <vector>

namespace {

    bool isFunctionInSelf(void* fn) {
        if (fn == nullptr) return false;
        Dl_info info;
        if (dladdr(fn, &info) == 0) return false;
        const uintptr_t self = security_scanners::selfBase();
        return reinterpret_cast<uintptr_t>(info.dli_fbase) == self;
    }

    jobjectArray toJavaArray(JNIEnv* env, const std::vector<std::string>& items) {
        jclass stringClass = env->FindClass("java/lang/String");
        if (stringClass == nullptr) {
            return nullptr;
        }

        jobjectArray result = env->NewObjectArray(
                static_cast<jsize>(items.size()), stringClass, nullptr);
        if (result == nullptr) {
            return nullptr;
        }

        for (jsize index = 0; index < static_cast<jsize>(items.size()); ++index) {
            jstring value = env->NewStringUTF(items[index].c_str());
            if (value == nullptr) {
                return nullptr;
            }
            env->SetObjectArrayElement(result, index, value);
            env->DeleteLocalRef(value);
        }
        return result;
    }

    jobjectArray scanNative(JNIEnv* env, jclass, jint module) {
        if (module < 0 || module > 9) {
            return toJavaArray(env, {security_scanners::evidence(
                    "UNKNOWN_MODULE", true, 100, "MEDIUM",
                    "invalid-module:" + std::to_string(module))});
        }
        return toJavaArray(env,
                           scanNativeModule(static_cast<NativeModule>(module)));
    }

    jobjectArray scanNativeWithPath(JNIEnv* env, jclass, jint module, jstring apkPath) {
        if (module < 0 || module > 9) {
            return toJavaArray(env, {security_scanners::evidence(
                    "UNKNOWN_MODULE", true, 100, "MEDIUM",
                    "invalid-module:" + std::to_string(module))});
        }

        const char* path = nullptr;
        if (apkPath != nullptr) {
            path = env->GetStringUTFChars(apkPath, nullptr);
            if (path == nullptr) {
                return toJavaArray(env, {});
            }
        }

        jobjectArray result = toJavaArray(env,
                                          scanNativeModule(static_cast<NativeModule>(module),
                                                           path == nullptr ? "" : path));

        if (path != nullptr) {
            env->ReleaseStringUTFChars(apkPath, path);
        }
        return result;
    }

    jboolean checkRoot(JNIEnv*, jclass) {
        return nativeRootDetected() ? JNI_TRUE : JNI_FALSE;
    }

    jboolean checkFrida(JNIEnv*, jclass) {
        return nativeFridaDetected() ? JNI_TRUE : JNI_FALSE;
    }

    jboolean verifyNativeBinding(JNIEnv*, jclass) {
        const bool rootOk  = isFunctionInSelf(reinterpret_cast<void*>(checkRoot));
        const bool fridaOk = isFunctionInSelf(reinterpret_cast<void*>(checkFrida));
        return (rootOk && fridaOk) ? JNI_TRUE : JNI_FALSE;
    }

    void setBaselineDir(JNIEnv* env, jclass, jstring dir) {
        if (dir == nullptr) return;
        const char* path = env->GetStringUTFChars(dir, nullptr);
        if (path == nullptr) return;
        security_scanners::setBaselineDir(path);
        env->ReleaseStringUTFChars(dir, path);
    }

    jboolean recordBaseline(JNIEnv*, jclass) {
        return nativeRecordBaseline() ? JNI_TRUE : JNI_FALSE;
    }

    void clearBaseline(JNIEnv*, jclass) {
        nativeClearBaseline();
    }

    static JNINativeMethod methods[] = {
            {"scanNative",          "(I)[Ljava/lang/String;",                  reinterpret_cast<void*>(scanNative)},
            {"scanNativeWithPath",  "(ILjava/lang/String;)[Ljava/lang/String;", reinterpret_cast<void*>(scanNativeWithPath)},
            {"checkRoot",           "()Z",                                     reinterpret_cast<void*>(checkRoot)},
            {"checkFrida",          "()Z",                                     reinterpret_cast<void*>(checkFrida)},
            {"verifyNativeBinding", "()Z",                                     reinterpret_cast<void*>(verifyNativeBinding)},
            {"setBaselineDir",      "(Ljava/lang/String;)V",                   reinterpret_cast<void*>(setBaselineDir)},
            {"recordBaseline",      "()Z",                                     reinterpret_cast<void*>(recordBaseline)},
            {"clearBaseline",       "()V",                                     reinterpret_cast<void*>(clearBaseline)}
    };

}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("dev/m4c4r0n1/seclibrary/NativeSecurity");
    if (clazz == nullptr) {
        return JNI_ERR;
    }

    if (env->RegisterNatives(
            clazz,
            methods,
            static_cast<jint>(sizeof(methods) / sizeof(methods[0]))) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}