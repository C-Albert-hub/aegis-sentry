package dev.m4c4r0n1.seclibrary;

public final class NativeSecurity {
    private static final boolean LOADED;

    static {
        boolean loaded;
        try {
            System.loadLibrary("seclibrary");
            loaded = true;
        } catch (UnsatisfiedLinkError error) {
            loaded = false;
        }
        LOADED = loaded;
    }

    private NativeSecurity() {
    }

    static boolean isLoaded() {
        return LOADED;
    }

    /**
     * Module map: 0 root, 1 debug, 2 thread, 3 fd, 4 memory,
     * 5 ELF, 6 native integrity, 7 app integrity, 8 environment, 9 proc.
     */
    static native String[] scanNative(int module);

    static native String[] scanNativeWithPath(int module, String apkPath);

    /** Deprecated compatibility methods. Prefer SecuritySDK.scan(...). */
    @Deprecated
    public static native boolean checkRoot();

    @Deprecated
    public static native boolean checkFrida();

    /** Native-side self-check: verifies JNI function pointers still live inside the .so. */
    static native boolean verifyNativeBinding();

    // ---- Runtime baseline ----
    static native void setBaselineDir(String dir);
    static native boolean recordBaseline();
    static native void clearBaseline();
}