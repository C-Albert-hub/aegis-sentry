package dev.m4c4r0n1.seclibrary;

import android.content.Context;

import java.util.concurrent.CompletableFuture;

/** Public SDK entry point. Scans are explicit and run asynchronously. */
public final class SecuritySDK {

    private static volatile boolean initialized = false;

    private SecuritySDK() {
    }

    /**
     * Must be called once before {@link #scan}.
     *
     * <p>Points native at the app-private files dir for baseline storage and
     * records the integrity baseline on first run. Subsequent runs are no-ops
     * (the baseline file already exists).
     */
    public static void init(Context context) {
        if (initialized) return;
        if (context == null || !NativeSecurity.isLoaded()) {
            initialized = true;
            return;
        }

        final String filesDir = context.getApplicationContext()
                .getFilesDir()
                .getAbsolutePath();
        NativeSecurity.setBaselineDir(filesDir);
        NativeSecurity.recordBaseline();

        initialized = true;
    }

    /** Pre-scan self-check. Returns false if the native binding was tampered with. */
    public static boolean verifyBinding() {
        return NativeSecurity.isLoaded() && NativeSecurity.verifyNativeBinding();
    }

    /** Clears the recorded baseline. Only call after reinstall / explicit reset. */
    @SuppressWarnings("unused")
    public static void resetBaseline() {
        if (NativeSecurity.isLoaded()) {
            NativeSecurity.clearBaseline();
        }
    }

    @SuppressWarnings("unused")
    public static CompletableFuture<SecurityResult> scan(Context context) {
        CompletableFuture<SecurityResult> future = new CompletableFuture<>();
        scan(context, ScanConfig.defaults(), new ScanCallback() {
            @Override
            public void onCompleted(SecurityResult result) {
                future.complete(result);
            }

            @Override
            public void onError(Throwable error) {
                future.completeExceptionally(error);
            }
        });
        return future;
    }

    public static ScanHandle scan(Context context, ScanConfig config, ScanCallback callback) {
        if (!NativeSecurity.isLoaded()) {
            callback.onError(new IllegalStateException("seclibrary not loaded"));
            return new ScanHandle();   // ← 空句柄，cancel() 是 no-op
        }

        if (!verifyBinding()) {
            callback.onError(new SecurityException("native binding tampered"));
            return new ScanHandle();
        }

        if (!initialized) {
            init(context);
        }

        return SecurityManager.scan(context, config, callback);
    }
}