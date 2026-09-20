package dev.m4c4r0n1.seclibrary;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

/** Coordinates asynchronous detection, evidence normalization, and risk evaluation. */
public final class SecurityManager {
    private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "security-sdk-worker");
        thread.setDaemon(true);
        return thread;
    });
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final AtomicReference<Context> LEGACY_CONTEXT = new AtomicReference<>();

    private SecurityManager() {
    }

    public static ScanHandle scan(Context context, ScanConfig config, ScanCallback callback) {
        if (context == null) {
            throw new IllegalArgumentException("context == null");
        }
        if (config == null) {
            throw new IllegalArgumentException("config == null");
        }
        if (callback == null) {
            throw new IllegalArgumentException("callback == null");
        }

        Context appContext = context.getApplicationContext();
        ScanHandle handle = new ScanHandle();
        Future<?> future = EXECUTOR.submit(() -> {
            post(handle, callback::onStarted);
            try {
                int total = DetectionEngine.detectorCount(config);
                List<Evidence> evidence = DetectionEngine.detect(
                        appContext,
                        config,
                        handle,
                        (detector, completed, count) -> post(handle, () -> callback.onProgress(
                                new ScanProgress(detector, completed, count)
                        ))
                );
                if (handle.isCancelled() || Thread.currentThread().isInterrupted()) {
                    return;
                }
                SecurityResult result = RiskEngine.evaluate(evidence);
                post(handle, () -> {
                    callback.onProgress(new ScanProgress("completed", total, total));
                    callback.onCompleted(result);
                });
            } catch (Throwable error) {
                post(handle, () -> callback.onError(error));
            }
        });
        handle.attach(future);
        return handle;
    }

    /** Compatibility entry point for the original demo API. */
    @Deprecated
    public static void init(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context == null");
        }
        LEGACY_CONTEXT.set(context.getApplicationContext());
    }

    /** Compatibility entry point. New code should use scan(context, config, callback). */
    @Deprecated
    public static void check(SecurityCallback callback) {
        Context context = LEGACY_CONTEXT.get();
        if (context == null) {
            throw new IllegalStateException("SecurityManager.init(context) must be called first");
        }
        scan(context, ScanConfig.defaults(), new ScanCallback() {
            @Override
            public void onProgress(ScanProgress progress) {
                callback.onStep("Checking " + progress.getDetector() + "...");
            }

            @Override
            public void onCompleted(SecurityResult result) {
                RiskResult legacy = new RiskResult();
                for (Evidence evidence : result.getEvidence()) {
                    legacy.addItem(new RiskItem(evidence.getType().name(), evidence.isDetected()));
                }
                callback.onResult(legacy);
            }

            @Override
            public void onError(Throwable error) {
                callback.onStep("Security scan failed");
            }
        });
    }

    private static void post(ScanHandle handle, Runnable runnable) {
        if (!handle.isCancelled()) {
            MAIN.post(runnable);
        }
    }
}
