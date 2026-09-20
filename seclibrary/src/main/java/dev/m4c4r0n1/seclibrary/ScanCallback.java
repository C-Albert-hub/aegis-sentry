package dev.m4c4r0n1.seclibrary;

public interface ScanCallback {
    default void onStarted() {
    }

    default void onProgress(ScanProgress progress) {
    }

    void onCompleted(SecurityResult result);

    default void onError(Throwable error) {
    }
}
