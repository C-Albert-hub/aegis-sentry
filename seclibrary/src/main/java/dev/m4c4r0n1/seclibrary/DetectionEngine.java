package dev.m4c4r0n1.seclibrary;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;

/** Chooses detector modules and executes them in a deterministic order. */
final class DetectionEngine {
    interface ProgressListener {
        void onDetectorStarted(String detector, int completed, int total);
    }

    private DetectionEngine() {
    }

    static List<Evidence> detect(
            Context context,
            ScanConfig config,
            ScanHandle handle,
            ProgressListener progressListener
    ) {
        List<Detector> detectors = createDetectors(config);
        List<Evidence> evidence = new ArrayList<>();
        for (int index = 0; index < detectors.size(); index++) {
            if (handle.isCancelled() || Thread.currentThread().isInterrupted()) {
                return evidence;
            }
            Detector detector = detectors.get(index);
            progressListener.onDetectorStarted(detector.name(), index, detectors.size());
            evidence.addAll(EvidenceEngine.collect(context, detector));
        }
        return evidence;
    }

    static int detectorCount(ScanConfig config) {
        return createDetectors(config).size();
    }

    private static List<Detector> createDetectors(ScanConfig config) {
        List<Detector> detectors = new ArrayList<>();
        if (config.includes(ScanConfig.Module.ENVIRONMENT)) {
            detectors.add(new NativeDetector(0, "root-scanner"));
            detectors.add(new NativeDetector(8, "environment-scanner"));
            detectors.add(new NativeDetector(9, "proc-scanner"));
        }
        if (config.includes(ScanConfig.Module.ANTI_DEBUG)) {
            detectors.add(new NativeDetector(1, "debug-scanner"));
            detectors.add(new NativeDetector(2, "thread-scanner"));
        }
        if (config.includes(ScanConfig.Module.ANTI_INJECTION)) {
            detectors.add(new NativeDetector(3, "fd-scanner"));
            detectors.add(new NativeDetector(4, "memory-scanner"));
        }
        if (config.includes(ScanConfig.Module.APP_INTEGRITY)) {
            detectors.add(new NativeDetector(7, "app-integrity-scanner"));
        }
        if (config.includes(ScanConfig.Module.NATIVE_INTEGRITY)) {
            detectors.add(new NativeDetector(5, "elf-scanner"));
            detectors.add(new NativeDetector(6, "integrity-scanner"));
        }
        return detectors;
    }
}
