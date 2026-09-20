package dev.m4c4r0n1.seclibrary;

import android.content.Context;

import java.util.Collections;
import java.util.List;

/** Normalizes detector output into one stable evidence stream. */
final class EvidenceEngine {
    private EvidenceEngine() {
    }

    static List<Evidence> collect(Context context, Detector detector) {
        try {
            List<Evidence> evidence = detector.detect(context);
            return evidence == null ? Collections.emptyList() : evidence;
        } catch (Throwable error) {
            return Collections.singletonList(Evidence.detected(
                    detector.name(),
                    EvidenceType.DETECTOR_ERROR,
                    error.getClass().getSimpleName(),
                    100,
                    Severity.MEDIUM
            ));
        }
    }
}
