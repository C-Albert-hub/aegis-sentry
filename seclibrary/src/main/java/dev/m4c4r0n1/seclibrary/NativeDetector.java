package dev.m4c4r0n1.seclibrary;

import android.content.Context;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class NativeDetector implements Detector {
    private final int module;
    private final String detectorName;

    NativeDetector(int module, String detectorName) {
        this.module = module;
        this.detectorName = detectorName;
    }

    @Override
    public String name() {
        return detectorName;
    }

    @Override
    public List<Evidence> detect(Context context) {
        if (!NativeSecurity.isLoaded()) {
            return Collections.singletonList(Evidence.detected(
                    detectorName,
                    EvidenceType.NATIVE_LIBRARY_FORMAT,
                    "native-library-unavailable",
                    100,
                    Severity.MEDIUM
            ));
        }

        String[] raw = module == 7
                ? NativeSecurity.scanNativeWithPath(module, context.getApplicationInfo().sourceDir)
                : NativeSecurity.scanNative(module);
        List<Evidence> result = new ArrayList<>();
        for (String item : raw) {
            Evidence evidence = parse(item);
            if (evidence != null) {
                result.add(evidence);
            }
        }
        return result;
    }

    private Evidence parse(String raw) {
        if (raw == null) {
            return null;
        }
        String[] fields = raw.split("\\|", 5);
        if (fields.length != 5) {
            return null;
        }
        try {
            EvidenceType type = EvidenceType.valueOf(fields[0]);
            boolean detected = "1".equals(fields[1]);
            int confidence = Integer.parseInt(fields[2]);
            Severity severity = Severity.valueOf(fields[3]);
            return detected
                    ? Evidence.detected(detectorName, type, fields[4], confidence, severity)
                    : Evidence.clear(detectorName, type, fields[4]);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
