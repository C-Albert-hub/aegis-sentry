package dev.m4c4r0n1.aegis.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.m4c4r0n1.seclibrary.Evidence;
import dev.m4c4r0n1.seclibrary.EvidenceType;

/**
 * Pure UI-side classification of {@link Evidence} into result modules.
 *
 * <p>This class only reads {@link Evidence#getType()} and {@link Evidence#getSource()}.
 * It never invokes the SDK, JNI, or any native detector — it is safe to change freely
 * without affecting the .so or the scan pipeline.
 */
public final class EvidenceClassifier {

    /** Module display names, in the order they should appear as tabs. */
    public static final String[] TYPES = {
            "Environment Security",
            "Anti-Debug",
            "Anti-Injection",
            "App Integrity",
            "Native Integrity"
    };

    // Index constants — keep in sync with TYPES above.
    public static final int ENVIRONMENT      = 0;
    public static final int ANTI_DEBUG       = 1;
    public static final int ANTI_INJECTION   = 2;
    public static final int APP_INTEGRITY    = 3;
    public static final int NATIVE_INTEGRITY = 4;

    private EvidenceClassifier() {
    }

    /**
     * Groups evidence by module. The returned map always contains every key in
     * {@link #TYPES}, even when the corresponding list is empty, so callers can
     * rely on {@code get(type)} returning a non-null list.
     */
    public static Map<String, List<Evidence>> group(List<Evidence> evidence) {
        Map<String, List<Evidence>> groups = new LinkedHashMap<>();
        for (String type : TYPES) {
            groups.put(type, new ArrayList<>());
        }
        if (evidence == null) {
            return groups;
        }
        for (Evidence item : evidence) {
            List<Evidence> bucket = groups.get(moduleFor(item));
            if (bucket != null) {
                bucket.add(item);
            }
        }
        return groups;
    }

    /**
     * Maps a single evidence item to its display module. Mirrors the SDK's own
     * detector naming (source hints + evidence type) but is purely presentational.
     */
    public static String moduleFor(Evidence evidence) {
        String source = evidence.getSource() == null
                ? ""
                : evidence.getSource().toLowerCase();
        EvidenceType type = evidence.getType();

        if (source.contains("app-integrity")
                || type.name().startsWith("APK_")
                || type == EvidenceType.DEX_HASH
                || type == EvidenceType.NATIVE_LIBRARY_HASH) {
            return TYPES[APP_INTEGRITY];
        }
        if (source.contains("native-integrity")
                || type.name().contains("ELF")
                || type.name().contains("GOT")
                || type.name().contains("PLT")
                || type.name().contains("TEXT")
                || type.name().contains("RODATA")
                || type.name().contains("FUNCTION")
                || type.name().contains("MEMORY_ELF")
                || type == EvidenceType.NATIVE_PATH
                || type == EvidenceType.NATIVE_SYMBOL
                || type == EvidenceType.NATIVE_LIBRARY_FORMAT) {
            return TYPES[NATIVE_INTEGRITY];
        }
        if (source.contains("anti-injection")
                || type == EvidenceType.SUSPICIOUS_FD
                || type == EvidenceType.SUSPICIOUS_MAP
                || type == EvidenceType.RWX_MEMORY
                || type == EvidenceType.ANONYMOUS_EXECUTABLE_MEMORY
                || type == EvidenceType.EXECUTABLE_MEMORY
                || type == EvidenceType.SUSPICIOUS_SOCKET) {
            return TYPES[ANTI_INJECTION];
        }
        if (source.contains("anti-debug")
                || type == EvidenceType.DEBUGGER
                || type == EvidenceType.TRACER_PID
                || type == EvidenceType.TRACER_PARENT
                || type == EvidenceType.THREAD_STATE
                || type == EvidenceType.SUSPICIOUS_THREAD
                || type == EvidenceType.PROCESS_PARENT) {
            return TYPES[ANTI_DEBUG];
        }
        return TYPES[ENVIRONMENT];
    }

    /**
     * Converts an {@link EvidenceType} constant name (UPPER_SNAKE_CASE) into a
     * human-readable title, e.g. {@code APK_HASH_MISMATCH -> "Apk Hash Mismatch"}.
     */
    public static String displayName(EvidenceType type) {
        String[] words = type.name().toLowerCase().split("_");
        StringBuilder result = new StringBuilder();
        for (String word : words) {
            if (word.isEmpty()) continue;
            if (result.length() > 0) result.append(' ');
            result.append(Character.toUpperCase(word.charAt(0))).append(word.substring(1));
        }
        return result.toString();
    }
}