package dev.m4c4r0n1.seclibrary;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class RiskEngine {
    private RiskEngine() {
    }

    static SecurityResult evaluate(List<Evidence> evidence) {
        int score = score(evidence);
        boolean critical = evidence.stream().anyMatch(item ->
                item.isDetected() && item.getSeverity() == Severity.CRITICAL);
        RiskDecision decision;
        if (critical || score <= 50) {
            decision = RiskDecision.COMPROMISED;
        } else if (score < 80) {
            decision = RiskDecision.SUSPICIOUS;
        } else {
            decision = RiskDecision.SAFE;
        }
        return new SecurityResult(evidence, score, decision);
    }

    static int score(List<Evidence> evidence) {
        // Several detectors report different views of the same condition. For example,
        // RWX_MEMORY and EXECUTABLE_MEMORY can both describe one mapping. Keep every
        // Evidence item for the UI, but charge only the strongest signal per risk family.
        Map<String, Integer> pointsByFamily = new HashMap<>();

        for (Evidence item : evidence) {
            if (!item.isDetected()) {
                continue;
            }
            int points = item.getSeverity().riskPoints() * item.getConfidence() / 100;
            pointsByFamily.merge(riskFamily(item.getType()), points, Math::max);
        }

        int total = pointsByFamily.values().stream().mapToInt(Integer::intValue).sum();
        return Math.max(0, 100 - Math.min(100, total));
    }

    private static String riskFamily(EvidenceType type) {
        switch (type) {
            case ROOT_SU:
            case ROOT_FRAMEWORK:
                return "root";
            case DEBUGGER:
            case TRACER_PID:
            case TRACER_PARENT:
            case PROCESS_PARENT:
            case THREAD_STATE:
            case SUSPICIOUS_THREAD:
                return "debug";
            case SUSPICIOUS_FD:
            case SUSPICIOUS_MAP:
            case EXECUTABLE_MEMORY:
            case RWX_MEMORY:
            case ANONYMOUS_EXECUTABLE_MEMORY:
            case SUSPICIOUS_SOCKET:
                return "injection";
            case APK_SIGNATURE:
            case APK_PATH:
            case APK_HASH:
            case DEX_HASH:
            case NATIVE_LIBRARY_HASH:
                return "app-integrity";
            case NATIVE_LIBRARY_FORMAT:
            case ELF_HEADER:
            case ELF_SECTION:
            case TEXT_HASH:
            case RODATA_HASH:
            case GOT_INTEGRITY:
            case PLT_INTEGRITY:
            case FUNCTION_ENTRY:
            case MEMORY_ELF_MISMATCH:
            case NATIVE_PATH:
            case NATIVE_SYMBOL:
                return "native-integrity";
            default:
                return type.name();
        }
    }
}
