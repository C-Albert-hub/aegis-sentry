package dev.m4c4r0n1.seclibrary;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RiskEngineTest {
    @Test
    public void duplicateEvidenceUsesHighestPointsPerType() {
        SecurityResult result = RiskEngine.evaluate(Arrays.asList(
                Evidence.detected("one", EvidenceType.ROOT_SU, "low-confidence", 50, Severity.HIGH),
                Evidence.detected("two", EvidenceType.ROOT_SU, "high-confidence", 100, Severity.HIGH),
                Evidence.detected("three", EvidenceType.DEBUGGER, "connected", 100, Severity.MEDIUM)
        ));

        assertEquals(50, result.getScore());
        assertEquals(RiskDecision.COMPROMISED, result.getDecision());
    }

    @Test
    public void clearEvidenceDoesNotAffectScore() {
        SecurityResult result = RiskEngine.evaluate(Arrays.asList(
                Evidence.clear("test", EvidenceType.ROOT_SU, "absent"),
                Evidence.clear("test", EvidenceType.DEBUGGER, "absent")
        ));

        assertEquals(100, result.getScore());
        assertEquals(RiskDecision.SAFE, result.getDecision());
        assertEquals("absent", result.getEvidence().get(0).getValue());
    }

    @Test
    public void moduleScoreUsesTheSameSafetyScale() {
        SecurityResult result = RiskEngine.evaluate(Arrays.asList(
                Evidence.detected("test", EvidenceType.DEBUGGER, "connected", 100, Severity.HIGH),
                Evidence.clear("test", EvidenceType.ROOT_SU, "absent")
        ));

        assertEquals(68, result.getScoreFor(Collections.singletonList(result.getEvidence().get(0))));
        assertEquals(100, result.getScoreFor(Collections.singletonList(result.getEvidence().get(1))));
    }

    @Test
    public void correlatedInjectionSignalsDoNotDrainTheScoreThreeTimes() {
        SecurityResult result = RiskEngine.evaluate(Arrays.asList(
                Evidence.detected("memory", EvidenceType.ANONYMOUS_EXECUTABLE_MEMORY,
                        "same-mapping", 100, Severity.HIGH),
                Evidence.detected("memory", EvidenceType.RWX_MEMORY,
                        "same-mapping", 100, Severity.HIGH),
                Evidence.detected("memory", EvidenceType.EXECUTABLE_MEMORY,
                        "same-mapping", 100, Severity.HIGH)
        ));

        assertEquals(68, result.getScore());
    }

    @Test
    public void configKeepsAnImmutableModuleSnapshot() {
        ScanConfig config = ScanConfig.builder()
                .disable(ScanConfig.Module.APP_INTEGRITY)
                .expectedCertificateSha256("AA:BB")
                .build();

        assertFalse(config.includes(ScanConfig.Module.APP_INTEGRITY));
        assertEquals("aabb", config.getExpectedCertificateSha256());
    }
}
