package dev.m4c4r0n1.seclibrary;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Final result exposed to SDK consumers after evidence correlation and scoring. */
public final class SecurityResult {
    private final List<Evidence> evidence;
    private final int score;
    private final RiskDecision decision;

    SecurityResult(List<Evidence> evidence, int score, RiskDecision decision) {
        this.evidence = Collections.unmodifiableList(new ArrayList<>(evidence));
        this.score = score;
        this.decision = decision;
    }

    public List<Evidence> getEvidence() {
        return evidence;
    }

    public int getScore() {
        return score;
    }

    /** Returns the same safety score calculation for a detection module subset. */
    public int getScoreFor(List<Evidence> subset) {
        return RiskEngine.score(subset);
    }

    public RiskDecision getDecision() {
        return decision;
    }

    public boolean hasRisk() {
        return decision != RiskDecision.SAFE;
    }
}
