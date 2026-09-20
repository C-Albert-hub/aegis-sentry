package dev.m4c4r0n1.seclibrary;

import java.util.Objects;

/** Immutable, explainable result emitted by a detector. */
public final class Evidence {
    private final String source;
    private final EvidenceType type;
    private final String value;
    private final int confidence;
    private final Severity severity;
    private final boolean detected;

    private Evidence(
            String source,
            EvidenceType type,
            String value,
            int confidence,
            Severity severity,
            boolean detected
    ) {
        this.source = Objects.requireNonNull(source, "source");
        this.type = Objects.requireNonNull(type, "type");
        this.value = value == null ? "" : value;
        this.confidence = Math.max(0, Math.min(100, confidence));
        this.severity = Objects.requireNonNull(severity, "severity");
        this.detected = detected;
    }

    public static Evidence detected(
            String source,
            EvidenceType type,
            String value,
            int confidence,
            Severity severity
    ) {
        return new Evidence(source, type, value, confidence, severity, true);
    }

    public static Evidence clear(
            String source,
            EvidenceType type,
            String value
    ) {
        return new Evidence(source, type, value, 100, Severity.INFO, false);
    }

    public String getSource() {
        return source;
    }

    public EvidenceType getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public int getConfidence() {
        return confidence;
    }

    public Severity getSeverity() {
        return severity;
    }

    public boolean isDetected() {
        return detected;
    }
}
