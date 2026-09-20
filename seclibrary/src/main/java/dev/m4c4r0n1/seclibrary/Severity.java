package dev.m4c4r0n1.seclibrary;

/** Severity of a single piece of security evidence. */
public enum Severity {
    INFO(0),
    LOW(8),
    MEDIUM(18),
    HIGH(32),
    CRITICAL(50);

    private final int riskPoints;

    Severity(int riskPoints) {
        this.riskPoints = riskPoints;
    }

    int riskPoints() {
        return riskPoints;
    }
}
