package dev.m4c4r0n1.seclibrary;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;


@SuppressWarnings("ClassCanBeRecord")
public final class ScanProgress {
    private final String detector;
    private final int completed;
    private final int total;

    public ScanProgress(@NonNull String detector,
                        @IntRange(from = 0) int completed,
                        @IntRange(from = 0) int total) {
        // Fall back to "unknown" instead of allowing a null to surface later.
        this.detector = detector;

        // Clamp negatives so a misbehaving SDK caller can't break the UI.
        int safeCompleted = Math.max(0, completed);
        int safeTotal = Math.max(0, total);

        // Keep completed <= total (except when total == 0, both are 0 anyway).
        if (safeTotal > 0 && safeCompleted > safeTotal) {
            safeCompleted = safeTotal;
        }

        this.completed = safeCompleted;
        this.total = safeTotal;
    }

    @NonNull
    public String getDetector() {
        return detector;
    }

    @IntRange(from = 0)
    public int getCompleted() {
        return completed;
    }

    @IntRange(from = 0)
    public int getTotal() {
        return total;
    }
}