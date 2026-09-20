package dev.m4c4r0n1.aegis;

import androidx.annotation.Nullable;

import dev.m4c4r0n1.seclibrary.ScanProgress;
import dev.m4c4r0n1.seclibrary.SecurityResult;

final class ScanUiState {
    enum Phase {
        READY,
        RUNNING,
        COMPLETE,
        ERROR
    }

    private final Phase phase;
    private final int progress;
    @Nullable
    private final String errorMessage;
    @Nullable
    private final ScanProgress currentProgress;
    @Nullable
    private final SecurityResult result;

    private ScanUiState(
            Phase phase,
            int progress,
            @Nullable ScanProgress currentProgress,
            @Nullable SecurityResult result,
            @Nullable String errorMessage
    ) {
        this.phase = phase;
        this.progress = progress;
        this.currentProgress = currentProgress;
        this.result = result;
        this.errorMessage = errorMessage;
    }

    static ScanUiState ready() {
        return new ScanUiState(Phase.READY, 0, null, null, null);
    }

    static ScanUiState running(ScanProgress progress) {
        int percent = progress.getTotal() == 0
                ? 0
                : Math.min(99, progress.getCompleted() * 100 / progress.getTotal());
        return new ScanUiState(Phase.RUNNING, percent, progress, null, null);
    }

    static ScanUiState complete(SecurityResult result) {
        return new ScanUiState(Phase.COMPLETE, 100, null, result, null);
    }

    /** Restores a previously-completed result from cache (phase = COMPLETE). */
    static ScanUiState restored(SecurityResult result) {
        return new ScanUiState(Phase.COMPLETE, 100, null, result, null);
    }

    static ScanUiState error(@Nullable Throwable error) {
        String message = error == null ? null : error.getClass().getSimpleName();
        return new ScanUiState(Phase.ERROR, 0, null, null, message);
    }

    Phase getPhase() {
        return phase;
    }

    int getProgress() {
        return progress;
    }

    @Nullable
    ScanProgress getCurrentProgress() {
        return currentProgress;
    }

    @Nullable
    SecurityResult getResult() {
        return result;
    }

    @Nullable
    String getErrorMessage() {
        return errorMessage;
    }
}