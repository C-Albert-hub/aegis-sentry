package dev.m4c4r0n1.aegis;

import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import dev.m4c4r0n1.seclibrary.SecurityResult;

/**
 * Small UI-only handoff for the result screen.
 *
 * <p><b>Scope:</b> This store is process-local and in-memory. It exists purely so
 * that {@code OverviewFragment} and {@code ResultsFragment} can share the latest
 * {@link SecurityResult} without owning it themselves. The SDK
 * ({@code SecuritySDK}) remains the only producer of results; the UI only reads.
 *
 * <p><b>Lifecycle:</b> Contents survive configuration changes (it's static) but are
 * lost when the process dies. If we later need "last result" to survive a cold start,
 * swap the static field for DataStore/Room — no caller changes required.
 *
 * <p><b>Threading:</b> All mutating methods are {@code synchronized}; LiveData delivery
 * still happens on the main thread via {@link MutableLiveData#setValue}.
 */
final class ScanResultStore {

    @Nullable
    private static SecurityResult latest;
    private static final MutableLiveData<SecurityResult> liveResult = new MutableLiveData<>();

    private ScanResultStore() {
        // no instances
    }

    /** Stores the latest result and notifies observers. */
    static synchronized void save(SecurityResult result) {
        latest = result;
        liveResult.setValue(result);
    }

    /** Returns the most recent result, or {@code null} if none has been saved. */
    @Nullable
    static synchronized SecurityResult get() {
        return latest;
    }

    /**
     * Clears the cached result and pushes {@code null} to observers.
     * Call this on logout / explicit "reset scan" so stale data isn't shown next launch.
     *
     * <p><b>Do not</b> call from {@code ViewModel.onCleared()}: that also fires on
     * configuration changes and would wipe the result on rotation.
     */
    static synchronized void clear() {
        latest = null;
        liveResult.setValue(null);
    }

    /** Observable view of the latest result. */
    static LiveData<SecurityResult> observe() {
        return liveResult;
    }
}