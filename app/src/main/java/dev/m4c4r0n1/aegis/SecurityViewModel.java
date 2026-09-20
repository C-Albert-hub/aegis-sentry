package dev.m4c4r0n1.aegis;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import dev.m4c4r0n1.seclibrary.ScanCallback;
import dev.m4c4r0n1.seclibrary.ScanConfig;
import dev.m4c4r0n1.seclibrary.ScanHandle;
import dev.m4c4r0n1.seclibrary.ScanProgress;
import dev.m4c4r0n1.seclibrary.SecurityResult;
import dev.m4c4r0n1.seclibrary.SecuritySDK;

/** UI-facing state holder. It starts work only after the user explicitly requests it. */
public final class SecurityViewModel extends AndroidViewModel {
    /** Minimum time the progress ring stays visible so very fast scans don't flicker. */
    private static final long MIN_DISPLAY_MS = 1400L;

    private final MutableLiveData<ScanUiState> state = new MutableLiveData<>(initialState());
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private long scanStartedAt;
    private Runnable completionRunnable;
    private ScanHandle scanHandle;

    public SecurityViewModel(@NonNull Application application) {
        super(application);
    }

    private static ScanUiState initialState() {
        SecurityResult result = ScanResultStore.get();
        return result == null ? ScanUiState.ready() : ScanUiState.restored(result);
    }

    LiveData<ScanUiState> getState() {
        return state;
    }

    void startScan() {
        ScanUiState current = state.getValue();
        if (current != null && current.getPhase() == ScanUiState.Phase.RUNNING) {
            return;
        }

        scanHandle = SecuritySDK.scan(
                getApplication(),
                ScanConfig.defaults(),
                new ScanCallback() {
                    @Override
                    public void onStarted() {
                        scanStartedAt = SystemClock.uptimeMillis();
                        state.setValue(ScanUiState.running(new ScanProgress("starting", 0, 1)));
                    }

                    @Override
                    public void onProgress(ScanProgress progress) {
                        state.setValue(ScanUiState.running(progress));
                    }

                    @Override
                    public void onCompleted(SecurityResult result) {
                        ScanResultStore.save(result);
                        long remaining = Math.max(0L,
                                MIN_DISPLAY_MS - (SystemClock.uptimeMillis() - scanStartedAt));
                        completionRunnable = () -> {
                            state.setValue(ScanUiState.complete(result));
                            scanHandle = null;
                            completionRunnable = null;
                        };
                        mainHandler.postDelayed(completionRunnable, remaining);
                    }

                    @Override
                    public void onError(Throwable error) {
                        if (completionRunnable != null) {
                            mainHandler.removeCallbacks(completionRunnable);
                            completionRunnable = null;
                        }
                        state.setValue(ScanUiState.error(error));
                        scanHandle = null;
                    }
                }
        );
    }

    @Override
    protected void onCleared() {
        if (completionRunnable != null) {
            mainHandler.removeCallbacks(completionRunnable);
            completionRunnable = null;
        }
        if (scanHandle != null) {
            scanHandle.cancel();
            scanHandle = null;
        }
        super.onCleared();
    }
}