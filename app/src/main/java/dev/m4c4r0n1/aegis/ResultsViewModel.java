package dev.m4c4r0n1.aegis;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.ViewModel;

import dev.m4c4r0n1.seclibrary.SecurityResult;

/** ViewModel facade for the result screen; it never invokes a detector or JNI directly. */
public final class ResultsViewModel extends ViewModel {
    private final LiveData<SecurityResult> result = ScanResultStore.observe();

    public ResultsViewModel() {
        super();
    }

    public LiveData<SecurityResult> getResult() {
        return result;
    }
}
