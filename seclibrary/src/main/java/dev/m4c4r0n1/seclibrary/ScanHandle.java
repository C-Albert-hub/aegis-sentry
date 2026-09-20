package dev.m4c4r0n1.seclibrary;

import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ScanHandle {
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private volatile Future<?> future;

    void attach(Future<?> future) {
        this.future = future;
        if (cancelled.get()) {
            future.cancel(true);
        }
    }

    public boolean cancel() {
        boolean changed = cancelled.compareAndSet(false, true);
        Future<?> current = future;
        if (current != null) {
            current.cancel(true);
        }
        return changed;
    }

    public boolean isCancelled() {
        return cancelled.get();
    }
}
