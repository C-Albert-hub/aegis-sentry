package dev.m4c4r0n1.aegis;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.animation.DecelerateInterpolator;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.transition.AutoTransition;
import androidx.transition.TransitionManager;

import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.List;

import dev.m4c4r0n1.seclibrary.Evidence;
import dev.m4c4r0n1.seclibrary.RiskDecision;
import dev.m4c4r0n1.seclibrary.SecurityResult;
import dev.m4c4r0n1.seclibrary.Severity;

/** Overview UI. Detection remains behind SecurityViewModel and SecuritySDK. */
public final class HomeFragment extends Fragment {

    // ---------------------------------------------------------------------
    // Animation tunables
    // ---------------------------------------------------------------------

    /** Duration of the stats row height-folding transition. */
    private static final long STATS_REVEAL_DURATION_MS = 280L;
    /** Delay before the stats row starts revealing, so the score ring leads. */
    private static final long STATS_REVEAL_DELAY_MS    = 120L;

    /** Duration of each count-up animation. */
    private static final long COUNT_DURATION_MS        = 520L;
    /** Extra delay between pass -> warning -> failure, to stagger them. */
    private static final long COUNT_STAGGER_MS         = 40L;

    private CircleProgressView scoreView;
    private TextView status;
    private TextView passCount;
    private TextView warningCount;
    private TextView failureCount;
    private View statsRow;
    private MaterialButton scanButton;

    /** Count-up animators currently running; cancelled on re-render / teardown. */
    private final List<ValueAnimator> runningCountAnimators = new ArrayList<>();

    public HomeFragment() {
        super(R.layout.fragment_home);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        scoreView     = view.findViewById(R.id.scoreView);
        status        = view.findViewById(R.id.status);
        passCount     = view.findViewById(R.id.passCount);
        warningCount  = view.findViewById(R.id.warningCount);
        failureCount  = view.findViewById(R.id.failureCount);
        statsRow      = view.findViewById(R.id.statsRow);
        scanButton    = view.findViewById(R.id.scanButton);

        SecurityViewModel viewModel = new ViewModelProvider(requireActivity())
                .get(SecurityViewModel.class);
        viewModel.getState().observe(getViewLifecycleOwner(), this::render);
        scanButton.setOnClickListener(button -> viewModel.startScan());

        renderDevice(view);
    }

    @Override
    public void onDestroyView() {
        cancelCountAnimations();
        super.onDestroyView();
    }

    // ---------------------------------------------------------------------
    // State rendering
    // ---------------------------------------------------------------------

    private void render(ScanUiState state) {
        scanButton.setEnabled(state.getPhase() != ScanUiState.Phase.RUNNING);
        switch (state.getPhase()) {
            case READY:
                if (state.getResult() == null) {
                    scanButton.setText(R.string.start_scan);
                    scoreView.reset();
                    status.setText(R.string.ready_to_scan);
                    hideStats();
                } else {
                    renderCompleted(state.getResult());
                }
                break;

            case RUNNING:
                scanButton.setText(R.string.scanning);
                scoreView.setScanProgress(state.getProgress());
                status.setText(state.getCurrentProgress() == null
                        ? getString(R.string.scanning)
                        : state.getCurrentProgress().getDetector());
                hideStats();
                break;

            case COMPLETE:
                if (state.getResult() != null) renderCompleted(state.getResult());
                break;

            case ERROR:
                scanButton.setText(R.string.try_again_scan);
                scoreView.reset();
                status.setText(R.string.scan_failed);
                hideStats();
                break;
        }
    }

    private void renderCompleted(SecurityResult result) {
        scanButton.setText(R.string.scan_again);
        scoreView.setScore(result.getScore());
        status.setText(result.getDecision() == RiskDecision.SAFE
                ? R.string.scan_complete
                : R.string.scan_attention);

        int pass = 0, warning = 0, failure = 0;
        for (Evidence evidence : result.getEvidence()) {
            if (!evidence.isDetected()) pass++;
            else if (evidence.getSeverity() == Severity.LOW
                    || evidence.getSeverity() == Severity.MEDIUM) warning++;
            else failure++;
        }

        // Pre-fill final text so the row measures at its true height before
        // we reveal it. The count-up then animates on top of this.
        passCount.setText(getString(R.string.stat_pass, pass));
        warningCount.setText(getString(R.string.stat_warning, warning));
        failureCount.setText(getString(R.string.stat_failure, failure));

        // Start count-ups slightly after the row starts to unfold, so the
        // user reads "row appears -> numbers spin up" as one gesture.
        long baseDelay = STATS_REVEAL_DELAY_MS;
        animateCount(passCount,    R.string.stat_pass,    pass,    baseDelay);
        animateCount(warningCount, R.string.stat_warning, warning, baseDelay + COUNT_STAGGER_MS);
        animateCount(failureCount, R.string.stat_failure, failure, baseDelay + COUNT_STAGGER_MS * 2);

        showStats();
    }

    private void hideStats() {
        cancelCountAnimations();
        setStatsVisible(false);
    }

    private void showStats() {
        setStatsVisible(true);
    }

    // ---------------------------------------------------------------------
    // Stats row reveal
    // ---------------------------------------------------------------------

    /**
     * Toggles the stats row with a height-folding transition so content below
     * doesn't jump. The transition targets the row itself; the parent's layout
     * pass animates the height change.
     */
    private void setStatsVisible(boolean visible) {
        if (statsRow == null) return;
        int target = visible ? View.VISIBLE : View.GONE;
        if (statsRow.getVisibility() == target) return;

        ViewParent parent = statsRow.getParent();
        if (!(parent instanceof ViewGroup)) {
            statsRow.setVisibility(target);
            return;
        }

        AutoTransition transition = new AutoTransition();
        transition.setDuration(STATS_REVEAL_DURATION_MS);
        transition.setStartDelay(visible ? STATS_REVEAL_DELAY_MS : 0L);
        transition.addTarget(statsRow);

        TransitionManager.beginDelayedTransition((ViewGroup) parent, transition);

        // Ensure the transition owns alpha / translation from a clean state.
        statsRow.setAlpha(1f);
        statsRow.setTranslationY(0f);
        statsRow.setVisibility(target);
    }

    // ---------------------------------------------------------------------
    // Count-up animation
    // ---------------------------------------------------------------------

    /**
     * Animates the given TextView from 0 up to {@code target}, formatted with
     * {@code stringRes}. A short alpha fade rides along so the number appears
     * to "materialise" rather than hard-cut.
     *
     * @param startDelayMs delay before this specific count starts, for staggering.
     */
    private void animateCount(TextView view, int stringRes, int target, long startDelayMs) {
        if (view == null) return;

        // Zero stays put; fading from 0 to 0 has no meaning.
        if (target <= 0) {
            view.setText(getString(stringRes, 0));
            view.setAlpha(1f);
            return;
        }

        // Clean slate — reset alpha in case a previous run left it mid-fade.
        view.setAlpha(0f);

        ValueAnimator animator = ValueAnimator.ofInt(0, target);
        animator.setDuration(COUNT_DURATION_MS);
        animator.setStartDelay(startDelayMs);
        animator.setInterpolator(new DecelerateInterpolator());

        animator.addUpdateListener(a -> {
            int value = (int) a.getAnimatedValue();
            float fraction = a.getAnimatedFraction();

            view.setText(getString(stringRes, value));

            // Fade in over the first ~40% of the animation, then stay solid.
            float alpha = Math.min(1f, fraction / 0.4f);
            view.setAlpha(alpha);
        });

        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                view.setText(getString(stringRes, target));
                view.setAlpha(1f);
                runningCountAnimators.remove(animation);
            }
        });

        runningCountAnimators.add(animator);
        animator.start();
    }

    /**
     * Cancels all in-flight count-up animations. Safe to call during iteration:
     * we snapshot before cancelling, because {@code Animator.cancel()} invokes
     * the end listener which would otherwise mutate the live list.
     */
    private void cancelCountAnimations() {
        if (runningCountAnimators.isEmpty()) return;
        List<ValueAnimator> snapshot = new ArrayList<>(runningCountAnimators);
        runningCountAnimators.clear();
        for (ValueAnimator animator : snapshot) {
            animator.cancel();
        }
    }

    // ---------------------------------------------------------------------
    // Device info
    // ---------------------------------------------------------------------

    private void renderDevice(View root) {
        setRow(root, R.id.modelRow,           R.string.device_model,           Build.MODEL);
        setRow(root, R.id.manufacturerRow,    R.string.device_manufacturer,    Build.MANUFACTURER);
        setRow(root, R.id.deviceRow,          R.string.device_device,          Build.DEVICE);
        setRow(root, R.id.brandRow,           R.string.device_brand,           Build.BRAND);
        setRow(root, R.id.androidVersionRow,  R.string.device_android_version,
                getString(R.string.android_version_value,
                        value(Build.VERSION.RELEASE), Build.VERSION.SDK_INT));
        setRow(root, R.id.securityPatchRow,   R.string.device_security_patch,  Build.VERSION.SECURITY_PATCH);
        setRow(root, R.id.kernelRow,          R.string.device_kernel,
                System.getProperty("os.version", "Unavailable"));
        setRow(root, R.id.buildTypeRow,       R.string.device_build_type,      Build.TYPE);
        setRow(root, R.id.buildTagsRow,       R.string.device_build_tags,      Build.TAGS);
        setRow(root, R.id.fingerprintRow,     R.string.device_fingerprint_label, Build.FINGERPRINT);
    }

    private void setRow(View root, int rowId, int labelId, String fieldValue) {
        View row = root.findViewById(rowId);
        ((TextView) row.findViewById(R.id.fieldLabel)).setText(labelId);
        ((TextView) row.findViewById(R.id.fieldValue)).setText(value(fieldValue));
    }

    private static String value(String value) {
        return value == null || value.trim().isEmpty() ? "Unavailable" : value;
    }
}