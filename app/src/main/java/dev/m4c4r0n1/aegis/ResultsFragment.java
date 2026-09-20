package dev.m4c4r0n1.aegis;

import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.ViewModelProvider;

import dev.m4c4r0n1.aegis.core.EvidenceClassifier;
import com.google.android.material.button.MaterialButton;

import java.util.List;

import dev.m4c4r0n1.seclibrary.Evidence;
import dev.m4c4r0n1.seclibrary.SecurityResult;
import dev.m4c4r0n1.seclibrary.Severity;

/**
 * Results UI.
 *
 * <p>The module selector is a row of chips, each carrying a status dot so the
 * user can see at a glance which module has findings without tapping through
 * every tab. Dot colours: green = all clean, amber = warnings, red = failures,
 * grey = no data.
 */
public final class ResultsFragment extends Fragment {

    private static final String STATE_TAB = "selected-tab";
    private static final String TYPE_TAG_PREFIX = "result-type-";

    private LinearLayout moduleButtons;   // ← 关键：LinearLayout，不是 ToggleGroup
    private CircleProgressView scoreRing;
    private TextView summaryView;
    private Fragment[] typeFragments;
    private MaterialButton[] tabButtons;
    private int selectedTab;

    public ResultsFragment() {
        super(R.layout.fragment_results);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        moduleButtons = view.findViewById(R.id.moduleButtons);   // ← LinearLayout
        scoreRing     = view.findViewById(R.id.resultScoreRing);
        summaryView   = view.findViewById(R.id.resultSummary);

        tabButtons = new MaterialButton[]{
                view.findViewById(R.id.moduleEnvironment),
                view.findViewById(R.id.moduleAntiDebug),
                view.findViewById(R.id.moduleAntiInjection),
                view.findViewById(R.id.moduleAppIntegrity),
                view.findViewById(R.id.moduleNativeIntegrity)
        };

        if (savedInstanceState != null) {
            selectedTab = savedInstanceState.getInt(STATE_TAB, 0);
        }

        new ViewModelProvider(requireActivity()).get(ResultsViewModel.class).getResult()
                .observe(getViewLifecycleOwner(), this::renderSummary);

        for (int i = 0; i < tabButtons.length; i++) {
            final int position = i;
            tabButtons[i].setOnClickListener(v -> selectTab(position));
        }

        prepareTypeFragments();
        applyTabStyles(null);
        showType(selectedTab);
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        outState.putInt(STATE_TAB, selectedTab);
        super.onSaveInstanceState(outState);
    }

    private void selectTab(int position) {
        if (position < 0 || position >= EvidenceClassifier.TYPES.length) return;
        if (position == selectedTab) return;
        selectedTab = position;
        showType(selectedTab);
        SecurityResult current = new ViewModelProvider(requireActivity())
                .get(ResultsViewModel.class).getResult().getValue();
        applyTabStyles(current);
    }

    private void prepareTypeFragments() {
        FragmentManager manager = getChildFragmentManager();
        typeFragments = new Fragment[EvidenceClassifier.TYPES.length];
        FragmentTransaction transaction = manager.beginTransaction().setReorderingAllowed(true);
        boolean needsCreate = false;
        for (int index = 0; index < typeFragments.length; index++) {
            typeFragments[index] = manager.findFragmentByTag(TYPE_TAG_PREFIX + index);
            if (typeFragments[index] == null) {
                typeFragments[index] = DetectionTypeFragment.newInstance(
                        EvidenceClassifier.TYPES[index]);
                transaction.add(R.id.resultFragmentContainer, typeFragments[index],
                        TYPE_TAG_PREFIX + index);
                needsCreate = true;
            }
        }
        if (needsCreate) {
            for (int index = 1; index < typeFragments.length; index++) {
                transaction.hide(typeFragments[index]);
            }
            transaction.commitNow();
        }
    }

    private void showType(int position) {
        if (typeFragments == null || position < 0 || position >= typeFragments.length) return;
        FragmentTransaction transaction = getChildFragmentManager().beginTransaction()
                .setReorderingAllowed(true);
        for (int index = 0; index < typeFragments.length; index++) {
            if (index == position) {
                transaction.show(typeFragments[index]);
            } else {
                transaction.hide(typeFragments[index]);
            }
        }
        transaction.commitNow();
    }

    private void renderSummary(SecurityResult result) {
        if (scoreRing == null || summaryView == null) return;
        if (result == null) {
            scoreRing.reset();
            summaryView.setText(R.string.no_scan_yet);
            applyTabStyles(null);
            return;
        }
        scoreRing.setScore(result.getScore());
        summaryView.setText(R.string.overall_security_score);
        applyTabStyles(result);
    }

    private void applyTabStyles(@Nullable SecurityResult result) {
        if (tabButtons == null || !isAdded()) return;

        for (int i = 0; i < tabButtons.length; i++) {
            MaterialButton button = tabButtons[i];
            boolean selected = i == selectedTab;

            int background = requireContext().getColor(selected
                    ? R.color.chip_background_selected
                    : R.color.chip_background);
            int stroke = requireContext().getColor(selected
                    ? R.color.chip_stroke_selected
                    : R.color.chip_stroke);
            int text = requireContext().getColor(selected
                    ? R.color.chip_text_selected
                    : R.color.chip_text);

            button.setBackgroundTintList(ColorStateList.valueOf(background));
            button.setStrokeColor(ColorStateList.valueOf(stroke));
            button.setTextColor(text);

            int dotColorRes = dotColorFor(result, i);
            button.setIconTint(ColorStateList.valueOf(requireContext().getColor(dotColorRes)));
            button.setIconResource(R.drawable.ic_dot);

            button.setTypeface(null, selected ? Typeface.BOLD : Typeface.NORMAL);
        }
    }

    private int dotColorFor(@Nullable SecurityResult result, int position) {
        if (result == null) return R.color.chip_dot;

        String type = EvidenceClassifier.TYPES[position];
        List<Evidence> evidence = EvidenceClassifier.group(result.getEvidence()).get(type);
        if (evidence == null || evidence.isEmpty()) return R.color.chip_dot;

        boolean hasWarning = false;
        boolean hasFailure = false;
        for (Evidence item : evidence) {
            if (!item.isDetected()) continue;
            Severity severity = item.getSeverity();
            if (severity == Severity.LOW || severity == Severity.MEDIUM) {
                hasWarning = true;
            } else {
                hasFailure = true;
            }
        }
        if (hasFailure) return R.color.chip_dot_risk;
        if (hasWarning) return R.color.chip_dot_warning;
        return R.color.chip_dot_safe;
    }
}