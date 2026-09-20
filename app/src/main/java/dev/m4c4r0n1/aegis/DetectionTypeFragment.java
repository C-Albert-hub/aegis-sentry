package dev.m4c4r0n1.aegis;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.interpolator.view.animation.LinearOutSlowInInterpolator;
import androidx.lifecycle.ViewModelProvider;

import dev.m4c4r0n1.aegis.core.EvidenceClassifier;
import com.google.android.material.card.MaterialCardView;

import java.util.List;

import dev.m4c4r0n1.seclibrary.Evidence;
import dev.m4c4r0n1.seclibrary.SecurityResult;
import dev.m4c4r0n1.seclibrary.Severity;

public final class DetectionTypeFragment extends Fragment {

    private static final String ARG_TYPE = "type";
    private static final long DETAIL_ANIM_MS = 260L;

    private LinearLayout evidenceContainer;

    public DetectionTypeFragment() {
        super(R.layout.fragment_detection_type);
    }

    static DetectionTypeFragment newInstance(String type) {
        DetectionTypeFragment fragment = new DetectionTypeFragment();
        Bundle args = new Bundle();
        args.putString(ARG_TYPE, type);
        fragment.setArguments(args);
        return fragment;
    }

    static String tagFor(int position) {
        return "detection-type-" + position;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        evidenceContainer = view.findViewById(R.id.evidenceContainer);
        new ViewModelProvider(requireActivity()).get(ResultsViewModel.class).getResult()
                .observe(getViewLifecycleOwner(), this::render);
    }

    private void render(SecurityResult result) {
        if (result == null) return;

        String type = getArguments() == null
                ? EvidenceClassifier.TYPES[EvidenceClassifier.ENVIRONMENT]
                : getArguments().getString(ARG_TYPE,
                EvidenceClassifier.TYPES[EvidenceClassifier.ENVIRONMENT]);

        List<Evidence> evidence = EvidenceClassifier.group(result.getEvidence()).get(type);
        if (evidence == null) return;

        evidenceContainer.removeAllViews();

        TextView summary = requireView().findViewById(R.id.typeSummary);
        if (summary != null) {
            summary.setText(getString(R.string.module_summary, evidence.size()));
        }

        if (evidence.isEmpty()) {
            evidenceContainer.addView(createEmptyView());
            return;
        }

        for (Evidence item : evidence) {
            evidenceContainer.addView(createEvidence(item));
        }
    }

    private TextView createEmptyView() {
        TextView empty = new TextView(requireContext());
        empty.setText(R.string.no_type_evidence);
        empty.setTextColor(requireContext().getColor(R.color.ink_secondary));
        empty.setTextSize(13f);
        return empty;
    }

    private View createEvidence(Evidence evidence) {
        View item = getLayoutInflater().inflate(R.layout.item_security, evidenceContainer, false);

        MaterialCardView card = item.findViewById(R.id.securityCard);
        View statusCircle = item.findViewById(R.id.statusCircle);
        TextView name = item.findViewById(R.id.name);
        TextView subtitle = item.findViewById(R.id.subtitle);
        TextView statusBadge = item.findViewById(R.id.statusBadge);
        View detail = item.findViewById(R.id.evidenceDetail);
        TextView value = item.findViewById(R.id.evidenceValue);

        name.setText(EvidenceClassifier.displayName(evidence.getType()));

        // 拆 details：第一行 = subtitle，剩余 = value
        String details = evidence.getValue();
        String[] lines = details == null ? new String[0] : details.split("\n", -1);

        String summary = lines.length > 0 ? lines[0] : "";
        subtitle.setText(summary);

        StringBuilder body = new StringBuilder();
        for (int i = 1; i < lines.length; i++) {
            if (body.length() > 0) body.append("\n");
            body.append(lines[i]);
        }
        value.setText(formatDetailLines(body.toString()));

        // 状态
        String badgeText;
        int badgeTextColor;
        int badgeBgColor;
        int circleColor;

        if (!evidence.isDetected()) {
            badgeText = "PASS";
            badgeTextColor = requireContext().getColor(R.color.status_safe);
            badgeBgColor = requireContext().getColor(R.color.status_safe_tint);
            circleColor = requireContext().getColor(R.color.status_safe_dark);
        } else {
            Severity severity = evidence.getSeverity();
            if (severity == Severity.LOW || severity == Severity.MEDIUM) {
                badgeText = "WARN";
                badgeTextColor = requireContext().getColor(R.color.status_warning);
                badgeBgColor = requireContext().getColor(R.color.status_warning_tint);
                circleColor = requireContext().getColor(R.color.status_warning_dark);
            } else {
                badgeText = "FAIL";
                badgeTextColor = requireContext().getColor(R.color.status_risk);
                badgeBgColor = requireContext().getColor(R.color.status_risk_tint);
                circleColor = requireContext().getColor(R.color.status_risk_dark);
            }
        }

        // 左圈：动态创建
        final float density = getResources().getDisplayMetrics().density;
        final int circleSizePx = (int) (20 * density);

        ViewGroup.LayoutParams lp = statusCircle.getLayoutParams();
        lp.width = circleSizePx;
        lp.height = circleSizePx;
        statusCircle.setLayoutParams(lp);

        GradientDrawable circle = new GradientDrawable();
        circle.setShape(GradientDrawable.OVAL);
        circle.setColor(circleColor);
        circle.setSize(circleSizePx, circleSizePx);
        statusCircle.setBackground(circle);

        statusBadge.setText(badgeText);
        statusBadge.setTextColor(badgeTextColor);
        statusBadge.setBackground(makeCapsuleBackground(badgeBgColor));

        collapseImmediately(detail);

        card.setOnClickListener(view -> toggleDetail(card, detail, value));
        card.setContentDescription(name.getText());

        return item;
    }
    // ---------------------------------------------------------------------
    // Format details with DotSpan
    // ---------------------------------------------------------------------

    private CharSequence formatDetailLines(String details) {
        if (details == null || details.isEmpty()) return "";

        String[] lines = details.split("\n", -1);
        SpannableStringBuilder builder = new SpannableStringBuilder();

        final float density = getResources().getDisplayMetrics().density;
        final int gap = (int) (12 * density);
        final int dotSize = (int) (6 * density);
        final float yOffset = 1 * density;
        final int dotColor = requireContext().getColor(R.color.brand_blue);

        for (int i = 0; i < lines.length; i++) {
            if (i > 0) builder.append("\n");

            String line = lines[i];
            String trimmed = line.trim();

            if (trimmed.startsWith("• ")) {
                int start = builder.length();
                builder.append(trimmed.substring(2));
                builder.setSpan(
                        new DotSpan(gap, dotSize, dotColor, yOffset),
                        start, builder.length(),
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            } else {
                builder.append(line);
            }
        }
        return builder;
    }

    // ---------------------------------------------------------------------
    // Expand / collapse
    // ---------------------------------------------------------------------

    private void collapseImmediately(View detail) {
        ViewGroup.LayoutParams params = detail.getLayoutParams();
        params.height = 0;
        detail.setLayoutParams(params);
        detail.setVisibility(View.GONE);
    }

    private void toggleDetail(MaterialCardView card, View detail, TextView value) {
        final boolean collapsing = detail.getVisibility() == View.VISIBLE;

        Object tag = detail.getTag(R.id.evidenceDetail);
        if (tag instanceof ValueAnimator) {
            ((ValueAnimator) tag).cancel();
        }

        final int parentWidth = detail.getWidth() > 0
                ? detail.getWidth()
                : (evidenceContainer != null ? evidenceContainer.getWidth() : 0);
        detail.measure(
                View.MeasureSpec.makeMeasureSpec(Math.max(parentWidth, 0),
                        View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        final int targetHeight = detail.getMeasuredHeight();

        final int from;
        final int to;
        if (collapsing) {
            from = detail.getHeight();
            to = 0;
        } else {
            detail.setVisibility(View.VISIBLE);
            ViewGroup.LayoutParams params = detail.getLayoutParams();
            params.height = 0;
            detail.setLayoutParams(params);
            from = 0;
            to = targetHeight;
            value.setAlpha(0f);
        }

        ValueAnimator animator = ValueAnimator.ofInt(from, to);
        animator.setDuration(DETAIL_ANIM_MS);
        animator.setInterpolator(new LinearOutSlowInInterpolator());

        animator.addUpdateListener(animation -> {
            final float progress = animation.getAnimatedFraction();

            ViewGroup.LayoutParams params = detail.getLayoutParams();
            params.height = (int) animation.getAnimatedValue();
            detail.setLayoutParams(params);

            final float contentAlpha;
            if (collapsing) {
                contentAlpha = Math.max(0f, 1f - progress / 0.6f);
            } else {
                contentAlpha = Math.max(0f, (progress - 0.3f) / 0.7f);
            }
            value.setAlpha(contentAlpha);
        });

        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                ViewGroup.LayoutParams params = detail.getLayoutParams();
                if (collapsing) {
                    params.height = 0;
                    detail.setLayoutParams(params);
                    detail.setVisibility(View.GONE);
                } else {
                    params.height = ViewGroup.LayoutParams.WRAP_CONTENT;
                    detail.setLayoutParams(params);
                }
                value.setAlpha(1f);
                detail.setTag(R.id.evidenceDetail, null);
            }
        });

        detail.setTag(R.id.evidenceDetail, animator);
        animator.start();

        card.setStrokeColor(requireContext().getColor(
                collapsing ? R.color.outline_light : R.color.brand_blue));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private Drawable makeCapsuleBackground(int color) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.RECTANGLE);
        d.setColor(color);
        d.setCornerRadius(12 * getResources().getDisplayMetrics().density);
        return d;
    }
}