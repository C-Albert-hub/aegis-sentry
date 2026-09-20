package dev.m4c4r0n1.aegis;

import android.animation.ArgbEvaluator;
import android.content.Context;
import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.View;

import androidx.core.content.ContextCompat;

/**
 * Score ring for the overview screen. It distinguishes scan progress from the final score.
 *
 * <p><b>Animation model.</b> A single {@code displayedValue} (0..100) smoothly follows a
 * target via exponential approach. Arc sweep and numeric label are both driven from it,
 * so they cannot drift out of sync.
 *
 * <p><b>Typography.</b> Value, unit and caption use independent Paints so each can be
 * tuned without touching the others. Sizes are derived from the ring radius rather than
 * fixed dp, so the composition holds at any View size.
 *
 * <p><b>SDK safety.</b> This view never touches the SDK, JNI, or any native code.
 */
public class CircleProgressView extends View {

    // ---------------------------------------------------------------------
    // Geometry ratios (relative to ring radius)
    // ---------------------------------------------------------------------

    private static final float STROKE_WIDTH_RATIO  = 0.09f;  // ring thickness / radius
    private static final float VALUE_SIZE_RATIO    = 0.72f;  // value text size / radius
    private static final float PERCENT_SIZE_RATIO  = 0.38f;  // % size relative to value
    private static final float CAPTION_SIZE_RATIO  = 0.22f;  // caption size relative to value
    private static final float PERCENT_GAP_RATIO   = 0.08f;  // gap / value size
    private static final float PERCENT_RISE_RATIO  = 0.28f;  // superscript offset / value size
    private static final float CAPTION_OFFSET_RATIO = 0.55f; // caption y offset / radius
    private static final float BASELINE_NUDGE_RATIO = 0.02f; // optical centering nudge

    // Minimum sizes so the view stays readable if it's ever rendered very small.
    private static final float MIN_STROKE_DP = 6f;

    // ---------------------------------------------------------------------
    // Animation tunables
    // ---------------------------------------------------------------------

    private static final float SMOOTHING = 0.18f;
    private static final float SNAP_EPSILON = 0.05f;

    private static final long COLOR_FADE_MS = 420L;
    private static final int  SCORE_SAFE_MIN = 80;
    private static final int  SCORE_WARNING_MIN = 50;

    private static final float GLOW_STROKE_MULT = 1.6f;
    private static final float GLOW_BLUR_DP     = 6f;
    private static final int   GLOW_ALPHA_MIN   = 18;
    private static final int   GLOW_ALPHA_MAX   = 60;
    private static final long  GLOW_PERIOD_MS   = 1400L;

    // ---------------------------------------------------------------------
    // Paints
    // ---------------------------------------------------------------------

    private final Paint ringPaint     = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glowPaint     = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint valuePaint    = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint percentPaint  = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint captionPaint  = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final RectF ringBounds = new RectF();
    private final float density;
    private final ArgbEvaluator argbEvaluator = new ArgbEvaluator();
    private final BlurMaskFilter glowBlur;

    // Pre-resolved colours.
    private final int colorSurfaceSubtle;
    private final int colorInkPrimary;
    private final int colorInkSecondary;
    private final int colorBrandBlue;
    private final int colorStatusSafe;
    private final int colorStatusWarning;
    private final int colorStatusRisk;

    // ---------------------------------------------------------------------
    // Runtime state
    // ---------------------------------------------------------------------

    private int score = -1;
    private int targetProgress;
    private float displayedValue;
    private boolean scanning;

    private int currentArcColor;
    private int targetArcColor;
    private long colorFadeStartedAt;

    private long scanStartedAt;

    private String cachedText = "--";

    // ---------------------------------------------------------------------
    // Constructors
    // ---------------------------------------------------------------------

    public CircleProgressView(Context context) {
        this(context, null);
    }

    public CircleProgressView(Context context, AttributeSet attrs) {
        super(context, attrs);
        density = getResources().getDisplayMetrics().density;
        glowBlur = new BlurMaskFilter(GLOW_BLUR_DP * density, BlurMaskFilter.Blur.NORMAL);

        colorSurfaceSubtle = ContextCompat.getColor(context, R.color.surface_subtle);
        colorInkPrimary    = ContextCompat.getColor(context, R.color.ink_primary);
        colorInkSecondary  = ContextCompat.getColor(context, R.color.ink_secondary);
        colorBrandBlue     = ContextCompat.getColor(context, R.color.brand_blue);
        colorStatusSafe    = ContextCompat.getColor(context, R.color.status_safe);
        colorStatusWarning = ContextCompat.getColor(context, R.color.status_warning);
        colorStatusRisk    = ContextCompat.getColor(context, R.color.status_risk);

        currentArcColor = colorBrandBlue;
        targetArcColor  = colorBrandBlue;

        initPaints();
    }

    private void initPaints() {
        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeCap(Paint.Cap.ROUND);

        glowPaint.setStyle(Paint.Style.STROKE);
        glowPaint.setStrokeCap(Paint.Cap.ROUND);
        glowPaint.setMaskFilter(glowBlur);

        Typeface bold = Typeface.create(Typeface.DEFAULT, Typeface.BOLD);
        Typeface normal = Typeface.create(Typeface.DEFAULT, Typeface.NORMAL);

        valuePaint.setTextAlign(Paint.Align.CENTER);
        valuePaint.setTypeface(bold);

        percentPaint.setTextAlign(Paint.Align.LEFT);
        percentPaint.setTypeface(bold);

        captionPaint.setTextAlign(Paint.Align.CENTER);
        captionPaint.setTypeface(normal);
        captionPaint.setLetterSpacing(0.08f); // API 21+
    }

    // ---------------------------------------------------------------------
    // Drawing
    // ---------------------------------------------------------------------

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        boolean needsAnotherFrame = advanceValueAnimation();
        needsAnotherFrame |= advanceColorFade();
        needsAnotherFrame |= advanceGlowPulse();
        if (needsAnotherFrame) postInvalidateOnAnimation();

        float centerX = getWidth() / 2f;
        float centerY = getHeight() / 2f;
        float maxRadius = Math.min(getWidth(), getHeight()) / 2f;
        float stroke = Math.max(MIN_STROKE_DP * density, maxRadius * STROKE_WIDTH_RATIO);
        float radius = maxRadius - stroke;
        ringBounds.set(centerX - radius, centerY - radius, centerX + radius, centerY + radius);

        drawRing(canvas, stroke);
        drawValue(canvas, centerX, centerY, radius);
        drawCaption(canvas, centerX, centerY, radius);

        updateContentDescription();
    }

    private void drawRing(Canvas canvas, float stroke) {
        ringPaint.setStrokeWidth(stroke);
        ringPaint.setColor(colorSurfaceSubtle);
        canvas.drawArc(ringBounds, -90f, 360f, false, ringPaint);

        float sweep = displayedValue * 3.6f;
        if (scanning && sweep > 0f) {
            glowPaint.setStrokeWidth(stroke * GLOW_STROKE_MULT);
            glowPaint.setColor(currentArcColor);
            glowPaint.setAlpha(computeGlowAlpha());
            canvas.drawArc(ringBounds, -90f, sweep, false, glowPaint);
        }

        ringPaint.setColor(currentArcColor);
        canvas.drawArc(ringBounds, -90f, sweep, false, ringPaint);
    }

    private void drawValue(Canvas canvas, float centerX, float centerY, float radius) {
        boolean placeholder = score < 0 && !scanning;
        float valueSize = radius * VALUE_SIZE_RATIO;

        valuePaint.setTextSize(valueSize);
        valuePaint.setColor(colorInkPrimary);

        String value = updateCachedText(placeholder);

        // Optical vertical centering: digits have no descender, so pure (ascent+descent)/2
        // sits slightly high. Nudge down by a fraction of the text size.
        Paint.FontMetrics fm = valuePaint.getFontMetrics();
        float baseline = centerY
                - (fm.ascent + fm.descent) / 2f
                + valueSize * BASELINE_NUDGE_RATIO;

        float valueWidth = valuePaint.measureText(value);
        canvas.drawText(value, centerX, baseline, valuePaint);

        if (scanning) {
            percentPaint.setTextSize(valueSize * PERCENT_SIZE_RATIO);
            percentPaint.setColor(colorInkPrimary);
            float percentX = centerX + valueWidth / 2f + valueSize * PERCENT_GAP_RATIO;
            float percentBaseline = baseline - valueSize * PERCENT_RISE_RATIO;
            canvas.drawText("%", percentX, percentBaseline, percentPaint);
        }
    }

    private void drawCaption(Canvas canvas, float centerX, float centerY, float radius) {
        float valueSize = radius * VALUE_SIZE_RATIO;
        captionPaint.setTextSize(valueSize * CAPTION_SIZE_RATIO);
        captionPaint.setColor(colorInkSecondary);
        float captionY = centerY + radius * CAPTION_OFFSET_RATIO;
        canvas.drawText(scanning ? "SCANNING" : "SCORE", centerX, captionY, captionPaint);
    }

    // ---------------------------------------------------------------------
    // Animation drivers
    // ---------------------------------------------------------------------

    private boolean advanceValueAnimation() {
        float target = scanning ? targetProgress : Math.max(0, score);
        float delta = target - displayedValue;
        if (Math.abs(delta) < SNAP_EPSILON) {
            displayedValue = target;
            return false;
        }
        displayedValue += delta * SMOOTHING;
        return true;
    }

    private boolean advanceColorFade() {
        if (currentArcColor == targetArcColor) return false;
        long now = android.os.SystemClock.uptimeMillis();
        float t = (now - colorFadeStartedAt) / (float) COLOR_FADE_MS;
        if (t >= 1f) {
            currentArcColor = targetArcColor;
            return false;
        }
        currentArcColor = (int) argbEvaluator.evaluate(t, currentArcColor, targetArcColor);
        return true;
    }

    private boolean advanceGlowPulse() {
        return scanning;
    }

    private int computeGlowAlpha() {
        if (!scanning) return 0;
        long elapsed = android.os.SystemClock.uptimeMillis() - scanStartedAt;
        float phase = (elapsed % GLOW_PERIOD_MS) / (float) GLOW_PERIOD_MS;
        float eased = 0.5f - 0.5f * (float) Math.cos(phase * 2.0 * Math.PI);
        return (int) (GLOW_ALPHA_MIN + (GLOW_ALPHA_MAX - GLOW_ALPHA_MIN) * eased);
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private String updateCachedText(boolean placeholder) {
        if (placeholder) {
            if (!"--".equals(cachedText)) cachedText = "--";
            return cachedText;
        }
        String next = String.valueOf(Math.round(displayedValue));
        if (!next.equals(cachedText)) cachedText = next;
        return cachedText;
    }

    private void updateContentDescription() {
        String description;
        if (scanning) {
            description = "Scanning, " + Math.round(displayedValue) + " percent";
        } else if (score < 0) {
            description = "No score yet";
        } else {
            description = "Security score " + score + " out of 100";
        }
        if (!description.equals(getContentDescription())) {
            setContentDescription(description);
        }
    }

    private void fadeArcColorTo(int color) {
        if (color == targetArcColor) return;
        targetArcColor = color;
        colorFadeStartedAt = android.os.SystemClock.uptimeMillis();
    }

    private int bandColorFor(int value) {
        if (value < 0) return colorBrandBlue;
        if (value >= SCORE_SAFE_MIN) return colorStatusSafe;
        if (value >= SCORE_WARNING_MIN) return colorStatusWarning;
        return colorStatusRisk;
    }

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    public void reset() {
        scanning = false;
        score = -1;
        targetProgress = 0;
        displayedValue = 0f;
        cachedText = "--";
        currentArcColor = colorBrandBlue;
        targetArcColor  = colorBrandBlue;
        invalidate();
    }

    public void setScanProgress(int value) {
        int clamped = clamp(value);
        if (scanning && clamped == targetProgress) return;
        if (!scanning) scanStartedAt = android.os.SystemClock.uptimeMillis();
        scanning = true;
        targetProgress = clamped;
        fadeArcColorTo(colorBrandBlue);
        invalidate();
    }

    public void setScore(int value) {
        scanning = false;
        score = clamp(value);
        targetProgress = score;
        fadeArcColorTo(bandColorFor(score));
        invalidate();
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }
}