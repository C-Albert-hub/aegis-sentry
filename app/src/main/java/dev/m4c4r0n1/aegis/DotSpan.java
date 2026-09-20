package dev.m4c4r0n1.aegis;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.Layout;
import android.text.style.LeadingMarginSpan;

/**
 * 在段落左侧画一个实心圆点。
 *
 * <p>布局约定：
 * <ul>
 *   <li>圆点位于段落左边缘（x 起点），中心 = x + dotSize / 2</li>
 *   <li>文字从 x + gapWidth + dotSize 开始</li>
 *   <li>因此圆点右侧到文字的距离 = gapWidth</li>
 * </ul>
 *
 * <p>调 {@code gapWidth} 只影响圆点与文字的距离；
 * 调 {@code dotSize} 影响圆点大小；
 * 调 {@code yOffset} 微调圆点垂直位置。
 */
public final class DotSpan implements LeadingMarginSpan {

    private final int gapWidth;   // 圆点右侧到文字的间距（px）
    private final int dotSize;    // 圆点直径（px）
    private final int color;      // 圆点颜色
    private final float yOffset;  // 垂直偏移（px，正数往下）

    public DotSpan(int gapWidth, int dotSize, int color, float yOffset) {
        this.gapWidth = gapWidth;
        this.dotSize = dotSize;
        this.color = color;
        this.yOffset = yOffset;
    }

    @Override
    public int getLeadingMargin(boolean first) {
        // 缩进 = 圆点 + 圆点右侧到文字的距离
        return dotSize + gapWidth;
    }

    @Override
    public void drawLeadingMargin(Canvas canvas,
                                  Paint paint,
                                  int x,
                                  int dir,
                                  int top,
                                  int baseline,
                                  int bottom,
                                  CharSequence text,
                                  int start,
                                  int end,
                                  boolean first,
                                  Layout layout) {
        if (!first) return;

        Paint.Style oldStyle = paint.getStyle();
        int oldColor = paint.getColor();

        paint.setStyle(Paint.Style.FILL);
        paint.setColor(color);

        // 圆点位于段落左边缘（x 是段落左边缘）
        float cx = x + dotSize / 2f;
        float cy = (top + bottom) / 2f + yOffset;
        canvas.drawCircle(cx, cy, dotSize / 2f, paint);

        paint.setStyle(oldStyle);
        paint.setColor(oldColor);
    }
}