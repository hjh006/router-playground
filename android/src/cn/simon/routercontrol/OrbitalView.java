package cn.simon.routercontrol;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.view.View;

/** A static, decorative network orbital. No animation or synthetic telemetry. */
public final class OrbitalView extends View {
    private final Paint p = new Paint(3);
    private final int accent;

    public OrbitalView(Context context) {
        super(context);
        accent = context.getColor(R.color.primary);
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
    }

    @Override protected void onDraw(Canvas canvas) {
        float size = Math.min(getWidth(), getHeight());
        float cx = getWidth() * .5f, cy = getHeight() * .5f, r = size * .38f;
        p.setStyle(Paint.Style.FILL);
        p.setShader(new RadialGradient(cx, cy, r * 1.35f,
                new int[]{0x284FE6CB, 0x0A4FE6CB, 0x004FE6CB}, null, Shader.TileMode.CLAMP));
        canvas.drawCircle(cx, cy, r * 1.35f, p);
        p.setShader(null);
        p.setColor(accent);
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeWidth(getResources().getDisplayMetrics().density * .7f);
        p.setAlpha(70);
        canvas.drawCircle(cx, cy, r, p);
        RectF orbit = new RectF(cx - r, cy - r * .36f, cx + r, cy + r * .36f);
        for (int i = 0; i < 3; i++) {
            canvas.save();
            canvas.rotate(23 + i * 58, cx, cy);
            canvas.drawOval(orbit, p);
            canvas.restore();
        }
        double[] angles = {-.9, .3, 1.9, 3.5, 4.4};
        p.setAlpha(120);
        for (double angle : angles) {
            float x = cx + r * (float) Math.cos(angle), y = cy + r * (float) Math.sin(angle);
            canvas.drawLine(cx, cy, x, y, p);
        }
        p.setStyle(Paint.Style.FILL);
        p.setAlpha(255);
        canvas.drawCircle(cx, cy, size * .035f, p);
        for (double angle : angles) {
            float x = cx + r * (float) Math.cos(angle), y = cy + r * (float) Math.sin(angle);
            canvas.drawCircle(x, y, size * .018f, p);
        }
    }
}
