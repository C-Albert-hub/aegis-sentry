package dev.m4c4r0n1.aegis;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.appcompat.app.AppCompatDelegate;

public final class ThemePreferences {

    private static final String PREFS_NAME = "theme_prefs";
    private static final String KEY_MODE = "night_mode";
    private static final String KEY_SWITCHING = "theme_switching";
    private static final String KEY_SWITCHING_AT = "theme_switching_at";

    /** A theme-switch flag older than this is considered stale. */
    private static final long SWITCHING_STALE_MS = 2000L;

    private ThemePreferences() {}

    public static int getMode(Context context) {
        return prefs(context).getInt(KEY_MODE, AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
    }

    public static void setMode(Context context, int mode) {
        prefs(context).edit().putInt(KEY_MODE, mode).commit();
    }

    /** Returns true if a theme switch is pending AND recent. */
    public static boolean isSwitching(Context context) {
        if (!prefs(context).getBoolean(KEY_SWITCHING, false)) return false;

        long at = prefs(context).getLong(KEY_SWITCHING_AT, 0L);
        long ageMs = System.currentTimeMillis() - at;
        if (ageMs > SWITCHING_STALE_MS) {
            // Stale — treat as no switch and clear the flag.
            setSwitching(context, false);
            return false;
        }
        return true;
    }

    public static void setSwitching(Context context, boolean switching) {
        prefs(context).edit()
                .putBoolean(KEY_SWITCHING, switching)
                .putLong(KEY_SWITCHING_AT, System.currentTimeMillis())
                .commit();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}