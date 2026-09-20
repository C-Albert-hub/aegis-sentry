package dev.m4c4r0n1.aegis;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDelegate;

import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

public final class ThemeModeBottomSheet extends BottomSheetDialogFragment {

    private static final int EFFECTIVE_LIGHT = 0;
    private static final int EFFECTIVE_DARK = 1;
    private static final long FADE_IN_MS = 200L;
    private static final long HOLD_MS = 1600L;
    private static final long FADE_OUT_MS = 200L;

    private static final int[] OPTION_ICONS = {
            R.drawable.ic_brightness_auto,
            R.drawable.ic_light_mode,
            R.drawable.ic_dark_mode
    };

    private static final int[] OPTION_MODES = {
            AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM,
            AppCompatDelegate.MODE_NIGHT_NO,
            AppCompatDelegate.MODE_NIGHT_YES
    };

    private static final int[] OPTION_LABELS = {
            R.string.theme_mode_follow_system,
            R.string.theme_mode_light,
            R.string.theme_mode_dark
    };

    private static final int POSITION_SYSTEM = 0;

    public ThemeModeBottomSheet() {
        // Required empty constructor
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        int current = ThemePreferences.getMode(requireContext());
        int checkedItem = positionFromMode(current);

        ThemeOptionAdapter adapter = new ThemeOptionAdapter(
                requireContext(), OPTION_ICONS, OPTION_LABELS, checkedItem);

        return new MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.theme_mode_title)
                .setAdapter(adapter, (dialog, which) -> applyMode(which))
                .create();
    }

    private int positionFromMode(int mode) {
        for (int i = 0; i < OPTION_MODES.length; i++) {
            if (OPTION_MODES[i] == mode) return i;
        }
        return 0;
    }

    private void applyMode(int position) {
        if (position < 0 || position >= OPTION_MODES.length) return;

        int targetMode = OPTION_MODES[position];
        int currentMode = ThemePreferences.getMode(requireContext());
        boolean changes = effectiveTheme(targetMode) != effectiveTheme(currentMode);

        CharSequence message = null;
        if (position == POSITION_SYSTEM) {
            message = getString(systemToastText());
        } else if (!changes) {
            message = getString(R.string.theme_mode_unchanged);
        }

        if (changes) {
            ThemePreferences.setMode(requireContext(), targetMode);
            ThemePreferences.setSwitching(requireContext(), true);
            AppCompatDelegate.setDefaultNightMode(targetMode);
        }

        final CharSequence finalMessage = message;
        final Activity activity = getActivity();

        dismiss();

        if (finalMessage != null && activity != null) {
            View root = activity.findViewById(android.R.id.content);
            View anchor = activity.findViewById(R.id.bottomNavigation);
            if (root != null) {
                root.post(() -> showOverlayToast(activity, root, anchor, finalMessage));
            }
        }
    }

    /** Shows a custom, auto-sizing toast above the bottom navigation. */
    private void showOverlayToast(Activity activity, View root,
                                  @Nullable View anchor, CharSequence message) {
        if (activity.isFinishing()) return;
        if (!(root instanceof ViewGroup)) return;

        View custom = LayoutInflater.from(activity)
                .inflate(R.layout.custom_snackbar, (ViewGroup) root, false);
        TextView text = custom.findViewById(R.id.snackbarText);
        text.setText(message);

        float density = activity.getResources().getDisplayMetrics().density;

        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL;

        if (anchor != null) {
            int[] anchorLoc = new int[2];
            anchor.getLocationOnScreen(anchorLoc);
            int[] rootLoc = new int[2];
            root.getLocationOnScreen(rootLoc);
            int anchorTopInRoot = anchorLoc[1] - rootLoc[1];
            lp.bottomMargin = root.getHeight() - anchorTopInRoot + (int) (16 * density);
        } else {
            lp.bottomMargin = (int) (100 * density);
        }

        custom.setAlpha(0f);
        ((ViewGroup) root).addView(custom, lp);

        custom.animate()
                .alpha(1f)
                .setDuration(FADE_IN_MS)
                .withEndAction(() -> custom.postDelayed(() -> custom.animate()
                        .alpha(0f)
                        .setDuration(FADE_OUT_MS)
                        .withEndAction(() -> ((ViewGroup) root).removeView(custom))
                        .start(), HOLD_MS))
                .start();
    }

    private int effectiveTheme(int mode) {
        switch (mode) {
            case AppCompatDelegate.MODE_NIGHT_YES:
                return EFFECTIVE_DARK;
            case AppCompatDelegate.MODE_NIGHT_NO:
                return EFFECTIVE_LIGHT;
            default:
                return systemEffectiveTheme();
        }
    }

    private int systemEffectiveTheme() {
        int nightMode = Resources.getSystem()
                .getConfiguration().uiMode
                & Configuration.UI_MODE_NIGHT_MASK;
        return nightMode == Configuration.UI_MODE_NIGHT_YES
                ? EFFECTIVE_DARK
                : EFFECTIVE_LIGHT;
    }

    private int systemToastText() {
        return systemEffectiveTheme() == EFFECTIVE_DARK
                ? R.string.theme_system_current_dark
                : R.string.theme_system_current_light;
    }

    private static final class ThemeOptionAdapter extends BaseAdapter {

        private final Context context;
        private final int[] icons;
        private final int[] labels;
        private final int checkedPosition;

        ThemeOptionAdapter(Context context, int[] icons, int[] labels, int checkedPosition) {
            this.context = context;
            this.icons = icons;
            this.labels = labels;
            this.checkedPosition = checkedPosition;
        }

        @Override public int getCount() { return icons.length; }
        @Override public Object getItem(int position) { return labels[position]; }
        @Override public long getItemId(int position) { return position; }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View row = convertView;
            if (row == null) {
                row = LayoutInflater.from(context)
                        .inflate(R.layout.item_theme_option, parent, false);
            }

            ImageView icon = row.findViewById(R.id.optionIcon);
            TextView label = row.findViewById(R.id.optionLabel);
            ImageView check = row.findViewById(R.id.optionCheck);

            icon.setImageResource(icons[position]);
            label.setText(labels[position]);
            check.setVisibility(position == checkedPosition
                    ? View.VISIBLE : View.INVISIBLE);

            return row;
        }
    }
}