package dev.m4c4r0n1.aegis;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.fragment.app.Fragment;

public final class SettingsFragment extends Fragment {

    private TextView themeValue;

    public SettingsFragment() {
        super(R.layout.fragment_settings);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        themeValue = view.findViewById(R.id.themeValue);
        view.findViewById(R.id.rowTheme).setOnClickListener(v ->
                new ThemeModeBottomSheet()
                        .show(getChildFragmentManager(), "theme_mode"));

        refreshThemeSummary();
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshThemeSummary();
    }

    private void refreshThemeSummary() {
        if (themeValue == null) return;
        themeValue.setText(currentThemeLabel());
    }

    private String currentThemeLabel() {
        int mode = ThemePreferences.getMode(requireContext());
        if (mode == AppCompatDelegate.MODE_NIGHT_YES) {
            return getString(R.string.theme_mode_dark);
        }
        if (mode == AppCompatDelegate.MODE_NIGHT_NO) {
            return getString(R.string.theme_mode_light);
        }
        // Follow System
        return getString(R.string.theme_mode_follow_system);
    }
}