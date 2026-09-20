package dev.m4c4r0n1.aegis;

import android.content.res.ColorStateList;
import android.os.Bundle;
import android.view.View;
import android.view.animation.DecelerateInterpolator;

import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;

import com.google.android.material.button.MaterialButton;

/** Stable single-activity shell for overview, results, and settings. */
public final class MainActivity extends BaseActivity {

    private static final String TAG_OVERVIEW = "main-overview";
    private static final String TAG_RESULTS  = "main-results";
    private static final String TAG_SETTINGS = "main-settings";
    private static final String STATE_PAGE   = "selected-page";

    /** Brand overlay timings (ms). */
    private static final long OVERLAY_FADE_IN_MS = 600L;
    private static final long OVERLAY_HOLD_MS    = 800L;
    private static final long OVERLAY_FADE_OUT_MS = 800L;

    private Fragment overviewFragment;
    private Fragment resultsFragment;
    private Fragment settingsFragment;

    private MaterialButton overviewButton;
    private MaterialButton resultsButton;
    private MaterialButton settingsButton;

    private int selectedPage = R.id.navigationOverviewButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        android.util.Log.d("ThemeSwitch", "storedMode=" + ThemePreferences.getMode(this));
        // --- Brand overlay ------------------------------------------------
        View overlay = findViewById(R.id.themeTransitionOverlay);
        android.util.Log.d("ThemeSwitch", "MainActivity.onCreate isSwitching="
                + ThemePreferences.isSwitching(this) + " overlay=" + overlay);
        if (overlay != null) {
            if (ThemePreferences.isSwitching(this)) {
                ThemePreferences.setSwitching(this, false);

                // Fade in (covers the recreate black frames), hold briefly,
                // then fade out to reveal the new theme.
                overlay.setAlpha(0f);
                overlay.setVisibility(View.VISIBLE);
                overlay.animate()
                        .alpha(1f)
                        .setDuration(OVERLAY_FADE_IN_MS)
                        .withEndAction(() -> overlay.postDelayed(() -> overlay.animate()
                                        .alpha(0f)
                                        .setDuration(OVERLAY_FADE_OUT_MS)
                                        .setInterpolator(new DecelerateInterpolator())
                                        .withEndAction(() -> overlay.setVisibility(View.GONE))
                                        .start(),
                                OVERLAY_HOLD_MS))
                        .start();
                android.util.Log.d("ThemeSwitch", "overlay fade in/out started");
            } else {
                overlay.setVisibility(View.GONE);
                android.util.Log.d("ThemeSwitch", "overlay set GONE");
            }
        }

        // --- Fragment wiring ---------------------------------------------
        FragmentManager manager = getSupportFragmentManager();
        overviewFragment = manager.findFragmentByTag(TAG_OVERVIEW);
        resultsFragment  = manager.findFragmentByTag(TAG_RESULTS);
        settingsFragment = manager.findFragmentByTag(TAG_SETTINGS);

        if (savedInstanceState != null) {
            selectedPage = savedInstanceState.getInt(STATE_PAGE, R.id.navigationOverviewButton);
        }

        if (overviewFragment == null || resultsFragment == null || settingsFragment == null) {
            overviewFragment = new HomeFragment();
            resultsFragment  = new ResultsFragment();
            settingsFragment = new SettingsFragment();

            FragmentTransaction tx = manager.beginTransaction()
                    .setReorderingAllowed(true)
                    .add(R.id.mainContent, overviewFragment, TAG_OVERVIEW)
                    .add(R.id.mainContent, resultsFragment,  TAG_RESULTS)
                    .add(R.id.mainContent, settingsFragment, TAG_SETTINGS);

            if (selectedPage != R.id.navigationOverviewButton) tx.hide(overviewFragment);
            if (selectedPage != R.id.navigationResultsButton)  tx.hide(resultsFragment);
            if (selectedPage != R.id.navigationSettingsButton) tx.hide(settingsFragment);

            tx.commitNow();
        } else {
            showPage(selectedPage);
        }

        overviewButton = findViewById(R.id.navigationOverviewButton);
        resultsButton  = findViewById(R.id.navigationResultsButton);
        settingsButton = findViewById(R.id.navigationSettingsButton);

        overviewButton.setOnClickListener(v -> selectPage(R.id.navigationOverviewButton));
        resultsButton.setOnClickListener(v  -> selectPage(R.id.navigationResultsButton));
        settingsButton.setOnClickListener(v -> selectPage(R.id.navigationSettingsButton));

        updateNavigationStyles();
    }

    private void selectPage(int pageId) {
        if (pageId != R.id.navigationOverviewButton
                && pageId != R.id.navigationResultsButton
                && pageId != R.id.navigationSettingsButton) {
            return;
        }
        if (pageId == selectedPage) return;
        selectedPage = pageId;
        showPage(pageId);
        updateNavigationStyles();
    }

    private void updateNavigationStyles() {
        if (overviewButton == null || resultsButton == null || settingsButton == null) return;
        styleNavChip(overviewButton, selectedPage == R.id.navigationOverviewButton);
        styleNavChip(resultsButton,  selectedPage == R.id.navigationResultsButton);
        styleNavChip(settingsButton, selectedPage == R.id.navigationSettingsButton);
    }

    private void styleNavChip(MaterialButton button, boolean selected) {
        int background = getColor(selected
                ? R.color.nav_chip_background_selected
                : R.color.nav_chip_background);
        int iconTint = getColor(selected
                ? R.color.nav_chip_icon_selected
                : R.color.nav_chip_icon);
        int textColor = getColor(selected
                ? R.color.nav_chip_text_selected
                : R.color.nav_chip_text);

        button.setBackgroundTintList(ColorStateList.valueOf(background));
        button.setIconTint(ColorStateList.valueOf(iconTint));
        button.setTextColor(textColor);
    }

    private void showPage(int pageId) {
        if (overviewFragment == null || resultsFragment == null || settingsFragment == null) {
            return;
        }
        FragmentTransaction tx = getSupportFragmentManager().beginTransaction()
                .setReorderingAllowed(true);

        tx.hide(overviewFragment).hide(resultsFragment).hide(settingsFragment);

        if (pageId == R.id.navigationOverviewButton) {
            tx.show(overviewFragment);
        } else if (pageId == R.id.navigationResultsButton) {
            tx.show(resultsFragment);
        } else if (pageId == R.id.navigationSettingsButton) {
            tx.show(settingsFragment);
        }
        tx.commitNow();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        outState.putInt(STATE_PAGE, selectedPage);
        super.onSaveInstanceState(outState);
    }
}