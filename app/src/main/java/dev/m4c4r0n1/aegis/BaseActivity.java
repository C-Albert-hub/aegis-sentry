package dev.m4c4r0n1.aegis;

import android.content.Context;

import androidx.appcompat.app.AppCompatActivity;

public abstract class BaseActivity extends AppCompatActivity {

    @Override
    protected void attachBaseContext(Context newBase) {
        // Do nothing special — AppCompatDelegate handles night mode.
        super.attachBaseContext(newBase);
        android.util.Log.d("ThemeSwitch", "BaseActivity attachBaseContext, mode="
                + ThemePreferences.getMode(newBase));
    }
}