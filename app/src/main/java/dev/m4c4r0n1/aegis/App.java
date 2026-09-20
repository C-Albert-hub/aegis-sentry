package dev.m4c4r0n1.aegis;

import android.app.Application;

import androidx.appcompat.app.AppCompatDelegate;

public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        AppCompatDelegate.setDefaultNightMode(ThemePreferences.getMode(this));
    }
}