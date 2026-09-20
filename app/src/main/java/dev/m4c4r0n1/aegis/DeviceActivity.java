package dev.m4c4r0n1.aegis;

import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;


/** Read-only device information page. */
public final class DeviceActivity extends BaseActivity  {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_device);
        findViewById(R.id.backButton).setOnClickListener(view -> finish());
        setRow(R.id.modelRow, R.string.device_model, Build.MODEL);
        setRow(R.id.manufacturerRow, R.string.device_manufacturer, Build.MANUFACTURER);
        setRow(R.id.deviceRow, R.string.device_device, Build.DEVICE);
        setRow(R.id.brandRow, R.string.device_brand, Build.BRAND);
        setRow(R.id.androidVersionRow, R.string.device_android_version,
                getString(R.string.android_version_value, Build.VERSION.RELEASE, Build.VERSION.SDK_INT));
        setRow(R.id.securityPatchRow, R.string.device_security_patch, Build.VERSION.SECURITY_PATCH);
        setRow(R.id.kernelRow, R.string.device_kernel, System.getProperty("os.version", "Unavailable"));
        setRow(R.id.buildTypeRow, R.string.device_build_type, Build.TYPE);
        setRow(R.id.buildTagsRow, R.string.device_build_tags, Build.TAGS);
        setRow(R.id.fingerprintRow, R.string.device_fingerprint_label, Build.FINGERPRINT);
    }

    private void setRow(int rowId, int labelId, String value) {
        android.view.View row = findViewById(rowId);
        ((TextView) row.findViewById(R.id.fieldLabel)).setText(labelId);
        ((TextView) row.findViewById(R.id.fieldValue)).setText(value(value, "Unavailable"));
    }

    private static String value(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value;
    }
}
