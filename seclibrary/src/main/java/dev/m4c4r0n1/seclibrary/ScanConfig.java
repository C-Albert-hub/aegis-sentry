package dev.m4c4r0n1.seclibrary;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

public final class ScanConfig {
    public enum Module {
        ENVIRONMENT,
        ANTI_DEBUG,
        ANTI_INJECTION,
        APP_INTEGRITY,
        NATIVE_INTEGRITY
    }

    private final Set<Module> modules;
    private final String expectedCertificateSha256;
    private final String expectedApkSha256;
    private final String expectedDexSha256;
    private final String expectedNativeLibrarySha256;

    private ScanConfig(Builder builder) {
        modules = Collections.unmodifiableSet(EnumSet.copyOf(builder.modules));
        expectedCertificateSha256 = normalize(builder.expectedCertificateSha256);
        expectedApkSha256 = normalize(builder.expectedApkSha256);
        expectedDexSha256 = normalize(builder.expectedDexSha256);
        expectedNativeLibrarySha256 = normalize(builder.expectedNativeLibrarySha256);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ScanConfig defaults() {
        return builder().build();
    }

    public boolean includes(Module module) {
        return modules.contains(module);
    }

    public Set<Module> getModules() {
        return modules;
    }

    public String getExpectedCertificateSha256() {
        return expectedCertificateSha256;
    }

    public String getExpectedApkSha256() {
        return expectedApkSha256;
    }

    public String getExpectedDexSha256() {
        return expectedDexSha256;
    }

    public String getExpectedNativeLibrarySha256() {
        return expectedNativeLibrarySha256;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.replace(":", "").trim().toLowerCase(Locale.US);
    }

    public static final class Builder {
        private final EnumSet<Module> modules = EnumSet.allOf(Module.class);
        private String expectedCertificateSha256;
        private String expectedApkSha256;
        private String expectedDexSha256;
        private String expectedNativeLibrarySha256;

        public Builder enable(Module module) {
            modules.add(module);
            return this;
        }

        public Builder disable(Module module) {
            modules.remove(module);
            return this;
        }

        public Builder expectedCertificateSha256(String value) {
            expectedCertificateSha256 = value;
            return this;
        }

        public Builder expectedApkSha256(String value) {
            expectedApkSha256 = value;
            return this;
        }

        public Builder expectedDexSha256(String value) {
            expectedDexSha256 = value;
            return this;
        }

        public Builder expectedNativeLibrarySha256(String value) {
            expectedNativeLibrarySha256 = value;
            return this;
        }

        public ScanConfig build() {
            return new ScanConfig(this);
        }
    }
}
