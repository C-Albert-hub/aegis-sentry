package dev.m4c4r0n1.seclibrary;

import android.content.Context;

import java.util.List;

interface Detector {
    String name();

    List<Evidence> detect(Context context) throws Exception;
}
