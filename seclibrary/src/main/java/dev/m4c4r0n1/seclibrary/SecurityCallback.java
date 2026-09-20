package dev.m4c4r0n1.seclibrary;


public interface SecurityCallback {


    void onStep(String step);


    void onResult(RiskResult result);


}