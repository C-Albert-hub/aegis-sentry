package dev.m4c4r0n1.seclibrary;


public class RiskItem {


    private final String name;

    private final boolean detected;



    public RiskItem(
            String name,
            boolean detected
    ){

        this.name = name;
        this.detected = detected;

    }



    public String getName(){

        return name;

    }



    public boolean isDetected(){

        return detected;

    }

}