package dev.m4c4r0n1.seclibrary;

import java.util.ArrayList;
import java.util.List;

public class RiskResult {

    private final List<RiskItem> items =
            new ArrayList<>();

    public void addItem(
            RiskItem item
    ) {

        items.add(item);

    }

    public List<RiskItem> getItems() {

        return items;

    }

    public boolean hasRisk() {

        for (RiskItem item : items) {

            if (item.isDetected()) {

                return true;

            }

        }

        return false;

    }

    public int getScore(){

        int score = 100;


        for(RiskItem item: items){

            if(item.isDetected()){

                score -= 30;

            }

        }


        return Math.max(score,0);

    }


}