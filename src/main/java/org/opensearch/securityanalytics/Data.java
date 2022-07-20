/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics;

public class Data {


    public boolean  boolData;
    public  String message;
    public  int intData;
    public  Float floatData;
    public Data(boolean bData,String message,int intData ,Float fData){
        this.boolData= bData;
        this.message = message;
        this.floatData = fData;

    }

    public boolean  getBoolData() {
        return boolData;
    }

    public void setBoolData(boolean boolData) {
        this.boolData = boolData;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getIntData() {
        return intData;
    }

    public void setIntData(int intData) {
        this.intData = intData;
    }

    public Float getFloatData() {
        return floatData;
    }

    public void setFloatData(Float floatData) {
        this.floatData = floatData;
    }

    public Data getData() {
        return getData();
    }

    public void setData(boolean data) {
        this.boolData = data;
    }

// Data data = new Data();
}
