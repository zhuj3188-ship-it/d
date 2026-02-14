package com.env.detector;

public class DetectionItem {
    public String name;
    public String value;
    public boolean isRisk;
    public String detail;

    public DetectionItem(String name, String value, boolean isRisk, String detail) {
        this.name = name;
        this.value = value;
        this.isRisk = isRisk;
        this.detail = detail;
    }
}
