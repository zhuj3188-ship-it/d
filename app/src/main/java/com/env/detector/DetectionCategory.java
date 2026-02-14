package com.env.detector;

import java.util.List;

public class DetectionCategory {
    public String name;
    public List<DetectionItem> items;
    public boolean expanded = false;

    public DetectionCategory(String name, List<DetectionItem> items) {
        this.name = name;
        this.items = items;
    }

    public boolean hasRisk() {
        for (DetectionItem i : items) { if (i.isRisk) return true; }
        return false;
    }

    public int riskCount() {
        int c = 0;
        for (DetectionItem i : items) { if (i.isRisk) c++; }
        return c;
    }
}
