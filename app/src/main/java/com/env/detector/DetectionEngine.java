package com.env.detector;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
public class DetectionEngine {
    private final Context ctx;
    public DetectionEngine(Context ctx) { this.ctx = ctx; }
    public List<DetectionCategory> runAll() {
        List<DetectionCategory> r = new ArrayList<>();
        r.add(detectRoot()); r.add(detectBootloader()); r.add(detectMagisk()); r.add(detectXposed());
        r.add(detectHook()); r.add(detectMount()); r.add(detectSELinux()); r.add(detectProps());
        r.add(detectKernel()); r.add(detectApps()); r.add(detectEmulator()); r.add(detectTEE());
        r.add(detectAbnormalEnv()); r.add(deviceInfo()); return r;
    }
    private DetectionCategory detectRoot() {
        List<DetectionItem> items = new ArrayList<>();
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/xbin/su", "/data/adb/su"};
        boolean found = false; StringBuilder sb = new StringBuilder();
        for (String p : paths) { if (new File(p).exists()) { found = true; sb.append(p).append("\n"); } }
        items.add(new DetectionItem("SU Binary", found ? "Found" : "Not found", found, found ? sb.toString() : "No su"));
        String tags = Build.TAGS; boolean tk = tags != null && tags.contains("test-keys");
        items.add(new DetectionItem("Build Tags", tags != null ? tags : "null", tk, "test-keys=modified"));
        return new DetectionCategory("Root Detection", items);
    }
    private DetectionCategory detectBootloader() {
        List<DetectionItem> items = new ArrayList<>();
        String locked = getProp("ro.boot.flash.locked"); boolean ul = !"1".equals(locked);
        items.add(new DetectionItem("Bootloader", ul ? "Unlocked" : "Locked", ul, "flash.locked=" + locked));
        String vb = getProp("ro.boot.verifiedbootstate"); boolean ab = vb != null && !"green".equalsIgnoreCase(vb);
        items.add(new DetectionItem("Verified Boot", vb != null ? vb : "Unknown", ab, "should be green"));
        return new DetectionCategory("Bootloader Detection", items);
    }
    private DetectionCategory detectMagisk() {
        List<DetectionItem> items = new ArrayList<>();
        String[] paths = {"/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/modules", "/cache/magisk.log"};
        for (String p : paths) { if (new File(p).exists()) { items.add(new DetectionItem("Path:" + p, "Exists", true, "")); } }
        String[] pkgs = {"com.topjohnwu.magisk", "io.github.huskydg.magisk"};
        for (String pkg : pkgs) { if (isInstalled(pkg)) items.add(new DetectionItem("Pkg:" + pkg, "Installed", true, "")); }
        if (items.isEmpty()) items.add(new DetectionItem("Magisk", "Not detected", false, ""));
        return new DetectionCategory("Magisk Detection", items);
    }
    private DetectionCategory detectXposed() {
        List<DetectionItem> items = new ArrayList<>();
        String[] pkgs = {"de.robv.android.xposed.installer", "org.lsposed.manager"};
        boolean f = false;
        for (String pkg : pkgs) { if (isInstalled(pkg)) { f = true; items.add(new DetectionItem("Pkg:" + pkg, "Installed", true, "")); } }
        if (!f) items.add(new DetectionItem("Xposed", "Not detected", false, ""));
        return new DetectionCategory("Xposed Detection", items);
    }
    private DetectionCategory detectHook() {
        List<DetectionItem> items = new ArrayList<>();
        String maps = checkMaps(new String[]{"frida", "substrate", "cydia"});
        boolean h = !maps.isEmpty();
        items.add(new DetectionItem("Hook", h ? "Found" : "Not detected", h, h ? maps : ""));
        return new DetectionCategory("Hook Detection", items);
    }
    private DetectionCategory detectMount() {
        List<DetectionItem> items = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/mounts")); String line; boolean s = false;
            while ((line = br.readLine()) != null) {
                if (line.contains("magisk") || line.contains("tmpfs /system")) {
                    s = true; items.add(new DetectionItem("Mount", line.substring(0, Math.min(50, line.length())), true, line));
                }
            }
            br.close();
            if (!s) items.add(new DetectionItem("Mounts", "Normal", false, ""));
        } catch (Exception e) { items.add(new DetectionItem("Mounts", "Error", false, "")); }
        return new DetectionCategory("Mount Detection", items);
    }
    private DetectionCategory detectSELinux() {
        List<DetectionItem> items = new ArrayList<>(); String mode = "Unknown";
        try { Process p = Runtime.getRuntime().exec("getenforce"); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); mode = br.readLine(); br.close(); } catch (Exception e) {}
       private DetectionCategory detectProps() {
        List<DetectionItem> items = new ArrayList<>();
        String dbg = getProp("ro.debuggable"); boolean d = "1".equals(dbg);
        items.add(new DetectionItem("ro.debuggable", dbg, d, d ? "Debug on" : "OK"));
        String sec = getProp("ro.secure"); boolean ns = !"1".equals(sec);
        items.add(new DetectionItem("ro.secure", sec, ns, ns ? "Not secure" : "OK"));
        return new DetectionCategory("System Props", items);
    }
    private DetectionCategory detectKernel() {
        List<DetectionItem> items = new ArrayList<>(); String ver = "Unknown";
        try { BufferedReader br = new BufferedReader(new FileReader("/proc/version")); ver = br.readLine(); br.close(); } catch (Exception e) {}
        boolean custom = ver.toLowerCase().contains("custom") || ver.toLowerCase().contains("lineage");
        items.add(new DetectionItem("Kernel", ver.length() > 60 ? ver.substring(0, 60) + "..." : ver, custom, ver));
        return new DetectionCategory("Kernel Detection", items);
    }
    private DetectionCategory detectApps() {
        List<DetectionItem> items = new ArrayList<>();
        String[][] apps = {{"com.termux","Termux"},{"eu.chainfire.supersu","SuperSU"},{"com.noshufou.android.su","Superuser"}};
        boolean found = false;
        for (String[] a : apps) { if (isInstalled(a[0])) { found = true; items.add(new DetectionItem(a[1], "Installed", true, a[0])); } }
        if (!found) items.add(new DetectionItem("Risk Apps", "None", false, ""));
        return new DetectionCategory("App Detection", items);
    }
    private DetectionCategory detectEmulator() {
        List<DetectionItem> items = new ArrayList<>();
        boolean emu = Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("Emulator") || Build.HARDWARE.contains("goldfish") || Build.PRODUCT.contains("sdk");
        items.add(new DetectionItem("Emulator", emu ? "Detected" : "Not detected", emu, "Model:" + Build.MODEL));
        return new DetectionCategory("Emulator Detection", items);
    }
    private DetectionCategory detectTEE() {
        List<DetectionItem> items = new ArrayList<>();
        boolean t = new File("/dev/trusty-ipc-dev0").exists() || new File("/dev/qseecom").exists();
        items.add(new DetectionItem("TEE", t ? "Available" : "Not found", !t, ""));
        return new DetectionCategory("TEE Detection", items);
    }
    private DetectionCategory detectAbnormalEnv() {
        List<DetectionItem> items = new ArrayList<>();
        boolean proxy = System.getProperty("http.proxyHost") != null;
        items.add(new DetectionItem("HTTP Proxy", proxy ? "Set" : "Not set", proxy, ""));
        return new DetectionCategory("Abnormal Env", items);
    }
    private DetectionCategory deviceInfo() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(new DetectionItem("Brand", Build.BRAND, false, ""));
        items.add(new DetectionItem("Model", Build.MODEL, false, ""));
        items.add(new DetectionItem("Android", Build.VERSION.RELEASE, false, "SDK " + Build.VERSION.SDK_INT));
        items.add(new DetectionItem("ABI", Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "Unknown", false, ""));
        return new DetectionCategory("Device Info", items);
    }
    private String getProp(String name) {
        try { Process p = Runtime.getRuntime().exec(new String[]{"getprop", name});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String v = br.readLine(); br.close(); return v != null && !v.isEmpty() ? v : null; } catch (Exception e) { return null; }
    }
    private boolean isInstalled(String pkg) {
        try { ctx.getPackageManager().getPackageInfo(pkg, 0); return true; } catch (Exception e) { return false; }
    }
    private String checkMaps(String[] kws) {
        StringBuilder sb = new StringBuilder();
        try { BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps")); String line;
            while ((line = br.readLine()) != null) { for (String k : kws) { if (line.toLowerCase().contains(k)) { sb.append(line).append("\n"); break; } } } br.close(); } catch (Exception e) {}
        return sb.toString();
    }
}
