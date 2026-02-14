package com.env.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DetectionEngine {
    private final Context ctx;

    public DetectionEngine(Context ctx) { this.ctx = ctx; }

    public List<DetectionCategory> runAll() {
        List<DetectionCategory> r = new ArrayList<>();
        r.add(detectRoot());
        r.add(detectBootloader());
        r.add(detectMagisk());
        r.add(detectXposed());
        r.add(detectHook());
        r.add(detectMount());
        r.add(detectSELinux());
        r.add(detectProps());
        r.add(detectKernel());
        r.add(detectApps());
        r.add(detectEmulator());
        r.add(detectTEE());
        r.add(detectAbnormalEnv());
        r.add(deviceInfo());
        return r;
    }

    private DetectionCategory detectRoot() {
        List<DetectionItem> items = new ArrayList<>();
        String[] paths = {"/system/bin/su","/system/xbin/su","/sbin/su","/data/local/xbin/su","/data/local/bin/su","/data/adb/su"};
        boolean found = false;
        StringBuilder sb = new StringBuilder();
        for (String p : paths) {
            if (new File(p).exists()) { found = true; sb.append(p).append("\n"); }
        }
        items.add(new DetectionItem("SU 二进制", found ? "发现" : "未发现", found, found ? "路径:\n" + sb : "未发现 su"));

        boolean suExec = false;
        try { Runtime.getRuntime().exec("su"); suExec = true; } catch (Exception e) {}
        items.add(new DetectionItem("SU 可执行", suExec ? "是" : "否", suExec, "尝试执行 su 命令"));

        String tags = Build.TAGS;
        boolean testKeys = tags != null && tags.contains("test-keys");
        items.add(new DetectionItem("Build Tags", tags != null ? tags : "null", testKeys, "test-keys 表示系统被修改"));

        String[] dirs = {"/data/adb/magisk","/data/adb/modules","/data/adb/ksu","/data/adb/ap","/system/app/Superuser.apk"};
        boolean dirFound = false;
        StringBuilder ds = new StringBuilder();
        for (String d : dirs) { if (new File(d).exists()) { dirFound = true; ds.append(d).append("\n"); } }
        items.add(new DetectionItem("Root 目录", dirFound ? "发现" : "未发现", dirFound, dirFound ? "目录:\n" + ds : "未发现"));

        boolean twrp = new File("/sdcard/TWRP").exists();
        items.add(new DetectionItem("Recovery 残留", twrp ? "发现" : "未发现", twrp, "检查 /sdcard/TWRP"));

        return new DetectionCategory("Root 检测", items);
    }

    private DetectionCategory detectBootloader() {
        List<DetectionItem> items = new ArrayList<>();
        String locked = getProp("ro.boot.flash.locked");
        boolean unlocked = !"1".equals(locked);
        items.add(new DetectionItem("Bootloader", unlocked ? "已解锁" : "已锁定", unlocked, "ro.boot.flash.locked=" + locked));

        String vb = getProp("ro.boot.verifiedbootstate");
        boolean abnVb = vb != null && !"green".equalsIgnoreCase(vb);
        items.add(new DetectionItem("Verified Boot", vb != null ? vb : "未知", abnVb, "正常值应为 green"));

        String digest = getProp("ro.boot.vbmeta.digest");
        boolean zero = digest != null && digest.matches("^0+$");
        items.add(new DetectionItem("VBMeta Digest", digest != null ? digest.substring(0, Math.min(16, digest.length())) + "..." : "未知", zero, zero ? "全零表示被修改" : "正常"));

        return new DetectionCategory("Bootloader 检测", items);
    }

    private DetectionCategory detectMagisk() {
        List<DetectionItem> items = new ArrayList<>();
        String[] paths = {"/data/adb/magisk","/data/adb/magisk.db","/data/adb/modules","/cache/magisk.log"};
        boolean found = false;
        for (String p : paths) {
            if (new File(p).exists()) { found = true; items.add(new DetectionItem("路径: " + p, "存在", true, "")); }
        }
        String[] pkgs = {"com.topjohnwu.magisk","io.github.huskydg.magisk","io.github.vvb2060.magisk"};
        for (String pkg : pkgs) {
            if (isInstalled(pkg)) items.add(new DetectionItem("包: " + pkg, "已安装", true, ""));
        }
        String maps = checkMaps(new String[]{"magisk","zygisk"});
        boolean mapsHit = !maps.isEmpty();
        items.add(new DetectionItem("内存映射", mapsHit ? "发现" : "正常", mapsHit, mapsHit ? maps : "正常"));
        if (!found && !mapsHit && items.size() == 1) items.add(0, new DetectionItem("Magisk", "未检测到", false, ""));
        return new DetectionCategory("Magisk 检测", items);
    }

    private DetectionCategory detectXposed() {
        List<DetectionItem> items = new ArrayList<>();
        String[] pkgs = {"de.robv.android.xposed.installer","org.lsposed.manager","io.github.lsposed.manager","com.solohsu.android.edxp.manager"};
        boolean pkgFound = false;
        for (String pkg : pkgs) {
            if (isInstalled(pkg)) { pkgFound = true; items.add