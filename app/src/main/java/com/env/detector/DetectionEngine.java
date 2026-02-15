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
public DetectionEngine(Context ctx){this.ctx=ctx;}
public List<DetectionCategory> runAll(){
List<DetectionCategory> r=new ArrayList<>();
r.add(detectRoot());r.add(detectBootloader());r.add(detectMagisk());r.add(detectXposed());
r.add(detectHook());r.add(detectMount());r.add(detectSELinux());r.add(detectProps());
r.add(detectKernel());r.add(detectApps());r.add(detectEmulator());r.add(detectTEE());
r.add(detectAbnormalEnv());r.add(deviceInfo());return r;}
private DetectionCategory detectRoot(){
List<DetectionItem> items=new ArrayList<>();
String[] paths={"/system/bin/su","/system/xbin/su","/sbin/su","/data/local/xbin/su","/data/adb/su"};
boolean found=false;StringBuilder sb=new StringBuilder();
for(String p:paths){if(new File(p).exists()){found=true;sb.append(p).append("\n");}}
items.add(new DetectionItem("SU Binary",found?"Found":"Not found",found,found?sb.toString():"No su"));
String tags=Build.TAGS;boolean tk=tags!=null&&tags.contains("test-keys");
items.add(new DetectionItem("Build Tags",tags!=null?tags:"null",tk,"test-keys=modified"));
return new DetectionCategory("Root Detection",items);}
private DetectionCategory detectBootloader(){
List<DetectionItem> items=new ArrayList<>();
String locked=getProp("ro.boot.flash.locked");boolean ul=!"1".equals(locked);
items.add(new DetectionItem("Bootloader",ul?"Unlocked":"Locked",ul,"flash.locked="+locked));
String vb=getProp("ro.boot.verifiedbootstate");boolean ab=vb!=null&&!"green".equalsIgnoreCase(vb);
items.add(new DetectionItem("Verified Boot",vb!=null?vb:"Unknown",ab,"should be green"));
return new DetectionCategory("Bootloader Detection",items);}
private DetectionCategory detectMagisk(){
List<DetectionItem> items=new ArrayList<>();
String[] paths={"/data/adb/magisk","/data/adb/magisk.db","/data/adb/modules","/cache/magisk.log"};
boolean f=false;for(String p:paths){if(new File(p).exists()){f=true;items.add(new DetectionItem("Path:"+p,"Exists",true,""));}}
String[] pkgs={"com.topjohnwu.magisk","io.github.huskydg.magisk"};
for(String pkg:pkgs){if(isInstalled(pkg))items.add(new DetectionItem("Pkg:"+pkg,"Installed",true,""));}
if(items.isEmpty())items.add(new DetectionItem("Magisk","Not detected",false,""));
return new DetectionCategory("Magisk Detection",items);}
private DetectionCategory detectXposed(){
List<DetectionItem> items=new ArrayList<>();
String[] pkgs={"de.robv.android.xposed.installer","org.lsposed.manager"};boolean f=false;
for(String pkg:pkgs){if(isInstalled(pkg)){f=true;items.add(new DetectionItem("Pkg:"+pkg,"Installed",true,""));}}
if(!f)items.add(new DetectionItem("Xposed","Not detected",false,""));
return new DetectionCategory("Xposed Detection",items);}
private DetectionCategory detectHook(){
List<DetectionItem> items=new ArrayList<>();
String maps=checkMaps(new String[]{"frida","substrate","cydia"});boolean h=!maps.isEmpty();
items.add(new DetectionItem("Hook",h?"Found":"Not detected",h,h?maps:""));
return new DetectionCategory("Hook Detection",items);}
private DetectionCategory detectMount(){
List<DetectionItem> items=new ArrayList<>();
try{BufferedReader br=new BufferedReader(new FileReader("/proc/mounts"));String line;boolean s=false;
while((line=br.readLine())!=null){if(line.contains("magisk")||line.contains("tmpfs /system")){s=true;
items.add(new DetectionItem("Mount",line.substring(0,Math.min(50,line.length())),true,line));}}br.close();
if(!s)items.add(new DetectionItem("Mounts","Normal",false,""));
}catch(Exception e){items.add(new DetectionItem("Mounts","Error",false,""));}
return new DetectionCategory("Mount Detection",items);}
private DetectionCategory detectSELinux(){
List<DetectionItem> items=new ArrayList<>();String mode="Unknown";
try{Process p=Runtime.getRuntime().exec("getenforce");BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));mode=br.readLine();br.close();}catch(Exception e){}
boolean perm="Permissive".equalsIgnoreCase(mode);
items.add(new DetectionItem("SELinux",mode,perm,perm?"Should be Enforcing":"OK"));
return new DetectionCategory("SELinux Detection",items);}
private DetectionCategory detectProps(){
List<DetectionItem> items=new ArrayList<>();
String dbg=getProp("ro.debuggable");boolean d="1".equals(dbg);
items.add(new DetectionItem("ro.debuggable",dbg,d,d?"Debug on":"OK"));
String sec=getProp("ro.secure");boolean ns=!"1".equals(sec);
items.add(new DetectionItem("ro.secure",sec,ns,ns?"Not secure":"OK"));
return new DetectionCategory("System Props",items);}
private DetectionCategory detectKernel(){
List<DetectionItem> items=new ArrayList<>();String ver="Unknown";
try{BufferedReader br=new BufferedReader(new FileReader("/proc/version"));ver=br.readLi
