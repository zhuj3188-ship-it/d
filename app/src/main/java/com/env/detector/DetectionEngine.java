package com.env.detector;
import android.content.Context;
import android.os.Build;
import java.io.*;
import java.util.*;
public class DetectionEngine {
private final Context ctx;
public DetectionEngine(Context c){ctx=c;}
public List<DetectionCategory> runAll(){
List<DetectionCategory> r=new ArrayList<>();
r.add(detectRoot());r.add(detectBootloader());r.add(detectMagisk());r.add(detectXposed());
r.add(detectHook());r.add(detectMount());r.add(detectSELinux());r.add(detectProps());
r.add(detectKernel());r.add(detectApps());r.add(detectEmulator());r.add(detectTEE());
r.add(detectAbnormalEnv());r.add(deviceInfo());return r;}
private DetectionCategory detectRoot(){
List<DetectionItem> t=new ArrayList<>();
String[] p={"/system/bin/su","/system/xbin/su","/sbin/su","/data/local/xbin/su","/data/adb/su"};
boolean f=false;StringBuilder s=new StringBuilder();
for(String x:p){if(new File(x).exists()){f=true;s.append(x).append("\n");}}
t.add(new DetectionItem("SU Binary",f?"Found":"Not found",f,f?s.toString():"No su"));
String tg=Build.TAGS;boolean tk=tg!=null&&tg.contains("test-keys");
t.add(new DetectionItem("Build Tags",tg!=null?tg:"null",tk,""));
return new DetectionCategory("Root Detection",t);}
private DetectionCategory detectBootloader(){
List<DetectionItem> t=new ArrayList<>();
String l=gp("ro.boot.flash.locked");boolean u=!"1".equals(l);
t.add(new DetectionItem("Bootloader",u?"Unlocked":"Locked",u,"locked="+l));
String v=gp("ro.boot.verifiedbootstate");boolean a=v!=null&&!"green".equalsIgnoreCase(v);
t.add(new DetectionItem("Verified Boot",v!=null?v:"Unknown",a,""));
return new DetectionCategory("Bootloader Detection",t);}
private DetectionCategory detectMagisk(){
List<DetectionItem> t=new ArrayList<>();
String[] p={"/data/adb/magisk","/data/adb/magisk.db","/data/adb/modules"};
for(String x:p){if(new File(x).exists())t.add(new DetectionItem("Path:"+x,"Exists",true,""));}
String[] k={"com.topjohnwu.magisk","io.github.huskydg.magisk"};
for(String x:k){if(ii(x))t.add(new DetectionItem("Pkg:"+x,"Installed",true,""));}
if(t.isEmpty())t.add(new DetectionItem("Magisk","Not detected",false,""));
return new DetectionCategory("Magisk Detection",t);}
private DetectionCategory detectXposed(){
List<DetectionItem> t=new ArrayList<>();
String[] k={"de.robv.android.xposed.installer","org.lsposed.manager"};boolean f=false;
for(String x:k){if(ii(x)){f=true;t.add(new DetectionItem("Pkg:"+x,"Installed",true,""));}}
if(!f)t.add(new DetectionItem("Xposed","Not detected",false,""));
return new DetectionCategory("Xposed Detection",t);}
private DetectionCategory detectHook(){
List<DetectionItem> t=new ArrayList<>();
String m=cm(new String[]{"frida","substrate","cydia"});boolean h=!m.isEmpty();
t.add(new DetectionItem("Hook",h?"Found":"Clean",h,h?m:""));
return new DetectionCategory("Hook Detection",t);}
private DetectionCategory detectMount(){
List<DetectionItem> t=new ArrayList<>();
try{BufferedReader b=new BufferedReader(new FileReader("/proc/mounts"));String l;boolean s=false;
while((l=b.readLine())!=null){if(l.contains("magisk")||l.contains("tmpfs /system")){s=true;
t.add(new DetectionItem("Mount",l.substring(0,Math.min(50,l.length())),true,l));}}b.close();
if(!s)t.add(new DetectionItem("Mounts","Normal",false,""));
}catch(Exception e){t.add(new DetectionItem("Mounts","Error",false,""));}
return new DetectionCategory("Mount Detection",t);}
private DetectionCategory detectSELinux(){
List<DetectionItem> t=new ArrayList<>();String m="Unknown";
try{Process p=Runtime.getRuntime().exec("getenforce");BufferedReader b=new BufferedReader(new InputStreamReader(p.getInputStream()));m=b.readLine();b.close();}catch(Exception e){}
boolean p="Permissive".equalsIgnoreCase(m);
t.add(new DetectionItem("SELinux",m,p,p?"Should be Enforcing":"OK"));
return new DetectionCategory("SELinux Detection",t);}
private DetectionCategory detectProps(){
List<DetectionItem> t=new ArrayList<>();
String d=gp("ro.debuggable");boolean db="1".equals(d);
t.add(new DetectionItem("ro.debuggable",d,db,db?"Debug on":"OK"));
String s=gp("ro.secure");boolean ns=!"1".equals(s);
t.add(new DetectionItem("ro.secure",s,ns,ns?"Not secure":"OK"));
return new DetectionCategory("System Props",t);}
private DetectionCategory detectKernel(){
List<DetectionItem> t=new ArrayList<>();String v="Unknown";
try{BufferedReader b=new BufferedReader(new FileReader("/proc/version"));v=b.readLine();b.close();}catch(Exception e){}
boolean c=v.toLowerCase().contains("custom")||v.toLowerCase().contains("lineage");
t.add(new DetectionItem("Kernel",v.length()>60?v.substring(0,60)+"...":v,c,v));
return new DetectionCategory("Kernel Detection",t);}
private DetectionCategory detectApps(){
List<DetectionItem> t=new ArrayList<>();
String[][] a={{"com.termux","Termux"},{"eu.chainfire.supersu","SuperSU"},{"com.noshufou.android.su","Superuser"}};
boolean f=false;for(String[] x:a){if(ii(x[0])){f=true;t.add(new DetectionItem(x[1],"Installed",true,x[0]));}}
if(!f)t.add(new DetectionItem("Risk Apps","None",false,""));return new DetectionCategory("App Detection",t);}
private DetectionCategory detectEmulator(){
List<DetectionItem> t=new ArrayList<>();
boolean e=Build.FINGERPRINT.contains("generic")||Build.MODEL.contains("Emulator")||Build.HARDWARE.contains("goldfish")||Build.PRODUCT.contains("sdk");
t.add(new DetectionItem("Emulator",e?"Detected":"No",e,"Model:"+Build.MODEL));
return new DetectionCategory("Emulator Detection",t);}
private DetectionCategory detectTEE(){
List<DetectionItem> t=new ArrayList<>();
boolean e=new File("/dev/trusty-ipc-dev0").exists()||new File("/dev/qseecom").exists();
t.add(new DetectionItem("TEE",e?"Available":"Not found",!e,""));
return new DetectionCategory("TEE Detection",t);}
private DetectionCategory detectAbnormalEnv(){
List<DetectionItem> t=new ArrayList<>();
boolean p=System.getProperty("http.proxyHost")!=null;
t.add(new DetectionItem("HTTP Proxy",p?"Set":"Not set",p,""));
return new DetectionCategory("Abnormal Env",t);}
private DetectionCategory deviceInfo(){
List<DetectionItem> t=new ArrayList<>();
t.add(new DetectionItem("Brand",Build.BRAND,false,""));
t.add(new DetectionItem("Model",Build.MODEL,false,""));
t.add(new DetectionItem("Android",Build.VERSION.RELEASE,false,"SDK "+Build.VERSION.SDK_INT));
t.add(new DetectionItem("ABI",Build.SUPPORTED_ABIS.length>0?Build.SUPPORTED_ABIS[0]:"Unknown",false,""));
return new DetectionCategory("Device Info",t);}
private String gp(String n){
try{Process p=Runtime.getRuntime().exec(new String[]{"getprop",n});
BufferedReader b=new BufferedReader(new InputStreamReader(p.getInputStream()));
String v=b.readLine();b.close();return v!=null&&!v.isEmpty()?v:null;}catch(Exception e){return null;}}
private boolean ii(String p){
try{ctx.getPackageManager().getPackageInfo(p,0);return true;}catch(Exception e){return false;}}
private String cm(String[] k){
StringBuilder s=new StringBuilder();
try{BufferedReader b=new BufferedReader(new FileReader("/proc/self/maps"));String l;
while((l=b.readLine())!=null){for(String x:k){if(l.toLowerCase().contains(x)){s.append(l).append("\n");break;}}}b.close();}catch(Exception e){}
return s.toString();}
}
