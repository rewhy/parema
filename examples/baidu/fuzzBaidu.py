#!/usr/bin/env python
# -*- coding: utf-8 -*- 

# Automaticlly run apps protected by Baidu packer


import os
import re
import sys
import time
import thread
import threading
import Queue
import signal
import subprocess
import ftplib
import hashlib
import commands
import xml.dom.minidom
import axmlparserpy.axmlprinter as axmlprinter

from subprocess import call, Popen, PIPE
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis  import analysis


#mu = threading.Lock()

def key(device, code):
    device.press(code, MonkeyDevice.DOWN_AND_UP)

def log(file, line):
    print "%s" % line

def get_manifest_apktool(filename):
    print "get_manifest_apktool"
    os.system("apktool d %s -f -o tmppp" % filename)
    try:
        dom = xml.dom.minidom.parse("tmppp/AndroidManifest.xml")
    except:
        print "parse XML error"
        return None
    return dom

def get_manifest_unzip(filename):
    print "get_manifest_unzip"
    os.system("rm -rf tmppp")
    os.system("unzip %s -d tmppp" % filename)
    try: 
        ap = axmlprinter.AXMLPrinter(open('tmppp/AndroidManifest.xml', 'rb').read())
    except:
        print "parse XML error"
        return None
    dom = xml.dom.minidom.parseString(ap.getBuff())
    return dom


class ApkInfo(object):
    def __init__(self, filename):
        self.filename = filename
        self.packageNames = []
        self.activities = {}
        self.services = {}
        self.recvsactions = {}
        self.mainActivity = None
        self.mainActivity = None
        self.mainService  = None
        self.dom = None
        self.isValid = False
        try:
            self.apk = apk.APK(filename)
            self.dvm = dvm.DalvikVMFormat(self.apk)
            self.isValid = self.apk.is_valid_APK()
        except:
            print "parse apk error"
            self.isValid = False
        
        res = get_manifest_apktool(filename) 
        if not res == None:
            self.dom = res
            self.process_manifest()
            return
        res = get_manifest_unzip(filename)
        if not res == None:
            self.dom = res
            self.process_manifest()
            return
        
        print "Cannot get manifest file"


    def get_main_activity(self):
        #return "v.v.v.MainActivity"
        return self.mainActivity
    def get_main_service(self):
	return self.mainService
    def get_activities(self):
        return self.apk.get_activities()
    def get_activities_with_actions(self):
        seractions = {}
        for key in self.activities.keys():
            seractions[key] = self.activities[key]["actions"]
        return seractions
    def get_package(self):
        #return "com.vnuhqwdqdqd.trarenren5"
        return self.packageNames[0]
    def get_receivers(self):
        return self.apk.get_receivers()
    def get_receivers_with_actions(self):
        return self.recvsactions
    def get_libraries(self):
        return self.apk.get_libraries()
    def get_services(self):
        return self.services
    def get_activities(self):
        return self.activities
    def get_services_with_actions(self):
        seractions = {}
        for key in self.services.keys():
            seractions[key] = self.services[key]["actions"]
        return seractions
    def is_valid(self):
        return self.isValid
    def get_md5(self):
        return hashlib.md5(open(self.filename, 'rb').read()).hexdigest()
    def get_dvm(self):
        return self.dvm
    def get_apk(self):
        return self.apk


    def process_manifest(self):
        print "parse manifest file"
        dom = self.dom
        for item in dom.getElementsByTagName('manifest'):
            self.packageNames.append( str( item.getAttribute("package") ) )
        for item in dom.getElementsByTagName('receiver'):
            for child in item.getElementsByTagName('action'):
                self.recvsactions[str(item.getAttribute("android:name"))] = (str(child.getAttribute("android:name")))

        for item in dom.getElementsByTagName('activity'):
            activity = str(item.getAttribute("android:name"))
            self.activities[activity] = {}
            self.activities[activity]["actions"] = []
            for child in item.getElementsByTagName('action'):
                action = str(child.getAttribute("android:name"))
                self.activities[activity]["actions"].append(str(child.getAttribute("android:name")))
                if action == "android.intent.action.MAIN":
                    self.mainActivity = activity
        

        for item in dom.getElementsByTagName('service'):
            service = str(item.getAttribute("android:name"))
            self.services[service] = {}
            self.services[service]["actions"] = []
            for child in item.getElementsByTagName('action'):
                action = str(child.getAttribute("android:name"))
                self.services[service]["actions"].append(action)
                if action == "android.intent.action.MAIN":
                    self.mainService = service
        print "ma:%s ms:%s" % (self.mainActivity, self.mainService)
        os.system("rm -rf tmppp")
        self.isValid = True

    def genScriptFuzzer(self):
        s1 = 'fuzzapp.sh'
        mainAct = ''
        for c in self.mainActivity:
            if c == '.':
                mainAct = mainAct + '/'
            else:
                mainAct = mainAct + c
        #mainAct1 = 'com.baidu.protect.StubApplication'
        #mainMth1 = 'getPackageName'
        #mainAct1 = 'com/shell/NativeApplication'
        mainAct1 = 'android/app/Activity'
        mainMth1 = 'performCreate'
        mainShorty1 = 'VL'
        #mainAct1 = 'com/baidu/protect/StubApplication'
        #mainMth1 = 'getPackageName'
        #mainShorty1 = 'L'
        #mainAct1 = 'dalvik/system/VMDebug'
        #mainAct1 = 'android/content/Context'
        #mainMth1 = 'loadClass'
        #mainMth1 = 'restoreHasCurrentPermissionRequest'
        #mainMth1 = 'startMethodTracingDdms'
        #mainMth1 = 'obtainStyledAttributes'
        #mainAct1 = 'com/baidu/protect/A'
        #mainMth1 = 'V'
        #mainShorty1 = 'VILL'
        #mainAct1 = 'com/baidu/protect/StubApplication'
        #mainMth1 = '<init>'
        #mainShorty1 = 'V'

        #mainAct1 = 'com/example/jeremy/empty/MainActivity'
        #mainAct1 = mainAct
        #mainMth1 = 'onCreate'
        #mainShorty1 = 'VLLL'
        #mainAct2 = 'com/example/jeremy/empty/MainActivity'
        #mainMth2 = 'onCreate'
        #mainAct2 = 'android/app/ActivityTransitionState'
        #mainAct2 = mainAct
        #mainMth2 = 'onCreate'
        #mainMth2 = 'readState'
        mainAct2 = mainAct1
        mainMth2 = mainMth1
        #mainAct  = 'com/baidu/protect/A'
        sf = open(s1, 'w')
        sf.write("#!/system/bin/sh\n")
        sf.write("export TMPDIR=/data/local/tmp/tmp\n")
        #sf.write("VGPARAMS=\'-v --trace-signals=yes --log-file=/data/local/tmp/fuzz/frw.log.%p --tool=malton --critical-ins-only=yes --trace-art-method=yes --output-log-info=no\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-symtab=yes --trace-signals=yes --log-file=/data/local/tmp/fuzz/frw.log.%p --tool=none\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-symtab=yes --log-file=/data/local/tmp/fuzz/frw.log.%p --tool=memcheck\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-symtab=yes --log-file=/data/local/tmp/fuzz/frw.log.%p --tool=drd\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-symtab=yes --log-file=/data/local/tmp/fuzz/frw.log.%p --tool=helgrind\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-signals=yes --log-file=/data/local/tmp/fuzz/fuzzer.log.%p --trace-children=yes --main-stacksize=268425456 --tool=deobfuscator " +
        ##sf.write("VGPARAMS=\'-v --trace-children=yes --trace-signals=yes --log-file=/data/local/tmp/fuzz/fuzzer.log.%p --trace-children=yes --main-stacksize=67108864 --tool=deobfuscator " +
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-signals=yes --log-file=/data/local/tmp/fuzz/fuzzer.log.%p --trace-children=yes --valgrind-stacksize=8388608 --tool=deobfuscator " +
        #sf.write("VGPARAMS=\'-v --trace-children=yes --trace-signals=yes --trace-children=yes --main-stacksize=67108864 --tool=deobfuscator " +
        sf.write("VGPARAMS=\'-v --trace-children=yes --trace-signals=yes --log-file=/data/local/tmp/fuzz/fuzzer.log.%p --tool=deobfuscator --time-slow=50 " +
                "--main-activity=L%s; --start-class=L%s; --start-method=%s --start-shorty=%s --stop-class=L%s; --stop-method=%s\'\n" 
                % (mainAct, mainAct1, mainMth1, mainShorty1, mainAct2, mainMth2));
        #sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/fuzz/fuzzer.log.%p --tool=deobfuscator")
        sf.write("exec valgrind $VGPARAMS $*\n")
        #sf.write("exec $*\n")
        sf.close()
        return s1


def startOneActivity(package, activity, deviceID):
    print "Start activity: %s/%s" % (package, activity)
    os.system("adb -s %s shell am start -n %s/%s" % (deviceID, package, activity))

def startActivities(package, activities, deviceID):
    for activity in activities:
        startOneActivity(package, activity, deviceID)
        time.sleep(10)

def startOneService(package, service, deviceID):
    print "Start service: %s/%s" % (package, service)
    os.system("adb -s %s shell am startservice -n %s/%s" % (deviceID, package,service))

def startServices(package, services, deviceID):
    for service in services:
        startOneService(package, service, deviceID)
        time.sleep(5)

def removeApp(package, deviceID):
    print("Try to remove package %s" % package)
    try:
        os.system("adb -s %s uninstall %s" % (deviceID, package))
        os.system("adb -s %s shell rm -rf /data/local/tmp/frw/*" % (deviceID))
    except:
        pass

def installApp(app, deviceID):
    os.system("adb -s %s install %s" % (deviceID, app))

def removeAPK(app, deviceID):
    apkInfo = ApkInfo(app)
    package = apkInfo.get_package()
    removeApp(package, deviceID)

def triggerReceivers(receivers, deviceID):
    actions = []
    for receiver in receivers.keys():
        action = receivers[receiver]
        if action in actions:
            continue
        actions.append(action)
        if not "BOOT" in action:
            print("trigger %s with %s" % (receiver, action))
            os.system("adb -s %s shell am broadcast -a %s" % (deviceID, action))
            time.sleep(5)

def wrapApp(package, script, deviceID):
    path = os.path.join("/data/local", script.split('/')[-1])
    os.system("adb -s %s push %s %s" % (deviceID, script, path))
    os.system("adb -s %s shell chmod 777 /data/local/%s" % (deviceID, script))
    wrapper = "wrap.%s" % package
    if len(wrapper) > 31:
        wrapper = wrapper[:31]
    os.system("adb -s %s shell am force-stop %s" % (deviceID, package))
    print("adb -s %s shell \"setprop %s \\\"logwrapper %s\\\"\"" % (deviceID, wrapper, path))
    os.system("adb -s %s shell \"setprop %s \\\"logwrapper %s\\\"\"" % (deviceID, wrapper, path))
    os.system("adb -s %s shell \"rm -rf /data/local/tmp/fuzz/*\"" % deviceID)
    #os.system("adb -s %s shell \"setprop %s \\\"\\\"\"" % (deviceID, wrapper))

def rmWrapApp(package, deviceID):
    wrapper = "wrap.%s" % package
    if len(wrapper) > 31:
        wrapper = wrapper[:31]
    os.system("adb -s %s shell am force-stop %s" % (deviceID, package))
    os.system("adb -s %s shell \"setprop %s \\\"\\\"\"" % (deviceID, wrapper))


def getUnpackDex(package):
    os.system("adb pull /data/local/tmp/fuzz %s_log_%d" % (package, time.time()))
    return
    os.system("mkdir %s_dex" % package)
    os.system("rm %s_dex" % (package))
    try:
        os.system("mv %s_log/fuzz/*.dex %s_dex/" % (package, package))
    except:
        return
    dixDir = "%s" % (package)
    cmd = "grep -r \"%s\" ./%s_dex/*" % (package, dixDir)
    print cmd
    (status, output) = commands.getstatusoutput(cmd)
    print ""
    if output.strip() == '':
        return
    target = ""
    print output
    for l in output.split('\n'):
        if not l.split('.')[-1] == 'dex':
            continue
        print l
        filepath = l.split()[-2]
        print filepath
        f = filepath.split('/')[-1]
        try:
            p = int(f.split('.')[0].split('-')[-1])
        except:
            continue
        if p > priority:
            priority = p
            target = filepath
            if priority >= 0:
                cmd = "cp %s %s_dex/recovered.dex" % (target, package)
                os.system(cmd)

def getMLogs(package, deviceID):
    os.system("adb -s %s shell am force-stop %s" % (deviceID, package))
    print("adb -s %s pull /data/local/tmp/frw %s_log" % (deviceID, deviceID))
    os.system("adb -s %s pull /data/local/tmp/frw %s_log" % (deviceID, deviceID))

def resolveInput(index):
    return

def runLogcat(deviceID, package):
    global isTerminate
    global applicationStarted
    isTerminate = False
    logFile = None
    #activityDisplayed = 0
    #adb = Popen(["adb", "-s", deviceID, "logcat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    os.system("adb -s %s logcat -c" % deviceID)
    adb = Popen(["adb", "-s", deviceID, "logcat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # ActivityManager: Start proc 6578:com.example.xxshenqi/u0a102 for activity com.example.xxshenqi/.WelcomeActivity
    startLine = r"(.*) ActivityManager: Start proc (\d*):(.*) for activity %s/(.*)" % (package)
    # ActivityManager: Process com.fractalist.MobileOptimizer:remote (pid 24507) has died
    diedLine  = r"(.*) ActivityManager: Process %s \(pid (\d*)\) has died" % package
    # I ActivityManager: Killing 5211:com.example.xxshenqi/u0a157 (adj -100): start timeout
    killLine  = r"(.*) ActivityManager: Killing (\d*):%s/(.*)" % package
    # ActivityManager: Displayed com.example.xxshenqi/.MainActivity
    dispLine  = r"(.*) ActivityManager: Displayed %s/(.*)" % package
    time.sleep(1)
    begTime = time.time()
    curTime = begTime
    proc = None
    #timeout = 30
    duration = 600
    while not isTerminate:
        if True:
            logcatInput = adb.stdout.readline()
            print logcatInput[:-1]
            if not logcatInput:
                print("We have lost the connection with ADB")
                os.kill(adb.pid, signal.SIGTERM)
                os.system("adb kill-server")
                adb = Popen(["adb", "-s", deviceID, "logcat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                #raise Exception("We have lost the connection with ADB")
            startObj = re.search(startLine, logcatInput, re.M|re.I)
            diedObj  = re.search(diedLine, logcatInput, re.M|re.I)
            killObj  = re.search(killLine, logcatInput, re.M|re.I)
            dispObj  = re.search(dispLine, logcatInput, re.M|re.I)
            if startObj:
                proc = startObj.group(2)
                applicationStarted = 1
                begTime = curTime
                log(logFile, "%s Running %s on %s with proc %s" % (time.strftime('%H:%M:%S'), package, deviceID, proc))
            elif dispObj:
                dispActivity = dispObj.group(2)
                log(logFile, "%s Displayed %s/%s" % (time.strftime('%H:%M:%S'), package, dispActivity))
                applicationStarted = 2
                break
            elif diedObj:
                proc = diedObj.group(2)
                applicationStarted = -1
                log(logFile, "%s Died %s %s" % (time.strftime('%H:%M:%S'), package, proc))
                break
            elif killObj:
                proc = killObj.group(2)
                applicationStarted = -1
                log(logFile, "%s Killed %s/%s" % (time.strftime('%H:%M:%S'), package, killObj.group(3)))
                break
            curTime = time.time()
        else:
            print "exception"
            break
    '''
    if curTime - begTime > duration:
        print "Time out"
        os.system("adb kill-server")
        isTerminate = True
        applicationStarted = -1
    '''

    if (applicationStarted < 1):
        log(logFile, "Analysis has not started...")
        os.kill(adb.pid, signal.SIGTERM)
        #rmWrapApp(package, deviceID)
        applicationStarted = -1
        return 1
    
    log(logFile, "%s Finish %s on %s" % (time.strftime('%H:%M:%S'), package, deviceID))

# run APP
# 1. Run monkey runner with script runapp.py
#    1.1 Connect to device
#    1.2 Unlock device
#    1.3 Install APK
#    1.4 Start MainActivity with AM command
# 2. Run logcat to collect output logs
#    2.1 Decide whether the activity has started
#    2.2 Read ther logs
# 3. Wait for specified duration
# 4. Run monkeyrunner with script stopapp.py
#    4.1 Stop activities
#    4.2 Uninstall the apk

def executeAPP(app, duration, deviceID):
    global isStart
    global finished
    global isTerminate
    global applicationStarted
    logFile = None
    isStart = False
    isTerminate = False
    applicationStarted = 0
    if not ".apk" in app:
        os.system("mv %s %s.apk" % (app, app))
        app = "%s.apk" % app
    try:
        apkInfo = ApkInfo(app)
    except:
        print("Get apk info error")
        return
    if not apkInfo.is_valid():
	print("Apk %s is invalid..." % app)
        isTerminate = True
	return 0
    print("Try to run %s on %s for %d seconds..." % (app, deviceID, duration))
    package = apkInfo.get_package()
    mainActivity = apkInfo.get_main_activity()
    
    os.system("adb -s %s shell rm -f /data/local/tmp/fuzz/*" % deviceID)
    os.system("adb -s %s logcat -c" % deviceID)
    
    
    mainAct = mainActivity
    wrap_script = apkInfo.genScriptFuzzer()
    type = 0
    #sys.exit(0)


    #start_ts = time.time()
    #removeApp(package, deviceID)
    installApp(app, deviceID)
    rmWrapApp(package, deviceID)
    
    startOneActivity(package, mainActivity, deviceID)
    os.system("adb -s %s shell am force-stop %s" % (deviceID, package))
    time.sleep(4)
    #time.sleep(2)
    
    os.system("adb -s %s logcat -c" % deviceID)
    wrapApp(package, wrap_script, deviceID)
    start_ts = time.time()
    startOneActivity(package, mainActivity, deviceID)
    #time.sleep(5)
    runLogcat(deviceID, package)
    isTerminate = True
    getUnpackDex(package)
    rmWrapApp(package, deviceID)
    removeApp(package, deviceID)
    print("Script exit...")
    return 1
    
def interruptHandler(signum, frame):
    """ 
    Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'
    """
    global isTerminate
    isTerminate = True
    #raise KeyboardInterrupt	


def getDevices():
    devices = []
    out = re.split(r'[\r\n]+', subprocess.check_output(['adb', 'devices']).rstrip())
    for line in out[1:]:
        if not line.strip():
            continue
        if 'offline' in line:
            continue
        serial, _ = re.split(r'\s+', line, maxsplit=1)
        devices.append(serial)
        print serial
    return devices;


def getUnpackagedApps():
    try:
        fr = open("unpackaged.txt", 'r')
    except:
        return []
    apps = []
    for l in fr.readlines():
        app = l.split(", ")[1]
        print app
        apps.append(app)
    fr.close()
    return apps

def runOneApp(app, dur, deviceID):
    apks = []
    apks.append(app)
    os.system("adb -s %s root" % deviceID)
    os.system("adb -s %s shell setenforce 0" % deviceID)
    
    for f in apks:
        #app = os.path.join(dir, f)
        #if apk in runned:
        #    continue
        print app
        #os.system("adb -s %s shell rm -rf /data/local/tmp/dex/*" % (deviceID))
        #os.system("adb -s %s shell rm -rf /data/local/tmp/bevgrind/*" % (deviceID))
        os.system("adb -s %s shell rm -rf /data/local/tmp/fuzz/*" % (deviceID))
        executeAPP(app, dur, deviceID)

if __name__ == "__main__":
    devices = getDevices()
    apkfile = sys.argv[1]  # directory of the apks or the path of apk
    if len(devices) > 0:
        #os.system("monkeyrunner unlockScreen.py %s" % devices[0])
        runOneApp(apkfile, 600, devices[0])
        #os.system("monkeyrunner lockScreen.py %s" % devices[0])
    else:
        print "No device"
