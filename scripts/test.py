#!/usr/bin/env python
# -*- coding: utf-8 -*- 

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


def log(line):
    os.system("echo \'%s\' >> branch.log" % line)

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

    def genScript(self):
        package = self.packageNames[0]
        s1 = 'wrap.sh'
        sf = open(s1, 'w')
        sf.write("#!/system/bin/sh\n")
        #sf.write("rm -rf /data/local/tmp/frw/*\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/frw/frw.log.%p --tool=datatrace --critical-ins-only=yes --trace-ins-taint=no\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/frw/frw.log.%p --tool=datatrace --critical-ins-only=yes --trace-ins-taint=no\'\n")
        sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/frw/frw.log.%p --tool=datatrace --critical-ins-only=yes --trace-ins-taint=no\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/frw/frw.log.%p --tool=none\'\n")
        #sf.write("export TMPDIR=/data/data/%s\n" % package)
        sf.write("export TMPDIR=/data/local/tmp/frw\n")
        sf.write("exec valgrind $VGPARAMS $*\n")
        sf.close()
        return s1
    
    def genScriptUnpackage(self):
        package = self.packageNames[0]
        s1 = 'bevgrind.sh'
        sf = open(s1, 'w')
        sf.write("#!/system/bin/sh\n")
        #sf.write("rm -rf /data/local/tmp/bevgrind/*\n")
        #sf.write("rm -rf /data/local/tmp/dex/*\n")
        #sf.write("VGPARAMS='--log-file=/data/local/tmp/bevgrind/unpackage.log.%p --trace-children=yes --tool=bevgrind --parse-dex=yes'\n");
        sf.write("VGPARAMS='--log-file=/data/local/tmp/bevgrind/unpackage.log.%p --trace-children=yes --tool=bevgrind'\n");
        #sf.write("VGPARAMS='--log-file=/data/local/tmp/bevgrind/unpackage.log.%p --trace-children=yes --tool=bevgrind --full-trace=yes'\n");
        #sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/frw/frw.log.%p --tool=datatrace --critical-ins-only=yes --trace-ins-taint=no\'\n")
        #sf.write("VGPARAMS=\'-v --trace-children=yes --log-file=/data/local/tmp/frw/frw.log.%p --tool=none\'\n")
        #sf.write("export TMPDIR=/data/data/%s\n" % package)
        #os.system("chmod 777 -R /data/data/%s\n" % package)
        os.system("adb shell chmod 777 /data/local/tmp")
        sf.write("export TMPDIR=/data/local/tmp\n")
        sf.write("exec valgrind $VGPARAMS $*\n")
        sf.close()
        return s1
    
    def genScriptFuzzer(self):
        s1 = 'fuzzapp.sh'
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
    os.system("adb -s %s shell \"setprop %s \\\"\\\"\"" % (deviceID, wrapper))



def outputLogs(deviceID):
    try:
        th = threading.Thread(target=runLogcat, args=(deviceID,))
        th.start()
    except:
        print "Start log thread error.."
        pass

def resolveInput(index):
    conFile = "ouput_%s.txt" % index
    os.system("adb pull /data/local/tmp/fuzz/%s" % conFile)
    print conFile
    return

def runLogcat(deviceID):
    global isTerminate
    isTerminate = False
    index = 0
    adb = Popen(["adb", "logcat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    #return to 0x1efbeeb1 for 1 iterative execution (orig: 0x730ce427)
    retLine  = r'(.*)return to 0x[0-9a-fA-F]+ for (\d+) iterative execution(.*)'
    expLine  = r'(.*)\[EXP (\d+)\](.*)'
    #expPattern  = re.compile(r'(.*) [EXP (\d+)] (.*)')
    logFile = open("branch.txt", "w+")
    while isTerminate == False:
        try:
            logcatInput = adb.stdout.readline()
        except:
            break;
        if not logcatInput:
            print("We have lost the connection with ADB")
            os.kill(adb.pid, signal.SIGTERM)
            os.system("adb kill-server")
            adb = Popen(["adb", "-s", deviceID, "logcat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            continue

        logFile.write(logcatInput)
        try:
            expObj  = re.search( expLine, logcatInput, re.M|re.I )
            retObj  = re.search( retLine, logcatInput, re.M|re.I )
        except:
            break;
        if retObj:
            print retObj.group()
            resolveInput(retObj.group(2))
            continue
            index = int(retObj.group(1))-1
            info  = expObj.group(2)
            log(info)
    logFile.close()

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
    os.system("adb -s %s logcat -c" % deviceID)
    
    package = apkInfo.get_package()
    mainActivity = apkInfo.get_main_activity()
    
    wrap_script = apkInfo.genScriptFuzzer()
    type = 0
   
    start_ts = time.time()
    removeApp(package, deviceID)
    installApp(app, deviceID)
            
    mainAct = mainActivity
    '''
    rmWrapApp(package, deviceID)
    startOneActivity(package, mainActivity, deviceID)
    time.sleep(4)
    return 0
    '''
    wrapApp(package, wrap_script, deviceID)
    start_ts = time.time()
    startOneActivity(package, mainActivity, deviceID)
    #os.system("adb shell logcat")
    runLogcat(deviceID)
    isTerminate = True
    removeAPK(app, deviceID)
    print("Script exit...")
    return 1
    
def interruptHandler(signum, frame):
    """ 
    Raise interrupt for the blocking call 'logcatInput = sys.stdin.readline()'
    """
    global isTerminate
    isTerminate = True
    raise KeyboardInterrupt	


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
        os.system("adb -s %s shell rm -rf /data/local/tmp/dex/*" % (deviceID))
        os.system("adb -s %s shell rm -rf /data/local/tmp/bevgrind/*" % (deviceID))
        executeAPP(app, dur, deviceID)

if __name__ == "__main__":
    devices = getDevices()
    runLogcat(devices)
