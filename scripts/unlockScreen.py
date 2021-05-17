#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import os
import sys
import time
import subprocess

from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice

weight = 1080
hight  = 1920

def monkeyConnect(deviceID):
    i = 0
    device = None
    while i < 2:
        try:
            i += 1 
            print("Waiting for the device %s..." % deviceID)
            device = MonkeyRunner.waitForConnection(timeout=3, deviceId=deviceID)
            strProperty = device.getProperty('model')
            break
        except:
            device = None
            print "Connect failture..."
            os.system("adb -s %s kill-server" % deviceID)
            time.sleep(1)
            pass
    return device

def lockDevice(deviceID):
    device.press("POWER", MonkeyDevice.DOWN_AND_UP)

def unlockDevice(deviceID):
    device = monkeyConnect(deviceID)
    device.wake()
    device.drag((weight/2, hight*9/10), (weight/2, hight/2), 0.3, 20)
    time.sleep(3)

if __name__ == "__main__":
    unlockDevice(sys.argv[1])
