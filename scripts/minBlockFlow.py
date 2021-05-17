#!/usr/bin/env python
#-*- coding: utf-8 -*-
import re
import os
import sys
import struct
import hashlib

MAX_CONSTRAIN_LEN = 256
bcRange = []

def buildMemRange(lf):
    tMems = []
    addrs = {}
    canRanges = []
    f = open(lf, 'r')
    lr = 0
    isCreate = False
    for line in f.readlines():
        if not isCreate:
            #[MEM]:  1 memcpy() s1=0x1f3686d0() 
            p1 = '^\[MEM\]: 1 memcpy\(\) s1=(0x[0-9a-z]*) s2=(0x[0-9a-z]*) n=(\d*) (.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                tAddr = int(r1.groups()[1], 0)
                tLen  = int(r1.groups()[2])
                tMems.append((tAddr, tAddr+tLen))
                continue

            p1 = '^\[INFO\] Start the detail analysis(.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                isCreate = True
            continue

        p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} PUT\((\d*)\) <- t(\d*):I32 \| \((0x[a-zA-Z0-9]*)\)$'
        r1 = re.match(p1, line[:-1])
        if r1:
            offset = int(r1.groups()[0])
            temp   = int(r1.groups()[1])
            value  = int(r1.groups()[2], 0)
            if offset == 60:
                lr = value
            continue

        p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*):I(\d*) = LD\(t(\d*|-1)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
        r1 = re.match(p1, line[:-1])
        if r1:
            temp = int(r1.groups()[0])
            size = int(r1.groups()[1])
            addrTemp = int(r1.groups()[2])
            value = int(r1.groups()[3], 0)
            addr = int(r1.groups()[4], 0)
            if (not addrTemp == -1) and (not (addr & 0xffff0000 == lr & 0xffff0000)):
                if not addr in addrs.keys():
                    addrs[addr] = size / 8
                elif addrs[addr] != size / 8:
                    print "Error source addr (0x%08x %d %d)" % (addr, addrs[addr], size/8)
            continue

    f.close()
    for addr in sorted(addrs.keys()):
        l = addrs[addr]
        end = addr + l - 1
        if len(canRanges) == 0:
            canRanges.append((addr, end))
        else:
            (s, e) = canRanges[-1]
            if end > e:
                if addr == e + 1:
                    canRanges[-1] = (s, end)
                else:
                    canRanges.append((addr, end))
    for s, e in canRanges:
        print "0x%08x - 0x%08x  %4d" % (s, e, e-s+1)

def analyCons(cons, addrValue):
    pat = re.compile('ld\((0x[a-z0-9]{8})\((0x[a-z0-9]*)\):I(8|16|32)\)')
    mem = {}
    memRanges = []
    memRanges1 = []
    for con in cons:
        print con
        items = pat.findall(con)
        for item in items:
            addr = int(item[0], 0)
            value = int(item[1], 0)
            size  = int(item[2])
            mem[addr] = (size/8, value)
    
    for addr in sorted(mem.keys()):
        i = 0
        (l,v) = mem[addr]
        end = addr + l - 1
        while i < len(memRanges):
            (b,e,type) = memRanges[i]
            if addr <= e + 1 and end > e:
                type = type | l
                memRanges[i] = (b, end, type)
                break
            i = i + 1
        if i == len(memRanges):
            memRanges.append((addr, end, l))
    #for a,e,t in memRanges:
    #    print "0x%08x - 0x%08x 0x%04x %d" % (a, e, t, e-a+1)
    la = 0
    le = 0
    lt = 0
    for a,e,t in memRanges:
        if lt != t or a - le >= 100:
            if la > 0:
                memRanges1.append((la, le, lt))
            la = a
            lt = t
        le = e
    memRanges1.append((la, le, lt))

    for a,e,t in memRanges1:
        length = e-a+1
        isCandidate = False
        if length > 5 and t in [1,2,4]:
            isCandidate = True
            addr = a
            while addr < e+1:
                if addr in addrValue.keys():
                    (value, size) = addrValue[addr]
                    #print "*(0x%08x) = 0x%x:I%d" % (addr, value, size)
                    addr = addr + size
                else:
                    #isCandidate = False
                    #print "*(0x%08x) = 0x??:I1" % (addr)
                    addr = addr + 1
        if isCandidate and t == 2:
            print "0x%08x - 0x%08x 0x%04x %d" % (a, e, t, length)
    return memRanges1
def getSymbolInput(con):
    srcAddrs = []
    #psrc = re.compile('src\((0x[a-f0-9]*):(0x[a-f0-9]*)\((0x[a-f0-9]*)\):I(\d*)\)')
    #psrc = re.compile('src\((0x[a-f0-9]*)\((0x[a-f0-9]*)\):I(\d*)\)')
    psrc = re.compile('src\((0x[a-f0-9]*)\((0x[a-f0-9]*)\):I(\d*):(0x[a-f0-9]{8})\)')
    for m in psrc.finditer(con):
        srcaddr = int(m.groups()[0], 0)
        srcvalue = int(m.groups()[1], 0)
        srcAddrs.append((srcaddr, srcvalue))
    return srcAddrs

def buildBlockFlow(f):
    global conBranches
    tMems = []
    regTaint = {}
    regCal = {}
    tmpTaint = {}
    tmpCal = {}
    addrTaint = {}  # Taint tag of the address
    addrCal = {}    # symblic expression of the address
    addrValue = {}  # data stored in the address
    oatFiles = []
    conBranches = []  # The executed conditional branches
    mainClass = None
    mainMethod = None
    callStack = []
    regs = []
    cons = []
    conSrcDict = {}
    consDest = {}
    symbBrachIndex = {}
    consIndex = 0
    tempDest = {}
    isCreate = False
    isVM = False
    isCall = False
    subroutines = []
    subDict = {}
    isbDict = {}
    taintSource = {}
    taintAddr = {}
    iteCons = []
    insBegin = 0 # memory range of the VM
    insEnd   = 0
    disBegin = 0 # Memory range of the dispatch code
    disLen   = 0
    curBlock = 0
    blockExits = []
    
    for i in range(16):
        regs.append(0)
    
    fr = open(f, 'r')
    for line in fr.readlines():
        preBlock = None
        p1 = '^Try to dump dex file (.*\.dex) (.*)$'
        r1 = re.match(p1, line[:-1])
        if r1:
            dexfile = r1.groups()[0].split('/')[-1]
            if len(oatFiles) > 0:
                oatFiles[-1].addDexFile(dexfile)
            continue
        
        if line[0:6] == '[INFO]':
            if isVM:
                if False:
                    print line[:-1]
                continue
            #p1 = '^\[INFO\] Start the detail analysis\(ret=(0x[a-z0-9]{8})\)\.$'
            p1 = '^\[INFO\] Start the detail analysis(.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                isCreate = True
                isVM = True
                print "Start detail analysis"
                continue
            p1 = '^\[INFO\] Sop the detail analysis\.$'
            r1 = re.match(p1, line[:-1])
            if r1:
                break
            p1 = '^\[INFO\] Meet oat file: (.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                #oatFile =  OatFile(r1.groups()[0])
                #oatFiles.append(oatFile)
                print "Add oat file %s" % r1.groups()[0]
                continue

            p1 = '^\[INFO\] oatdata: (0x[a-f0-9]{8}) - (0x[a-f0-9]{8}) len=(\d*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                #oatFiles[-1].addOatData(int(r1.groups()[0], 0), int(r1.groups()[2]))
                #print "Add %s oat data %s %s" % (oatFiles[-1].getOatFileName(), r1.groups()[0], r1.groups()[2])
                continue
            p1 = '^\[INFO\] oatexec: (0x[a-f0-9]{8}) - (0x[a-f0-9]{8}) len=(\d*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                #oatFiles[-1].addOatExec(int(r1.groups()[0], 0), int(r1.groups()[2]))
                #print "Add %s oat exec %s %s" % (oatFiles[-1].getOatFileName(), r1.groups()[0], r1.groups()[2])
                continue
            continue
        if not isVM:
            # [MODI2] ST(0x06c99418) <- 0x0 | Allocated.memoy | /data/app/com.example.jeremy.empty-1/lib/arm/libbaiduprotect.so
            p1 = '^\[MODI\d*\] ST\((0x[0-9a-f]*)\) <- (0x[0-9a-f]*) \| (.*) \| (.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                addr  = int(r1.groups()[0], 0)
                value = int(r1.groups()[1], 0)
                # addrValue[addr] = (value, 0)
                # print "*(0x%08x) = 0x%x" % (addr, value)
                continue

            #         [SYSC] 1 mmap(23) off_0x00000000 -> 0x1ecff000-0x1ed6086c 399468 r-x 0x12 /data/app/com.example.jeremy.empty-1/lib/arm/libbaiduprotect.so
            p1 = '^\[SYSC\] \d* mmap\((\d*)\) off_(0x[0-9a-f]*) -> (0x[0-9a-f]*)-(0x[0-9a-f]*) (\d*) r-x 0x12 /data/app/(.*)/lib/arm/libbaiduprotect\.so$'
            r1 = re.match(p1, line[:-1])
            if r1:
                insBegin = int(r1.groups()[2], 0)
                insEnd   = int(r1.groups()[3], 0)
                print "VM instruction addr: 0x%08x - 0x%08x" % (insBegin, insEnd)
                continue

                  # [MEM]:  1 memset() s=0x06c98ff0 c=0x00 n=1344
            p1 = '^\[MEM\]:  1 memset\(\) s=(0x[0-9a-f]*) c=0x00 n=1344$'
            r1 = re.match(p1, line[:-1])
            if r1:
                disBegin = int(r1.groups()[0], 0)
                disLen   = 1344
                print "Dispatch: 0x%08x - 0x%08x len=%d" % (disBegin, disBegin + disLen, disLen)
                continue

                  # [MEM]:  1 memcpy() s1=0x06c41c08 s2=0x1f90bf82 n=1 L
            p1 = '^\[MEM\]:  1 memcpy\(\) s1=(0x[0-9a-f]*) s2=(0x[0-9a-f]*) n=(\d*) (.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                tAddr = int(r1.groups()[0], 0)
                tLen  = int(r1.groups()[2])
                if tLen > 64:
                #if tLen == 104:
                    tMems.append((tAddr, tAddr+tLen))
                    print "Target: 0x%08x - 0x%08x len=%d" % (tAddr, tAddr+tLen, tLen)
           
                  # Added new Dex file object 0x06c58318 mem:0x1f922d10 - 0x1faf1068
            p1 = '^Added new Dex file object (0x[0-9a-f]*) mem:(0x[0-9a-f]*) - (0x[0-9a-f]*)$'
            #p1 = '^\[MEM\]:  1 memcpy\(\) s1=(0x[0-9a-f]*) s2=(0x[0-9a-f]*) n=(\d*) (.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                begAddr = int(r1.groups()[1], 0)
                endAddr  = int(r1.groups()[2], 0)
                tLen = endAddr - begAddr
                if tLen > 64:
                #if tLen == 104:
                    tMems.append((begAddr, endAddr))
                    print "Target: 0x%08x - 0x%08x len=%d" % (begAddr, endAddr, tLen)
            continue;
        p1 = '^\[CALL\] \d* \d* \d* (L.*;) (.*)\(\) [A-Z]* isNative=(\d) flag=\d* pArtMethod=(0x[a-f0-9]{8})$'
        r1 = re.match(p1, line[:-1])
        if r1:
            if False:
                #print line[:-1]
                regTaint.clear()
                regCal.clear()
            if isCreate:
                mainClass = r1.groups()[0]
                mainMethod = r1.groups()[1]
                isCreate = False
            continue
        #      [RETU] 01 11 01737 Landroid/app/Activity; getWindow() L isSource=Flase pArtMthod=0x70412668
        p1 = '^\[RETU\] \d* \d* \d* (L.*;) (.*)\(\) [A-Z]* isSource=(.*) pArtMthod=(0x[a-f0-9]{8})$'
        r1 = re.match(p1, line[:-1])
        if r1:
            #if False:
            #    print line[:-1]
            Clazz = r1.groups()[0]
            Method = r1.groups()[1]
            if Clazz == mainClass and Method == mainMethod:
                isVM = False
            continue
        if line[0:3] == '[I]':
            p1 = '^\[I\] \d Jump from (0x[a-fA-F0-9]{8}).* to (0x[a-zA-Z0-9]{8})(.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                src = int(r1.groups()[0], 0)
                dst = int(r1.groups()[1], 0)
                curBlock = dst
                str = r1.groups()[2]
                tmpstr = "  r0=%s  r1=%s  r2=%s  r3=%s  sp=0x%08x  lr=0x%08x" % (
                        regCal[8] if regCal.has_key(8) else ("0x%x" % regs[0]),
                        regCal[12] if regCal.has_key(12) else ("0x%x" % regs[1]),
                        regCal[16] if regCal.has_key(16) else ("0x%x" % regs[2]),
                        regCal[20] if regCal.has_key(20) else ("0x%x" % regs[3]),
                        regs[13], regs[14])
                if not dst in isbDict.keys():
                    isbDict[dst] = []
                isbDict[dst].append(tmpstr)
                if False:
                    if isCall:
                        print "Invoke: " + line[:-1]
                        isCall = False
                        if not dst in subroutines:
                            subroutines.append(dst)
                    else:
                        print line[:-1]
                    print "  r0=%s\n  r1=%s\n  r2=%s\n  r3=%s\n  sp=0x%08x\n  lr=0x%08x" % (
                            regCal[8] if regCal.has_key(8) else ("0x%x" % regs[0]),
                            regCal[12] if regCal.has_key(12) else ("0x%x" % regs[1]),
                            regCal[16] if regCal.has_key(16) else ("0x%x" % regs[2]),
                            regCal[20] if regCal.has_key(20) else ("0x%x" % regs[3]),
                            regs[13], regs[14])
                if len(callStack) > 0 and dst == callStack[-1]:
                    if False:
                        print "Return to 0x%08x\n" % dst
                    callStack.pop()
                tmpTaint.clear()
                tmpCal.clear()
                continue
        elif line[0:3] == '[R]':
            p1 = '^\[R\] \d Jump from (0x[a-fA-F0-9]{8})(.*) to (0x[a-zA-Z0-9]{8}).*$'
            r1 = re.match(p1, line[:-1])
            if r1:
                src = int(r1.groups()[0], 0)
                str = r1.groups()[1]
                dst = int(r1.groups()[2], 0)
                curBlock = dst
                tmpstr = "  r0=%s  r1=%s  r2=%s  r3=%s  sp=0x%08x  lr=0x%08x" % (
                        regCal[8] if regCal.has_key(8) else ("0x%x" % regs[0]),
                        regCal[12] if regCal.has_key(12) else ("0x%x" % regs[1]),
                        regCal[16] if regCal.has_key(16) else ("0x%x" % regs[2]),
                        regCal[20] if regCal.has_key(20) else ("0x%x" % regs[3]),
                        regs[13], regs[14])
                if not dst in isbDict.keys():
                    isbDict[dst] = []
                isbDict[dst].append(tmpstr)
                if False:
                    if isCall:
                        print "Invoke: " + line[:-1]
                        isCall = False
                        if not dst in subroutines:
                            subroutines.append(dst)
                    else:
                        print line[:-1]
                    print "  r0=%s\n  r1=%s\n  r2=%s\n  r3=%s\n  sp=0x%08x\n  lr=0x%08x" % (
                            regCal[8] if regCal.has_key(8) else ("0x%x" % regs[0]),
                            regCal[12] if regCal.has_key(12) else ("0x%x" % regs[1]),
                            regCal[16] if regCal.has_key(16) else ("0x%x" % regs[2]),
                            regCal[20] if regCal.has_key(20) else ("0x%x" % regs[3]),
                            regs[13], regs[14])
                if len(callStack) > 0 and dst == callStack[-1]:
                    if False:
                        print "Return to 0x%08x\n" % dst
                    callStack.pop()
                tmpTaint.clear()
                tmpCal.clear()
                continue
        elif line[0:3] == '[S]':
            p1 = '^\[S\] \d Jump from (0x[a-fA-F0-9]{8}).* to (0x[a-zA-Z0-9]{8}).*$'
            r1 = re.match(p1, line[:-1])
            if r1:
                src = int(r1.groups()[0], 0)
                dst = int(r1.groups()[1], 0)
                curBlock = dst
                tmpstr = "  r0=%s  r1=%s  r2=%s  r3=%s  sp=0x%08x  lr=0x%08x" % (
                        regCal[8] if regCal.has_key(8) else ("0x%x" % regs[0]),
                        regCal[12] if regCal.has_key(12) else ("0x%x" % regs[1]),
                        regCal[16] if regCal.has_key(16) else ("0x%x" % regs[2]),
                        regCal[20] if regCal.has_key(20) else ("0x%x" % regs[3]),
                        regs[13], regs[14])
                if not dst in isbDict.keys():
                    isbDict[dst] = []
                isbDict[dst].append(tmpstr)
                if False:
                    if isCall:
                        print "Invoke: " + line[:-1]
                        isCall = False
                        if not dst in subroutines:
                            subroutines.append(dst)
                    else:
                        print line[:-1]
                    print "  r0=%s\n  r1=%s\n  r2=%s\n  r3=%s\n  sp=0x%08x\n  lr=0x%08x" % (
                            regCal[8] if regCal.has_key(8) else ("0x%x" % regs[0]),
                            regCal[12] if regCal.has_key(12) else ("0x%x" % regs[1]),
                            regCal[16] if regCal.has_key(16) else ("0x%x" % regs[2]),
                            regCal[20] if regCal.has_key(20) else ("0x%x" % regs[3]),
                            regs[13], regs[14])
                if len(callStack) > 0 and dst == callStack[-1]:
                    if False:
                        print "Return to 0x%08x\n" % dst
                    callStack.pop()
                tmpTaint.clear()
                tmpCal.clear()
                continue
        else:
            if line[0:6] == '[STMT]':
                # Load
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*):I(\d*) = LD\(t(\d*|-1)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    rtemp = int(r1.groups()[0])
                    size = int(r1.groups()[1])
                    addrTemp = int(r1.groups()[2])
                    value = int(r1.groups()[3], 0)
                    addr = int(r1.groups()[4], 0)
                    if addr in addrTaint.keys():
                        tmpTaint[rtemp] = addrTaint[addr]
                        tmpCal[rtemp] = addrCal[addr]
                    else:
                        if rtemp in tmpTaint.keys():
                            del tmpTaint[rtemp]
                            del tmpCal[rtemp]

                        if not addrTemp == -1:
                            # We do not take the values from stack as taint source
                            if addrTemp in tmpTaint.keys():
                                tmpTaint[rtemp] = tmpTaint[addrTemp]
                                tmpCal[rtemp] = "load(%s)" % tmpCal[addrTemp]
                                if not addr in taintAddr.keys():
                                    taintAddr[addr] = []
                                if not addr in addrValue.keys():
                                    taintAddr[addr].append("t%d (%s) Unknown" %(addrTemp, tmpCal[addrTemp]))
                                    #p rint "TaintAddr: 0x%08x %s Unknwon" % (addr, tmpCal[addrTemp])
                                else:
                                    (vv, vl) = addrValue[addr]
                                    taintAddr[addr].append("t%d (%s) 0x%x:I%d" %(addrTemp, tmpCal[addrTemp], vv, vl))
                                    # print "TaintAddr: 0x%08x %s 0x%x:I%d" % (addr, tmpCal[addrTemp], vv, vl)
                            elif not (addr & 0xffff0000 == regs[13] & 0xffff0000) and size == 16:
                                if True: # Qihoo
                                    tmpTaint[rtemp] = []
                                    tmpTaint[rtemp].append("0x%08x:I%d" % (addr, size))
                                    #tmpCal[rtemp] = 'src(0x%08x:0x%04x(0x%04x):I%d)' % (addr, addr - s, value, size)
                                    #tmpCal[rtemp] = 'src(0x%08x(0x%04x):I%d)' % (addr, value, size)
                                    tmpCal[rtemp] = 'src(0x%08x(0x%04x):I%d:0x%08x)' % (addr, value, size, curBlock)
                                    print "Add Symbolic Inputs: t%d <- LD(0x%08x) : 0x%x:I%d" % (rtemp, addr, value, size)
                                else: # Baidu
                                    for s, e in tMems:
                                        if addr >= s and addr < e: # locate in a specific memory ranges
                                            tmpTaint[rtemp] = []
                                            tmpTaint[rtemp].append("0x%08x:I%d" % (addr, size))
                                            #tmpCal[rtemp] = 'src(0x%08x:0x%04x(0x%04x):I%d)' % (addr, addr - s, value, size)
                                            #tmpCal[rtemp] = 'src(0x%08x(0x%04x):I%d)' % (addr, value, size)
                                            tmpCal[rtemp] = 'src(0x%08x(0x%04x):I%d:0x%08x)' % (addr, value, size, curBlock)
                                            # print("Test1: %s" % line[:-1])
                                            break
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- \<cvt\>LD\(t(\d*)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    temp = int(r1.groups()[0])
                    stmp = int(r1.groups()[1])
                    value = int(r1.groups()[2], 0)
                    addr = int(r1.groups()[3], 0)
                    addrValue[addr] = (value, 4)
                    if temp in tmpTaint.keys():
                        del tmpTaint[temp]
                        del tmpCal[temp]
                    if addr in addrTaint.keys():
                        tmpTaint[temp] = addrTaint[addr]
                        tmpCal[temp] = addrCal[addr]
                    continue

                # Store
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} ST\(t(\d*)\) = t(\d*|-1):I(\d*) \| ST\((0x[a-f0-9]*)\) <- (0x[a-f0-9]*) \|(.*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    atemp = int(r1.groups()[0])
                    vtemp = int(r1.groups()[1])
                    vsize = int(r1.groups()[2])
                    addr = int(r1.groups()[3], 0)
                    value = int(r1.groups()[4], 0)
                    addrValue[addr] = (value, vsize/8)

                    if addr in addrTaint.keys():
                        del addrTaint[addr]
                        del addrCal[addr]
                    # TODO: atemp is tainted

                    if vtemp in tmpTaint.keys():
                        addrTaint[addr] = tmpTaint[vtemp]
                        addrCal[addr] = tmpCal[vtemp]
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} ST\(t(\d*)\) <\? t(\d*|-1):I(\d*) \| (.*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    atemp = int(r1.groups()[0])
                    #print "TODO: %s" % line[:-1]
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} ST\((0x[a-z0-9]*)\) <\? (0x[0-9a-z]*):I(\d*) \| (.*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    addr = int(r1.groups()[0], 0)
                    value = int(r1.groups()[1], 0)
                    vsize = int(r1.groups()[2])
                    addrValue[addr] = (value, vsize/8)
                    if addr in addrTaint.keys():
                        del addrTaint[addr]
                        del addrCal[addr]
                    #print "TODO: %s" % line[:-1]
                    continue

                # Unop
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- t(\d*):I(\d*) \| (0x[0-9a-z]*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp = int(r1.groups()[1])
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp]
                        tmpCal[dtmp] = tmpCal[stmp]
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) = (\d*)[US]*to[US]*(\d*)\(t(\d*)\) \| Unop\((0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp = int(r1.groups()[3])
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp]
                        tmpCal[dtmp] = tmpCal[stmp]
                    # if dtmp in tmpTaint.keys():
                    #    print line[:-1]
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) = Not(\d*)\(t(\d*)\) \| Unop\((0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp = int(r1.groups()[2])
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp]
                        #if len(tmpCal[stmp]) < MAX_CONSTRAIN_LEN:
                        tmpCal[dtmp] = "!(%s)" % tmpCal[stmp]
                    #svalue = int(r1.groups()[3], 0)
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) = Clz(\d*)\(t(\d*)\) \| Unop\((0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp = int(r1.groups()[2])
                    if stmp in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp]
                        tmpCal[dtmp] = "Clz(%s)" % tmpCal[stmp]
                    continue

                #Binop
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- Add(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        #for tt in tmpTaint[stmp2]:
                            #if not tt in tmpTaint[dtmp]:
                                #tmpTaint[dtmp].append(tt) 
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s+%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s+0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x+%s)" % (svalue1, tmpCal[stmp2])
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- Sub(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s-%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s-0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x-%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 - svalue2
                    #print "t%d = t%d - t%d | 0x%x = 0x%x - 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- Sar(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s/%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s/0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x/%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 - svalue2
                    #print "t%d = t%d - t%d | 0x%x = 0x%x - 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- Mul(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s*%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s*0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x*%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 * svalue2
                    #print "t%d = t%d x t%d | 0x%x = 0x%x x 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- Shl(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s<<%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s<<0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x<<%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 << svalue2
                    #print "t%d = t%d <<  t%d | 0x%x = 0x%x << 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- Shr(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s>>%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s>>0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x>>%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 >> svalue2
                    #print "t%d = t%d >>  t%d | 0x%x = 0x%x >> 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- (Or|Xor)(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[3])
                    stmp2 = int(r1.groups()[4])
                    svalue1 = int(r1.groups()[5], 0)
                    svalue2 = int(r1.groups()[6], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s|%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s|0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x|%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 | svalue2
                    #print "t%d = t%d | t%d | 0x%x = 0x%x | 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- And(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s&%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s&0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x&%s)" % (svalue1, tmpCal[stmp2])
                    #result  = svalue1 & svalue2
                    #print "t%d = t%d & t%d | 0x%x = 0x%x & 0x%x" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- CmpNE(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s!=%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s!=0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x!=%s)" % (svalue1, tmpCal[stmp2])
                    #if  not svalue1 == svalue2:
                    #    result = 1
                    #else:
                    #    result = 0
                    #print "t%d = (t%d != t%d) | 0x%x = (0x%x != 0x%x)" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- CmpLT(\d*)[U*|S*]\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s>%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s>0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x>%s)" % (svalue1, tmpCal[stmp2])
                    #if  not svalue1 == svalue2:
                    #    result = 1
                    #else:
                    #    result = 0
                    #print "t%d = (t%d != t%d) | 0x%x = (0x%x != 0x%x)" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- CmpLE(\d*)[U*|S*]\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s>=%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s>=0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x>=%s)" % (svalue1, tmpCal[stmp2])
                    #if  not svalue1 == svalue2:
                    if  dtmp in tmpTaint:
                        result = 1
                    else:
                        result = 0
                    # print "t%d = (t%d != t%d) | 0x%x = (0x%x != 0x%x)" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue
                
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- CmpEQ(\d*)\(t(\d*|-1), t(\d*|-1)\) \| Binop\((0x[a-f0-9]*), (0x[a-f0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[2])
                    stmp2 = int(r1.groups()[3])
                    svalue1 = int(r1.groups()[4], 0)
                    svalue2 = int(r1.groups()[5], 0)
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if stmp1 in tmpTaint.keys() and stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmpCal[dtmp] = "(%s==%s)" % (tmpCal[stmp1], tmpCal[stmp2])
                    elif stmp1 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp1]
                        tmpCal[dtmp] = "(%s==0x%x)" % (tmpCal[stmp1], svalue2)
                    elif stmp2 in tmpTaint.keys():
                        tmpTaint[dtmp] = tmpTaint[stmp2]
                        tmpCal[dtmp] = "(0x%x==%s)" % (svalue1, tmpCal[stmp2])
                    #if  svalue1 == svalue2:
                    #    result = 1
                    #else:
                    #    result = 0
                    #print "t%d = (t%d == t%d) | 0x%x = (0x%x == 0x%x)" % (dtmp, stmp1, stmp2, result, svalue1, svalue2) 
                    continue
                
                # ITE(<cond>,<iftrue>,<iffalse>)
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) = ITE\(t(\d*|-1), t(\d*|-1), t(\d*|-1)\) \| (F|T)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    cond = int(r1.groups()[1])
                    itrue = int(r1.groups()[2])
                    ifalse = int(r1.groups()[3])
                    cond_value = r1.groups()[4]
                    #print "TODO: %s" % line[:-1]
                    #continue
                    if cond in tmpTaint.keys() or itrue in tmpTaint.keys() or ifalse in tmpTaint.keys():
                        print "%s" % line[9:-1]
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    if cond in tmpTaint.keys():
                        #print "  ITE_cond: t%d  %s %s" % (cond, tmpCal[cond], cond_value)
                        iteCons.append(tmpCal[cond])

                    if cond_value == 'T':
                        if itrue in tmpTaint.keys() and cond_value == 'T':
                            tmpTaint[dtmp] = tmpTaint[itrue]
                            tmpCal[dtmp] = tmpCal[itrue]
                            print "  t%d  %s" % (itrue, tmpCal[itrue])
                    else:
                        if ifalse in tmpTaint.keys():
                            tmpTaint[dtmp] = tmpTaint[ifalse]
                            tmpCal[dtmp]= tmpCal[ifalse]
                            print "  t%d  %s" % (ifalse, tmpCal[ifalse])
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- armg_calculate_condition\(t(\d*|-1), t(\d*|-1), t(\d*|-1), t(\d*|-1)\) \| \((\d*), (-*\d*), (\d*), (\d*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp = int(r1.groups()[0])
                    stmp1 = int(r1.groups()[1])
                    stmp2 = int(r1.groups()[2])
                    stmp3 = int(r1.groups()[3])
                    stmp4 = int(r1.groups()[4])
                    value1 = int(r1.groups()[5])
                    value2 = int(r1.groups()[6])
                    value3 = int(r1.groups()[7])
                    value4 = int(r1.groups()[8])
                    #print "TODO: %s" % line[:-1]
                    #continue
                    if dtmp in tmpTaint.keys():
                        del tmpTaint[dtmp]
                        del tmpCal[dtmp]
                    tmpTaint[dtmp] = []
                    tmpCal[dtmp] = ''
                    tmp = 'acc('
                    if stmp1 in tmpTaint.keys():
                        #tmpTaint[dtmp].extend(tmpTaint[stmp1])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp1] if not tt in tmpTaint[dtmp]]) 
                        tmp = tmp + "%s," % tmpCal[stmp1]
                        print "  t%d  %s" % (stmp1, tmpCal[stmp1])
                    else:
                        tmp = tmp + "%d," % value1
                    if stmp2 in tmpTaint.keys():
                        #tmpTaint[dtmp].extend(tmpTaint[stmp2])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp2] if not tt in tmpTaint[dtmp]]) 
                        tmp = tmp + "%s," % tmpCal[stmp2]
                        print "  t%d  %s" % (stmp2, tmpCal[stmp2])
                    else:
                        tmp = tmp + "%d," % value2
                    if stmp3 in tmpTaint.keys():
                        #tmpTaint[dtmp].extend(tmpTaint[stmp3])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp3] if not tt in tmpTaint[dtmp]]) 
                        tmp = tmp + "%s," % tmpCal[stmp3]
                        print "  t%d  %s" % (stmp3, tmpCal[stmp3])
                    else:
                        tmp = tmp + "%d," % value3
                    if stmp4 in tmpTaint.keys():
                        #tmpTaint[dtmp].extend(tmpTaint[stmp4])
                        tmpTaint[dtmp].extend([tt for tt in tmpTaint[stmp4] if not tt in tmpTaint[dtmp]]) 
                        tmp = tmp + "%s" % tmpCal[stmp4]
                        print "  t%d  %s" % (stmp4, tmpCal[stmp4])
                    else:
                        tmp = tmp + "%d" % value4
                    tmp = tmp + ')'
                    if len(tmpTaint[dtmp]) > 0:
                        tmpCal[dtmp] = tmp
                        print tmpTaint
                        print tmp
                    del tmpTaint[dtmp]
                    del tmpCal[dtmp]
                    continue

                # Get
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} t(\d*) <- GET:I32\((\d*)\) \| (0x[a-zA-Z0-9]*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    temp   = int(r1.groups()[0])
                    offset = int(r1.groups()[1])
                    if temp in tmpTaint.keys():
                        del tmpTaint[temp]
                        del tmpCal[temp]
                    if offset in regTaint.keys():
                        tmpTaint[temp] = regTaint[offset]
                        tmpCal[temp] = regCal[offset]
                    continue

                # Put
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} PUT\((\d*)\) <- t(\d*):I32 \| \((0x[a-zA-Z0-9]*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    offset = int(r1.groups()[0])
                    temp   = int(r1.groups()[1])
                    value  = int(r1.groups()[2], 0)
                    if offset in regTaint.keys():
                        del regTaint[offset]
                        del regCal[offset]
                    if temp in tmpTaint.keys():
                        regTaint[offset] = tmpTaint[temp]
                        regCal[offset] = tmpCal[temp]
                    
                    rr = (offset-8) / 4
                    if rr < 16:
                        regs[rr] = value
                        if rr == 14:
                            callStack.append(value)
                            isCall = True
                            #print "Call with ret=0x%08x" % value
                    continue
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} PUT\((\d*)\) <- (0x[a-zA-Z0-9]*):I32$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    offset = int(r1.groups()[0])
                    value  = int(r1.groups()[1], 0)
                    if offset in regTaint.keys():
                        del regTaint[offset]
                        del regCal[offset]
                    rr = (offset-8) / 4
                    if rr < 16:
                        regs[rr] = value
                        if rr == 14:
                            callStack.append(value)
                            isCall = True
                            #print "Call with ret=0x%08x" % value
                    #regTaint[offset] = []
                    continue
                
                # Exit
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} if\(t(\d*)\) goto (0x[a-zA-Z0-9]{8}) \| \((\d*)\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    guard = int(r1.groups()[0])
                    dest  = int(r1.groups()[1], 0)
                    value = int(r1.groups()[2])
                    
                    if guard in tmpTaint.keys():
                        if value == 0:
                            con = "!(%s)" % (tmpCal[guard])
                            blockExits.append((consIndex, dest, con))
                            continue
                        else:
                            con = "%s" % (tmpCal[guard])
                        cons.append(con)
                        if not dest in consDest.keys():
                            consDest[dest] = []
                        consIndex += 1
                        consDest[dest].append((consIndex, con))
                    caddr = int(r1.groups()[1], 0)
                    continue
                
                #Next
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} goto (0x[a-zA-Z0-9]{8})$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dest  = int(r1.groups()[0], 0)
                    if len(blockExits) > 0:
                        for consIndex, dest1, con in blockExits:
                            if not con[0] == '!':
                                print "Error!!!"
                            cons.append(con)
                            if not dest in consDest.keys():
                                consDest[dest] = []
                            consDest[dest].append((consIndex, con))
                            print line[:-1]
                    del blockExits[:]
                    continue

                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} goto t(\d*) \| (0x[a-zA-Z0-9]{8})$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    dtmp  = int(r1.groups()[0], 0)
                    dest  = int(r1.groups()[1], 0)
                    if dtmp in tmpTaint.keys():
                        consIndex += 1
                        #if not curBlock in tempDest.keys():
                        #    tempDest[curBlock] = []
                        #tempDest[curBlock].append((consIndex, tmpCal[dtmp], dest))
                        if not dest in tempDest.keys():
                            tempDest[dest] = []
                        tempDest[dest].append((consIndex, tmpCal[dtmp], dest))
                        # print "Goto: 0x%08x of %s" % (dest, tmpCal[dtmp])
                    del blockExits[:]
                    continue
                
                p1 = '^\[STMT\] \d 0x[a-f0-9]{4} 0x[a-f0-9]{4} helper_instrument_WrTmp_CCall_else\(\)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    continue
                #print line[:-1]
    fr.close()
    constrains = []
    tmpaddres  = []
    opcodes  = []
    for addr in sorted(consDest.keys()):
        items = len(consDest[addr])
        conTypes = []
        conSrcs  = []
        for index, con in consDest[addr]:
            # addr and value of the symbolic input
            for srcaddr, srcvalue in getSymbolInput(con):
                if not srcaddr in conSrcs:
                    conSrcs.append(srcaddr)
                if not srcaddr in conSrcDict.keys():
                    conSrcDict[srcaddr] = []
                conSrcDict[srcaddr].append((index, addr, con))
            if con[0] == '!':
                con = con[2:-1]
            if not con in conTypes:
                conTypes.append(con)
                #print "Exit: 0x%08x  %s" % (addr, con)
        types = len(conTypes) # number of constrain types
        srcs  = len(conSrcs)  # number of symbolic inputs
        
        if srcs < 2:
            continue
        
        if not addr in subroutines:
            print "0x%08x Exit items=%d types=%d srcs=%d isSubroutine=False" % (addr, items, types, srcs)
        else:
            print "0x%08x Exit items=%d types=%d srcs=%d isSubroutine=True" % (addr, items, types, srcs)

        for index, con in consDest[addr]:
            isT = 'True'
            if con[0] == '!':
                con = con[2:-1]
                isT = 'False'
            constrains.append((index, con+(":0x%08x" % addr)))
            print "   %05d  %s  %s" % (index, con, isT)
            if srcs == 21: # Debug
                for srcaddr, srcvalue in getSymbolInput(con):
                    opcodes.append((srcaddr, srcvalue))
                    print "    src=0x%08x" % srcaddr

    
    #for addr in sorted(tempDest.keys()):
    for addr in tempDest.keys():
        items = len(tempDest[addr])
        conTypes = []
        conSrcs  = []
        for index, con, dst in tempDest[addr]:
            #if con[0] == '!':
            #    con = con[2:-1]
            if not con in conTypes:
                conTypes.append(con)
            for srcaddr, srcvalue in getSymbolInput(con):
                if not srcaddr in conSrcs:
                    conSrcs.append(srcaddr)
                if not srcaddr in conSrcDict.keys():
                    conSrcDict[srcaddr] = []
                conSrcDict[srcaddr].append((index, addr, con))
        types = len(conTypes)
        
        if types < 1:
            continue
        
        if not addr in subroutines:
            print "0x%08x Next items=%d types=%d srcs=%d isSubroutine=False" % (addr, items, types, len(conSrcs))
        else:
            print "0x%08x Next items=%d types=%d srcs=%d isSubroutine=True" % (addr, items, types, len(conSrcs))
        for index, con, dst in tempDest[addr]:
            print "   %05d 0x%08x %s" % (index, dst, con)
            constrains.append((index, con+(":0x%08x" % addr)))


    '''
    #for key in conSrcDict.keys():
    for key, opt in opcodes:
        tmpDict = {}
        print "\nSymbol=0x%08x(0x%02x) size=%d" % (key, (opt^0x9696)>>8, len(conSrcDict[key]))
        for index, addr, con in conSrcDict[key]:
            if len(getSymbolInput(con)) >= 1:
                if con[0] == '!':
                    con = con[2:-1]
                    tmpDict[index] = ((addr, con, 'False'))
                else:
                    tmpDict[index] = ((addr, con, 'True '))
        for index in sorted(tmpDict.keys()):
            (addr, con, bb) = tmpDict[index]
            print "   %05d 0x%08x %s %s" % (index, addr, bb, con)

        for index, con in tempDest[addr]:
            constrains.append((index, con))
            print "   %05d  %s" % (index, con)
    print "ite_cons:"
    for con in iteCons:
        print "   %s" % con
    print "IR_Block:"
    for key in isbDict.keys():
        print "Block: 0x%08x" % key
        for tmpstr in isbDict[key]:
            print tmpstr

    print "Taint Address:"
    for key in taintAddr.keys():
        print "Addr: 0x%08x" % key
        for con in taintAddr[key]:
            print "   %s" % con

    print "Decidee Dest:"
    for dest in tempDest.keys():
        print "Dest:  0x%08x 0x%04x" % (dest, dest-insBegin)
        for con in tempDest[dest]:
            print "   %s" % con

    i = 0
    tmpstr = ''
    disEnd = disBegin + disLen
    print "Dispatch routine (0x%08x - 0x%08x):" % (disBegin, disEnd)
    saddr = disBegin
    while saddr < disEnd:
        if saddr in addrValue.keys():
            (value, l) = addrValue[saddr]
            if value > insBegin and value < insEnd:
                print "*(0x%08x):I%d = 0x%x" % (saddr, l, value)
        saddr = saddr + 1
    '''
    return (constrains, addrValue)

#def drawCFG():
#    global conBranches
#    for type, con, dest in conBranches:

def classifyCons(cons, num):
    mem_regions = []
    cdict = {}
    #p = r'src\(0x[a-f0-9]*:0x[a-f0-9]*\(0x[a-f0-9]*\):I\d*\)'
    #p1= r'(.*)src\((0x[a-f0-9]*):0x[a-f0-9]*\((0x[a-f0-9]*)\):I\d*\)(.*)'
    sinput = r'src\(0x[a-f0-9]*\(0x[a-f0-9]*\):I\d*:0x[a-f0-9]{8}\)'
    sinput1 = r'(.*)src\((0x[a-f0-9]*)\((0x[a-f0-9]*)\):I(\d*):(0x[a-f0-9]{8})\)(.*):(0x[a-f0-9]{8})'
    for con in cons:
        print "dbg-con: %s" % con[1]
        # replace symbolic input with 'src'
        con1 = re.sub(sinput, "src", con[1][:-11])
        # print con1
        if not con1 in cdict.keys():
            cdict[con1] = []
        cdict[con1].append(con)
    for con in cdict.keys():
        if len(cdict[con]) != num:
            continue
        print "Exp-Class: %s num=%d" % (con, len(cdict[con]))
        tmpDict = {}
        region = []
        for con1 in cdict[con]:
            tmpDict[con1[0]] = con1[1]
        for i in sorted(tmpDict.keys()):
            # obtain the source address and loaded value by parsing the symbolic input
            r1 = re.match(sinput1, tmpDict[i])
            if r1:
                srcAddr = int(r1.groups()[1], 0)
                ldvalue = int(r1.groups()[2], 0)
                bgaddre = int(r1.groups()[4], 0)
                edaddre = int(r1.groups()[6], 0)
                region.append(srcAddr)
                print "Exp: %04d 0x%08x-0x%08x 0x%08x 0x%02x %s" % (i, bgaddre, edaddre, srcAddr, ldvalue & 0xff, tmpDict[i])
        mem_regions.append(region)
    return mem_regions


if __name__ == "__main__":
    (cons, addrValue) = buildBlockFlow(sys.argv[1])
    #for con in cons:
        #print con
    #mems = analyCons(cons, addrValue)
    mem_regions = classifyCons(cons, 21)
    #buildMemRange(sys.argv[1])
    #print canAddr
