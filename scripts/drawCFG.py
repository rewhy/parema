#!/usr/bin/evn python

import re
import os
import sys
import struct
from optparse import OptionParser
from androguard.core import androconf
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes.apk import *

import matplotlib, matplotlib.pyplot as plt
import pygraphviz
import networkx as nx
import numpy as np
import pylab

dexCodeItem = {
        0:'registersSize',
        2:'insSize',
        6:'outsSize',
        8:'triesSize',
        10:'debugInfoOff',
        14:'insnsSize',
        16:'insnsBegin'}


class OatFile(object):
    def __init__(self, name):
        self.name = name
        self.oatdata = 0
        self.oatdatalen = 0
        self.oatexec = 0
        self.oatexeclen = 0
        self.dexFiles = []

    def addOatData(self, oatdata, len):
        self.oatdata = oatdata
        self.oatdatalen = len

    def addOatExec(self, oatexec, len):
        self.oatexec = oatexec
        self.oatexeclen = len

    def addDexFile(self, dexfile):
        self.dexFiles.append(dexfile)

    def getOatFileName(self):
        return self.name

    def getOatData(self):
        return (self.oatdata, self.oatdatalen)

    def getOatExec(self):
        return (self.oatexec, self.oatexeclen)

    def getDexFiles(self):
        return self.dexFiles


class Block(object):
    def __init__(self, addr, isVm, regs, type):
        self.src = 0
        self.dst = 0
        self.nextBlock = None
        self.isVm = isVm
        self.addr = addr
        self.stmt = []
        self.info = ''
        self.regs = []
        self.type = type
        self.exitAddr = 0
        for r in regs:
            self.regs.append(r)

    def setInfo(self, info):
        tmp = info.split('(')[0]
        self.info = tmp.split(')')[0]

    def setSrc(self, src):
        self.src = src

    def setDst(self, dst):
        self.dst = dst

    def setNextBlock(self, block):
        self.nextBlock = block

    def addStmt(self, st):
        self.stmt.append(st)
    
    def addExit(self, exit):
        self.exitAddr = 0

    def getAddr(self):
        return self.addr

    def getSrc(self):
        return self.src

    def getDst(self):
        return self.dst

    def getNextBlock(self):
        return self.nextBlock

    def getStmt(self):
        return self.stmt

    def getSize(self):
        return len(self.stmt)

    def getType(self):
        return self.type

    def getInfo(self):
        if len(self.info) > 0:
            return "0x%08x(%s)" % (self.addr, self.info)
        else:
            return "0x%08x" % self.addr

    def isInVM(self):
        return self.isVm

    def getRegs(self):
        return self.regs

    def getLoadStmts(self, len):
        lst = []
        st1 = 0
        st2 = 0
        for st in self.stmt:
            if len > 0:
                p1 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(%d) = LD\((t-1)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$' % len
                p2 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(%d) = LD\((t\d*)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$' % len
            else:
                p1 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(\d*) = LD\((t-1)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
                p2 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(\d*) = LD\((t\d*)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
            r = None
            type = 0
            r1 = re.match(p1, st)
            if r1:
                r = r1
                st1 = st1 + 1
                type = 1
            else:
                r2 = re.match(p2, st)
                if r2:
                    r = r2
                    st2 = st2 + 1
                    type = 2
            if not r == None: 
                length = int(r.groups()[1])
                value = int(r.groups()[3], 0)
                addr  = int(r.groups()[4], 0)
                lst.append((value, length, addr, type))
        return (lst, st1, st2)
    
    def getLdFromMem(self, begAddr, endAddr, len):
        addres = []
        for st in self.stmt:
            if len > 0:
                p1 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(%d) = LD\((t-1)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$' % len
                p2 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(%d) = LD\((t\d*)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$' % len
            else:
                p1 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(\d*) = LD\((t-1)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
                p2 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* t(\d*):I(\d*) = LD\((t\d*)\) \| (0x[a-f0-9]*) <- LD\((0x[a-f0-9]{8})\) \|(.*)$'
            r = None
            r1 = re.match(p1, st)
            if r1:
                r = r1
            else:
                r2 = re.match(p1, st)
                if r2:
                    r = r2
            if not r == None:
                length = int(r.groups()[1])
                value = int(r.groups()[3], 0)
                addr  = int(r.groups()[4], 0)
                addres.append((value, length, addr))
        ldStmts = []
        for v, l, a in addres:
            if a >= begAddr and a <= endAddr:
                ldStmts.append((v,l,a))
        return ldStmts 

    def getReturnAddr(self):
        if len(self.stmt) == 0:
            return 0
        if self.exitAddr == 0:
            lastSt = self.stmt[-1]
        else:
            lastSt = self.stmt[-2]
        p2 = '^\[STMT\] \d 0x[a-f0-9]* 0x[a-f0-9]* PUT\(64\) <- (0x[a-f0-9]*)(.*)$'
        r = re.match(p2, lastSt)
        if r:
            rddr = int(r.groups()[0], 0)
            return rddr
        return 0

    def printStmts(self):
        print  "(0x%08x) -> 0x%08x -> (0x%08x):" % (self.src, self.addr, self.dst)
        for s in self.stmt:
            print "  %s" % s


class Subroutine(object):
    def __init__(self, addr):
        self.addr = addr
        self.retAddr = 0
        self.callSbs = []
        self.blocks = []
        self.ldValues = []

    def addBlock(self, block):
        self.blocks.append(block)

    def addCallSb(self, sb):
        self.callSbs.append(sb)

    def addIns(self, v, l, a):
        self.ldValues.append((v,l,a))

    def setRetAddr(self, addr):
        self.retAddr = addr

    def getAddr(self):
        return self.retAddr

    def getCallSbs(self):
        return self.callSbs

    def getRetAddr(self):
        return self.retAddr

    def getIns(self):
        return self.ldValues

    def getBlocks(self):
        return self.blocks

    def getInfo(self):
        if len(self.blocks) == 0:
            return "???"
        else:
            block = self.blocks[0]
            return block.getInfo()


def consSubroutineFlow(blocks):
    global targetMemRanges
    subroutines = []
    callStack = []
    callInsStack = []
    insArgs = []
    currAddr = 0
    callAddr = 0
    nextBlock = None
    for block in blocks:
        currAddr = block.getAddr()
        callAddr = block.getDst()
        ldInses = []
        if nextBlock != None and block != nextBlock:
            print "Error: 0x%08x 0x%08x" % (currAddr, nextBlock.getAddr())
        nextBlock = block.getNextBlock()
        
        if len(callStack) == 0:
            sb = Subroutine(currAddr)
            subroutines.append(sb)
            callStack.append(sb)
            callInsStack.append([])
        else:
            sb = callStack[-1]
            insArgs = callInsStack[-1]

        sb.addBlock(block)
        for b,e in targetMemRanges:
            ldStmts = block.getLdFromMem(b, e, 0)
            for v,l,a in ldStmts:
                #a = a-b
                insArgs.append((v,l,a))
        
        retAddr = block.getReturnAddr()
        if retAddr > 0: 
            #and nextBlock.getType() == 1: # Call the next block
            i = len(callStack)
            nextSb = Subroutine(callAddr)
            nextSb.setRetAddr(retAddr)
            subroutines.append(nextSb)
            sb.addCallSb(nextSb)
            callStack.append(nextSb)
            callInsStack.append([])
            r = nextBlock.getRegs()
            if len(insArgs) > 0:
                str = "Ins: "
                for v,l,a in insArgs:
                    str = str + "0x%08x(0x%04x) " % (a, v)
                    nextSb.addIns(v,l,a)
                print str
            print "%02d 0x%08x call 0x%08x 0x%02x (r0=0x%08x, r1=0x%08x, r2=0x%08x, r3=0x%08x, r4=0x%08x, lr=0x%08x pc=0x%08x)" % \
                    (i, currAddr, callAddr, r[14]-currAddr, r[0], r[1], r[2], r[3], r[4], r[14], r[15])
        else:
            if callAddr == sb.getRetAddr():
                callStack.pop()
                callInsStack.pop()
                if len(callInsStack) > 0:
                    callInsStack[-1] = []
                i = len(callStack)
                print "%02d 0x%08x exit 0x%08x " % (i, currAddr, callAddr)

    return subroutines

def consSBGraph(sbs):
    g = nx.DiGraph()
    for sb in sbs:
        srcInfo = sb.getInfo()
        for csb in sb.getCallSbs():
            dstInfo = csb.getInfo()
            ldInses = csb.getIns()
            if len(ldInses) > 0:
                g.add_edge(srcInfo, dstInfo, color='red', weight=12)
            else:
                g.add_edge(srcInfo, dstInfo, color='black', weight=12)
                

    return g

def consBlockFlow(f):
    global oatFiles
    global mainClass
    global mainMethod
    fr = open(f, 'r')
    blocks = []
    oatFiles = []
    blockDict = {}
    block = None
    mainClass = None
    mainMethod = None
    regs = []
    isCreate = False
    for i in range(16):
        regs.append(0)
    for line in fr.readlines():
        preBlock = None
        p1 = '^Try to dump dex file (.*\.dex) (.*)$'
        r1 = re.match(p1, line[:-1])
        if r1:
            dexfile = r1.groups()[0].split('/')[-1]
            if len(oatFiles) > 0:
                oatFiles[-1].addDexFile(dexfile)
            continue
        if isCreate:
            p1 = '^[CALL] \(\d\) \d* \d* (L.*;) (.*)\(\) [A-Z]* isNative=(\d) flag=\d* pArtMethod=(0x[a-f0-9]{8})$'
            r1 = re.match(p1, line[:-1])
            if r1:
                mainClass = r1.groups()[0]
                mainMethod = r1.groups()[1]
                isCreate = False
                continue

        if line[0:6] == '[INFO]':
            p1 = '^\[INFO\] Start the detail analysis \(ret=(0x[a-f0-9]*)\)\.$'
            r1 = re.match(p1, line[:-1])
            if r1:
                isCreate = True
                continue
            p1 = '^\[INFO\] Meet oat file: (.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                oatFile =  OatFile(r1.groups()[0])
                oatFiles.append(oatFile)
                print "Add oat file %s" % r1.groups()[0]
                continue
            p1 = '^\[INFO\] oatdata: (0x[a-f0-9]{8}) - (0x[a-f0-9]{8}) len=(\d*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                oatFiles[-1].addOatData(int(r1.groups()[0], 0), int(r1.groups()[2]))
                print "Add %s oat data %s %s" % (oatFiles[-1].getOatFileName(), r1.groups()[0], r1.groups()[2])
                continue
            p1 = '^\[INFO\] oatexec: (0x[a-f0-9]{8}) - (0x[a-f0-9]{8}) len=(\d*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                oatFiles[-1].addOatExec(int(r1.groups()[0], 0), int(r1.groups()[2]))
                print "Add %s oat exec %s %s" % (oatFiles[-1].getOatFileName(), r1.groups()[0], r1.groups()[2])
                continue
            continue
        if not isCreate:
        #if isCreate:
            continue;
        if line[0:3] == '[I]':
            p1 = '^\[I\] \d Jump from (0x[a-fA-F0-9]{8}).* to (0x[a-zA-Z0-9]{8})(.*)$'
            r1 = re.match(p1, line[:-1])
            if r1:
                src = int(r1.groups()[0], 0)
                dst = int(r1.groups()[1], 0)
                str = r1.groups()[2]
                if block:
                    block.setDst(dst)
                    blocks.append(block)
                    preBlock = block

                block = Block(dst, 0, regs, 0)
                block.setInfo(str.split()[1])
                block.setSrc(src)
                if not dst in blockDict.keys():
                    blockDict[dst] = []
                blockDict[dst].append(block)
                if not preBlock == None:
                    preBlock.setNextBlock(block)
        elif line[0:3] == '[R]':
            p1 = '^\[R\] \d Jump from (0x[a-fA-F0-9]{8})(.*) to (0x[a-zA-Z0-9]{8}).*$'
            r1 = re.match(p1, line[:-1])
            if r1:
                src = int(r1.groups()[0], 0)
                str = r1.groups()[1]
                dst = int(r1.groups()[2], 0)
                if not block:
                    block = Block(src, 0, regs, 0)
                    block.setSrc(0)
                    block.setInfo(str.split()[1])
                block.setDst(dst)
                preBlock = block
                blocks.append(block)
                src = block.getAddr() # Library codes (occupy multiple basic blocks)
                block = Block(dst, 1, regs, 1)
                block.setSrc(src)
                if not dst in blockDict.keys():
                    blockDict[dst] = []
                blockDict[dst].append(block)
                preBlock.setNextBlock(block)
        elif line[0:3] == '[S]':
            p1 = '^\[S\] \d Jump from (0x[a-fA-F0-9]{8}).* to (0x[a-zA-Z0-9]{8}).*$'
            r1 = re.match(p1, line[:-1])
            if r1:
                src = int(r1.groups()[0], 0)
                dst = int(r1.groups()[1], 0)
                if block:
                    block.setDst(dst)
                    blocks.append(block)
                    preBlock = block
                block = Block(dst, 1, regs, 1)
                block.setSrc(src)
                if not dst in blockDict.keys():
                    blockDict[dst] = []
                blockDict[dst].append(block)
                if not preBlock == None:
                    preBlock.setNextBlock(block)
        else:
            if line[0:6] == '[STMT]':
                p1 = '^\[STMT\] \d 0x[0-9a-f]* 0x[a-f0-9]* if\(t(\d*)\) goto (0x[a-zA-Z0-9]{8}) \| (\d*)$'
                r1 = re.match(p1, line[:-1])
                if r1:
                    caddr = int(int(r1.groups()[1]), 0)
                    block.addExit(caddr)
                    continue

                p2 = '^\[STMT\] \d 0x[0-9a-f]* 0x[a-f0-9]* PUT\((\d*)\) <- t\d*:I32 \| \((0x[a-zA-Z0-9]*)\)$'
                r2 = re.match(p2, line[:-1])
                if not r2:
                    p2 = '^\[STMT\] \d 0x[0-9a-f]* 0x[a-f0-9]* PUT\((\d*)\) <- (0x[a-zA-Z0-9]*):I32$'
                    r2 = re.match(p2, line[:-1])
                if r2:
                    r = (int(r2.groups()[0], 0) - 8)/4
                    if r >= 0 and r < 16:
                        regs[r] = int(r2.groups()[1], 0)
                if not block == None:
                    block.addStmt(line[:-1])

    blocks.append(block)
    fr.close()
    if len(blocks) > 0:
        print "number=%d from=0x%08x to=0x%08x" % (len(blocks), blocks[0].getAddr(), blocks[-1].getAddr())
    return (blocks, blockDict)

def consGraph(blocks):
    g = nx.DiGraph()
    i = 1
    while i + 1 < len(blocks):
        preBlock = blocks[i-1]
        curBlock = blocks[i]
        nxtBlock = blocks[i+1]
        srcAddr  = curBlock.getSrc()
        curAddr  = curBlock.getAddr()
        dstAddr  = curBlock.getDst()
        if not srcAddr == preBlock.getAddr():
            print "Error: %04d src = 0x%08x 0x%08x dst = 0x%08x" % (i, src, preBlock.getAddr(), dst)
            assert(0)
        if not dstAddr == nxtBlock.getAddr():
            print "Error: %04d src = 0x%08x dst = 0x%08x 0x%08x" % (i, src, dst, nxtBlock.getAddr())
            assert(0)
        nodes = g.nodes()
        src = preBlock.getInfo()
        cur = curBlock.getInfo()
        dst = nxtBlock.getInfo()
        # 0: Library code block 1: VM code block
        if not src in nodes:
            if preBlock.isInVM():
                g.add_node(src, color='black', type=1, style='filled',weight=2, block=preBlock)
            else:
                if len(nodes) == 0:
                    #g.add_node(src, color='blue', style='filled', weight=6, type=0, block=preBlock)
                    g.add_node(src, color='black', type=0, style='filled', weight=14, block=preBlock)
                else:
                    #g.add_node(src, color='blue', type=0, block=preBlock)
                    g.add_node(src, color='black', type=0, style='filled', weight=14, block=preBlock)
        if not cur in nodes:
            if curBlock.isInVM():
                g.add_node(cur, color='black', type=1, style='filled', weight=14, block=curBlock)
            else:
                #g.add_node(cur, color='blue', type=0, block=curBlock)
                g.add_node(cur, color='black', type=0, style='filled', weight=14, block=curBlock)
        if not dst in nodes:
            if nxtBlock.isInVM():
                g.add_node(dst, color='black', type=1, style='filled', weight=14, block=nxtBlock)
            else:
                if (i+2) == len(blocks):
                    #g.add_node(dst, color='blue', style='filled', type=0, block=nxtBlock)
                    g.add_node(dst, color='black', type=0, style='filled', weight=14, block=nxtBlock)
                    if curBlock.getReturnAddr() > 0:
                        g.add_edge(cur, dst, color='red', weight=14)
                    else:
                        g.add_edge(cur, dst, color='black', weight=12)
                    print "last1 %s" % dst
                else:
                    #g.add_node(dst, color='blue', type=0, block=nxtBlock)
                    g.add_node(dst, color='black', type=0, style='filled', weight=14, block=curBlock)
        if (i+2) == len(blocks):
            print "last %s %d" % (dst, nxtBlock.isInVM())
                    
        if curBlock.getReturnAddr() > 0:
            g.add_edge(cur, dst, color='red', weight=14)
        else:
            g.add_edge(cur, dst, color='black', weight=12)
        i = i+1
    print "Full Graph: nodes=%d edges=%d" % (g.number_of_nodes(), g.number_of_edges())
    return g

# reduce the edge that is from the node with out_degree==1 to the node with in_degree==1
def simplifyGraphEdge(sg, bd):
    global targetMemRanges
    while True:
        rm_nodes = 0
        for e in sg.edges():
            f = e[0]
            t = e[1]
            if sg.out_degree(f) == 1 and sg.in_degree(t) == 1:
                if sg.node[t]['type'] == 1:
                    srcBlock = sg.node[f]['block']
                    dstBlock = sg.node[t]['block']
                    dstAddr  = dstBlock.getAddr()
                    nxtNodes = sg.successors(t)
                    for n in nxtNodes:
                        sg.add_edge(f, n, weight=12)
                    srcBlock.addStmt("Jump to 0x%08x" % dstAddr)
                    for st in dstBlock.getStmt():
                        srcBlock.addStmt(st)
                    sg.remove_node(t)
                    rm_nodes = rm_nodes + 1
        if rm_nodes == 0:
            break
    print "Edge-simplified Graph: nodes=%d edges=%d" % (sg.number_of_nodes(), sg.number_of_edges())
    
    for beg, end in targetMemRanges:
        addrLens = {}
        ldBlocks = {}
        for node in sg.nodes():
            block = sg.node[node]['block']
            ldStmts = block.getLdFromMem(beg, end, 0)
            if len(ldStmts) > 0:
                sg.node[node]['color'] = 'red'
                sg.node[node]['style'] = 'filled'
                sg.node[node]['type'] = 2
                addres = []
                for v,l,a in ldStmts:
                    addres.append(a)
                    addrLens[a] = l
                str = "0x%08x(%02d %02d): " % (block.getAddr(), sg.in_degree(node), sg.out_degree(node))
                for a in sorted(addres):
                    str = str + "0x%02x:I%d " % (a-beg, addrLens[a])
                print str
    for beg, end in targetMemRanges:
        print "0x%08x - 0x%08x" % (beg, end)

    for n in sg.nodes():
        if sg.node[n]['type'] == 1:
            if sg.in_degree(n) == 1 and sg.out_degree(n) == 1:
                preNode = sg.predecessors(n)[0]
                nxtNode = sg.successors(n)[0]
                sg.remove_node(n)
                sg.add_edge(preNode, nxtNode, weight=12)
    return sg

# Draw the CFG of blocks according to the DiGraph
def drawGraph(g, name):        
    A = nx.to_agraph(g)
    A.draw(name+'.pdf', format='pdf', prog='dot') 
    return

    all_weights = []
    all_nodes = []
    #4 a. Iterate through the graph nodes to gather all the weights
    for (node1,node2,data) in g.edges(data=True):
        print data
        all_weights.append(data['weight']) 
        #we'll use this when determining edge thickness
        #4 b. Get unique weights
        unique_weights = list(set(all_weights))
        #4 c. Plot the edges - one by one!
        for weight in unique_weights:
            #4 d. Form a filtered list with just the weight you want to draw
            weighted_edges = [(node1,node2) for (node1,node2,edge_attr) in g.edges(data=True) if edge_attr['weight']==weight]
            #4 e. I think multiplying by [num_nodes/sum(all_weights)] makes the graphs edges look cleaner
            width = weight*len(node_list)*3.0/sum(all_weights)
            nx.draw_networkx_edges(g,pos,edgelist=weighted_edges,width=width)
    #Plot the graph
    plt.axis('off')
    plt.title('How often have they played each other?')
    plt.savefig(name+".png") 
    plt.show()


# Analysis the blocks with Ist_Load statements
def analysisLoadBlocks(blocks, gh):
    global targetMemRanges
    targetMemRanges = []
    ldAddres = {}
    firstBlock = 0
    lastBlock = 0
    # Identify the blocks with Ist_Load statements
    for block in blocks:
        (ldstmts, n1, n2) = block.getLoadStmts(0)
        # n1==0 means no direct load statement
        if len(ldstmts) > 0:# and n1 == 0: 
            for v,l,a,t in ldstmts:
                if not a in ldAddres.keys():
                    ldAddres[a] = []
                ldAddres[a].append((l/8, t))
    
    # Construct memory ranges for the source address of Ist_Load:I16 statements
    memRanges = []
    for addr in sorted(ldAddres.keys()):
        i = 0
        (l,t) = ldAddres[addr][0]
        end = addr + l - 1
        while i < len(memRanges):
            (b,e,type) = memRanges[i]
            if addr <= e + 1 and end > e:
                type = type | t
                memRanges[i] = (b, end, type)
                break
            i = i + 1
        if i == len(memRanges):
            memRanges.append((addr, end, t))


    # Look up the target memory range that stores the obfuscated instructions
    targetStart = 0
    targetEnd = 0
    targetSize = 0
    for b,e,t in memRanges:
        size = e-b+1
        print "0x%08x - 0x%08x %02d %02d" % (b, e, size, t)
        if size < 94 or size > 94:
            continue
        if targetSize < size:
            targetSize = size
            targetStart = b
            targetEnd = e
        
        targetMemRanges.append((b, e))
    print "Target range: 0x%08x - 0x%08x size=%d" % (targetStart, targetEnd, targetSize)
    if len(targetMemRanges) == 0:
        return (None, None)
    # Identify the Instruction loading block(s) that load data from the target memory range
    # And identify the block execution paths that are from the instruction loading block(s)
    i = 0
    depth = 10
    loadInfoDict = {}
    while i+depth < len(blocks):
        curB = blocks[i]
        nxtB = blocks[i+1]
        if curB.isInVM():
            (ldstmts, n1, n2) = curB.getLoadStmts(0)
            for v,l,a,t in ldstmts:
                if a >= targetStart and a < targetEnd:
                    if firstBlock == 0:
                        firstBlock = i
                    lastBlock = i
                    offset = a - targetStart
                    regs = nxtB.getRegs()
                    addr = nxtB.getAddr()
                    str = "%03x 0x%08x 0x%04x (0x%08x, 0x%08x, 0x%08x, 0x%08x 0x%08x, 0x%08x): 0x%08x->0x%08x" \
                            % (offset, a, v, regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], curB.getAddr(), addr)
                    path = []
                    j = 1
                    nxtBransh = 0
                    while j <= depth:
                        tmp = blocks[i+j].getDst()
                        if tmp == curB.getAddr():
                            break
                        if gh.out_degree("0x%08x" % blocks[i+j].getAddr()) > 1:
                            break 
                        j = j + 1
                    str = str + ("-%d->0x%08x" % (j, tmp))
                    if not a in loadInfoDict.keys():
                        loadInfoDict[a] = []
                    loadInfoDict[a].append(str)
        i = i + 1
    for key in sorted(loadInfoDict.keys()):
        for str in loadInfoDict[key]:
            print str
    return (firstBlock, lastBlock)

def parseDexPacked(dex):
    global mainClass
    global mainMethod
    nxtCodeOff = 0
    print "Parse Dex file: %s for %s %s" % (dex, mainClass, mainMethod)
    if mainClass == None or mainMethod == None:
        return (0, 0, 0)
    d = dvm.auto(dex)
    if d == None:
        return (0, 0, 0)
    for clazz in d.get_classes():
        if not clazz.get_name() == mainClass:
            continue
        for mth in clazz.get_methods():
            off = mth.get_code_off()
            len = mth.get_length()
            insOff = off+16
            insEnd = off+16 + (len-1)*2
            diff = off - nxtCodeOff
            if mth.get_name() == mainMethod:
                begin = int(dex.split('-')[0], 0)
                mth.pretty_show()
                print "0x%08x, 0x%08x, %d %s" % (begin, nxtCodeOff, len, mainMethod)
                return (begin, nxtCodeOff, len)
            nxtCodeOff = insEnd + 2
            print "0x%08x 0x%08x-0x%08x (0x%08x): %2d %2d %s" % (off, insOff, insEnd,  nxtCodeOff, len, diff, mth.get_name())
    return (0, 0, 0)

def minPrePattern(blocks):
    global oatFiles
    dexBegin = 0
    oatData = 0
    oatDataLen = 0
    dexFiles = []
    off = 0
    ll  = 0
    for oatFile in oatFiles:
        print oatFile.getOatFileName()
        if oatFile.getOatFileName() == 'classes.oat':
            (oatData, oatDataLen) = oatFile.getOatData()
            break

    if oatData > 0:
        dexFiles = oatFile.getDexFiles()
        for dexFile in dexFiles:
            (dexBegin, off, ll) = parseDexPacked(dexFile)
            if dexBegin > 0:
                break
    off = 0
    print dexCodeItem.keys()
    for block in blocks:
        (ldstmts, n1, n2) = block.getLoadStmts(0)
        if len(ldstmts) > 0:
            for v,l,a,t in ldstmts:
                if off == 0:
                    off = a-dexBegin
                off = a-dexBegin-off
                if off1 in dexCodeItem.keys():
                    print "0x%08x->0x%08x: 0x%08x(%08d) <- LD(0x%08x/0x%08x):I%02d %s = %d" % (block.getAddr(), block.getDst(), v, v, a, a-dexBegin, l, dexCodeItem[off1], v)
                else:
                    print "0x%08x->0x%08x: 0x%08x(%08d) <- LD(0x%08x/0x%08x):I%02d" % (block.getAddr(), block.getDst(), v, v, a, a-dexBegin, l)

if __name__ == "__main__":
    (bbs,bd) = consBlockFlow(sys.argv[1])
    
    fg = consGraph(bbs)
    (i, j) = analysisLoadBlocks(bbs, fg)
    
    sbs = consSubroutineFlow(bbs)
    sbg = consSBGraph(sbs)
    
    drawGraph(sbg, "sbg")
    drawGraph(fg, "full_flow")
    sg = simplifyGraphEdge(fg, bd)
    drawGraph(sg, "simply_flow")
    #minPrePattern(bbs[:i+1])
    #parseTrace(sys.argv[1])
