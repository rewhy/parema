import os
import re
import sys
import struct
import hashlib
import base64
import Queue
import signal
import subprocess
import commands
from collections import deque
from subprocess import call, Popen, PIPE


import zz3

satisfied_constraints_hashes = set()
input_index = 1

def get_constraints(bfile):
    constrants = []
    with open(bfile) as f:
        #branch: TAKEN(32to1(1Uto32(CmpNE32(INPUT:32(0),FIX:32(1)))))
        constraints = [m.group(1) for m in (re.match('^branch: (.+)$', line) for line in f) if m]
    f.close()
    return constraints

def create_constraint_groups(constraints):
    global satisfied_constraints_hashes
    constraint_groups = []
    execution_path = []

    for con in constraints:
        taken = re.search(r'^TAKEN.+', con)
        tmp = execution_path[:]
        # print execution_path
        if taken:
            con = con[6:-1]
            execution_path.append(con)
            tmp.append('Not_(%s)' % con)
        else:
            con = con[10:-1]
            tmp.append(con)
        # Calculate hash of this branch constraint
        con_hash = hashlib.md5(con).hexdigest()
        
        # Add the executed path
        if con_hash not in satisfied_constraints_hashes:
            for c in tmp:
                print  "branch: %s" % c
            constraint_groups.append(tmp)
            satisfied_constraints_hashes.add(con_hash)
    return constraint_groups

def get_constraint_groups(bfile):
    cons = get_constraints(bfile)
    con_groups = create_constraint_groups(cons)
    return con_groups


def generate_one_new_input(offsets_values_sizes):
    global input_index
    values = {}
    number = 0
    pack_format_by_size = {8:'<B',16:'<H',32:'<I'}
    
    new_file = "input_%d.txt" % input_index
    print "Generate new input file: %s" % new_file
    with open(new_file, 'w+b') as f:
        if offsets_values_sizes != None:
            for offset, value, size in offsets_values_sizes:
                if offset > number:
                    number = offset
                values[offset] = (size, value)
                print "%d:B%d:%d" % (offset, size, value)
            i = 0
            while i <= number:
                size, value = values[i]
                f.write(struct.pack(pack_format_by_size[size], value))
                i += 1
        else:
            print "Finish using file %s" % new_file
    f.close()
    input_index += 1
    os.system("adb push %s /data/local/tmp/fuzz/" % new_file)

def generate_new_inputs(index):
    global input_index
    fuzzing_inputs = deque()
    bfile = "output_%d.txt" % index
    #os.system("adb pull /data/local/tmp/fuzz/%s" % bfile)
    con_groups = get_constraint_groups(bfile)
    # each con_group represents one execution path
    for con_group in con_groups:
        i = 0
        print "Solve path %d:" % input_index
        for c in con_group:
            print "br: %s" % c
        #print con_group
        offsets_values_sizes = zz3.solve(con_group, index)
        if offsets_values_sizes == None:
            generate_one_new_input(None)
        if len(offsets_values_sizes) > 0:
            generate_one_new_input(offsets_values_sizes)
            i += 1

def getRuningInfo():
    index = 0
    os.system("adb shell rm -rf /data/local/tmp/fuzz/*")
    os.system("adb logcat -c")
    adb = Popen(["adb", "logcat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    finiLine = r'(.*)Finish the (\d+) iterative execution.'
    while True:
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
        try:
            finiObj  = re.search( finiLine, logcatInput, re.M|re.I )
        except:
            break
        if finiObj:
            print finiObj.group()[:-1]
            index = int(finiObj.group(2))
            generate_new_inputs(index)

if __name__ == "__main__":
    if(len(sys.argv) == 1):
        getRuningInfo()
    elif(len(sys.argv) == 2):
        generate_new_inputs(int(sys.argv[1]))
