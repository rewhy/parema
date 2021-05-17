#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2012, Axelle Apvrille <aafortinet at gmail.com>
#                     Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import struct
from optparse import OptionParser
from androguard.core import androconf
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes.apk import *


def disassemble(dex):
    d = dvm.auto(dex)
    if d == None:
        print "Parse Dex file error"
        return
    for clazz in d.get_classes():
        if not "Activity" in clazz.get_name():
            continue
        print clazz.get_name()
        for mth in clazz.get_methods():
            if not mth.get_name() == 'onCreate':
                continue
            #mth.pretty_show()
            #return
            print "mth=%s, codeSize=%d, codeOff=0x%x" % (mth.get_name(), mth.get_length(), mth.get_code_off())
            dalvikCode = mth.get_code()
            #print dalvikCode
            dCode = dalvikCode.get_bc()
            #print dCode
            #ins_lengths = []
            for ins in dCode.get_instructions():
                print "0x%02x:%d" % (ins.get_op_value(), ins.get_length())
                #ins_lengths.append(ins.get_length()/2)
                #print "%d %s %s" % (ins.get_length(), ins.get_name(), ins.get_output())
                #print "%s %s" % (ins.get_name(), ins.get_output())
                #print "%s %s %s" % (ins.get_raw(), ins.get_name(), ins.get_output())
            # print "0x%x" % mth.get_code_off()
            # print mth.get_code()
            return

if __name__ == "__main__":
    disassemble(sys.argv[1])
