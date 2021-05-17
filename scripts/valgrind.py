import os
import subprocess
import re
import hashlib
import base64

X86Condcode = {
        0 : 'CmpEQ',
        1 : 'CmpNE',
        2 : 'CmpGEU',
        3 : 'CmpLTU',
        8 : 'CmpGTU',
        9 : 'CmpLEU',
        10 : 'CmpGES',
        11 : 'CmpLTS',
        12 : 'CmpGTS',
        13 : 'CmpLES'
        }


class Operation:
    def __init__(self, operation, first_op, second_op, third_op, dest_op):
        self.operation = operation
        self.first_op = first_op
        self.second_op = second_op
        self.third_op = third_op
        
        self.dest_op = dest_op

    def to_z3(self):
        return getattr(self, self.operation)()
    
    def z3_binop(self, op):
        return '%s = %s %s %s' % (self.dest_op, self.first_op, op, self.second_op)
    
    def z3_binop_unsigned(self, op):
        return '%s = %s(%s, %s)' % (self.dest_op, op, self.first_op, self.second_op)
    
    def z3_cmp(self, op):
        if self.dest_op:
            return 'Not(%s %s %s)' % (self.first_op, op, self.second_op)
        else:
            return '%s %s %s' % (self.first_op, op, self.second_op)
    
    def z3_cmp_unsigned(self, op):
        if self.dest_op:
            return 'Not(%s(%s, %s))' % (op, self.first_op, self.second_op)
        else:
            return '%s(%s, %s)' % (op, self.first_op, self.second_op)
        
    def Not(self):
        return "%s = ~%s" % (self.dest_op, self.first_op)
    def Fix(self):
        return "%s = BitVecVal(%s, %s)" % (self.dest_op, self.first_op, self.second_op)
    def Str(self):
        opts = ''
        i = 0
        s = self.first_op
        l = int(self.second_op)/16

        while i < l:
            if(len(s) > i):
                opts += "ic_%d_%d = BitVecVal(%d, %s)\n" % (i, self.third_op, ord(s[l-i-1]), self.second_op)
            else:
                opts += "ic_%d_%d = BitVecVal(0, %s)\n" % (i, self.third_op, self.second_op)
            i += 1;
        i -= 1
        opts += "%s = ic_%d_%d" % (self.dest_op, i, self.third_op)
        while i >= 0:
            opts += " | (ic_%d_%d << %d)" % (i, self.third_op, (l-i-1)*16 )
            i -= 1
        opts += "\n"
				#print "%s = %s:%s" % (self.dest_op, self.first_op, self.second_op)
        return opts

    def Add(self):
        return self.z3_binop('+')
    def Sub(self):
        return self.z3_binop('-')
    def Mul(self):
        return self.z3_binop('*')
    def Or(self):
        return self.z3_binop('|')
    def And(self):
        return self.z3_binop('&')
    def Xor(self):
        return self.z3_binop('^')
    def Shl(self):
        return self.z3_binop('<<')
    def Shr(self):
        return self.z3_binop('>>')
    
    def To(self):
        ext_bit = int(self.third_op) - int(self.second_op)
        if ext_bit > 0:
            return "%s = ZeroExt(%d, %s)" % (self.dest_op, ext_bit, self.first_op)
        else:
            return "%s = Extract(%d, 0, %s)" % (self.dest_op, int(self.third_op)-1, self.first_op)
        
    def Cas(self, ext1, ext2):
        if ext1 > 0 and ext2 > 0:
            return "%s = ZeroExt(%d, %s) | (ZeroExt(%d, %s) << %s)" % (self.dest_op, ext1, self.first_op, \
                    ext2, self.second_op, self.third_op)
        else:
            if ext1 > 0:
                return "%s = ZeroExt(%d, %s) | (%s << %s)" % (self.dest_op, ext1, self.first_op, \
                        self.second_op, self.third_op)
            else:
                return "%s = %s | (ZeroExt(%d, %s) << %s)" % (self.dest_op, self.first_op, \
                        ext2, self.second_op, self.third_op)
        
    def SetElem(self, size):
        ext = 64 - size
        if int(self.second_op) > 0:
            return "%s = (%s & (~(ZeroExt(%d, c_%d) << (%d * %s)))) | (ZeroExt(%d, %s) << ( %d * %s))" % (self.dest_op,
                    self.first_op, ext, size, size, self.second_op, ext, self.third_op, size, self.second_op)
        else: 
            return "%s = (%s & (~(ZeroExt(%d, c_%d)))) | (ZeroExt(%d, %s))" % (self.dest_op,
                    self.first_op, ext, size, ext, self.third_op)
            
    def GetElem(self, size):
        end = int(self.second_op) - size
        beg = int(self.second_op) - 1
        return "%s = Extract(%d, %d, %s)" % (self.dest_op, beg, end, self.first_op)
    
    def CmpEQ(self):
        return self.z3_cmp('==')
    def CmpNE(self):
        return self.z3_cmp('!=')
    def DivModS(self):
        return self.z3_binop('/')
    def CmpLTS(self):
        return self.z3_cmp('<')
    def CmpLES(self):
        return self.z3_cmp('<=')
    def CmpGTS(self):
        return self.z3_cmp('>')
    def CmpGES(self):
        return self.z3_cmp('>=')
    
    def DivModU(self):
        return self.z3_binop_unsigned('UDiv')
    # Sar32(first_op, second_op, third_op) 
    # -> dist_op = LShR(first_op, second_op) & ~((~0x0) << thrid_op)
    def Sar(self, size):
        #return self.z3_binop_unsigned('LShR')
        if int(self.second_op) == 0:
            str1 = self.first_op
        else:
            str1 = "LShR(%s, %s)" % (self.first_op, self.second_op)
            
        if int(self.third_op) == size:
            str2 = ""
        else:
            str2 = "& (~(c_%s << %d))" % (self.third_op, size)
        return "%s = Extract(%d, 0, %s)" % (self.dest_op, size-1, str1)
            #return "%s = LShR(%s, %s) & (~((c_%s) << %d))" % (self.dest_op, self.first_op, self.second_op, self.third_op, size)
    def CmpLTU(self):
        return self.z3_cmp_unsigned('ULT')
    def CmpLEU(self):
        return self.z3_cmp_unsigned('ULE')
    def CmpGTU(self):
        return self.z3_cmp_unsigned('UGT')
    def CmpGEU(self):
        return self.z3_cmp_unsigned('UGE')
        '''	
                c = a/b: 64to32(DivModS64to32(32HLto64(Sar32(a,31), a), b))
        '''
    def HLto(self):
        return '%s = %s' % (self.dest_op, self.second_op)

