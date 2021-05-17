import re
import sys
import commands
from pyparsing import Literal, Word, alphanums, nums, Forward, ZeroOrMore

import valgrind

var_cnt = 0
size_by_var = None
offset_by_var = None
constant_by_var = None
string_by_var = None
constraint_by_var = None

valgrind_operations = None

signedness_by_var = None


def new_var(size):
    global var_cnt, size_by_var
    var_cnt += 1
    var = "_%d" % var_cnt
    size_by_var[var] = size
    return var

def update_var_size_cast(var, size, signedness):
    pass


#def add_operation(opt, opd1, opd2, dst_opd, con):
def add_operation(operation, first_operand, second_operand, third_operand, dest_operand, constraint):
    global valgrind_operations, constraint_by_var
    valgrind_operations.append((operation, first_operand, second_operand, third_operand, dest_operand))
    constraint_by_var[dest_operand] = constraint

def parse_function(s, loc, toks):
    global constraint_by_var, offset_by_var, signedness_by_var, size_by_var, constant_by_var, string_by_var

    operation = toks[0]
    string = ''.join(toks)
    #print "str: %s"%string
    m = re.match('^INPUT:(\d+)\((\d+)\)$', string)
    if m:
        newvar = new_var(int(m.group(1)))
        constraint_by_var[newvar] = string
        offset_by_var[newvar] = int(m.group(2))
        signedness_by_var[newvar] = 'S'
        return

    m = re.match('^FIX:(\d+)\((\d+)\)$', string)
    if m:
        newvar = new_var(int(m.group(1)))
        constraint_by_var[newvar] = string
        constant_by_var[newvar] = int(m.group(2))
        signedness_by_var[newvar] = 'S'
        add_operation('Fix%s'%m.group(1), m.group(2), None, None, newvar, string)			
        return
    
    m = re.match('^STR:(\d+)\((.*)\)$', string)
    if m:
        newvar = new_var(int(m.group(1)))
        constraint_by_var[newvar] = string
        string_by_var[newvar] = m.group(2)
        signedness_by_var[newvar] = 'V'
        add_operation('Str%s'%m.group(1), m.group(2), None, None, newvar, string)			
        return
    '''
    m = re.match('^Cas(\d+)_', operation)
    if m:
        dest_operand = new_var()
        constraint_by_var[dest_operand] = string
        print "11111111111111111111111111111111"
    '''
    for var, constraint in constraint_by_var.iteritems():
        # For opt(s)
        print "str: %s\ncon: %s" % (string, constraint)
        m = re.match('^[a-zA-Z0-9:_]+\(%s\)$'%re.escape(constraint), string)
        if m:
            mm = re.match('^LDle:(\d+)$', operation)
            if mm:
                update_var_size_ldle(var, int(mm.group(1)))
                add_operation(operation, var, None, None, var, string)
                return
            mm = re.match('^(\d+)([U|S])to(\d+)$', operation)
            if mm:
                update_var_size_cast(var, int(mm.group(1)), mm.group(2))
                dest_operand = new_var(int(mm.group(3)))
                add_operation("To%s"%mm.group(3), var, mm.group(1), mm.group(3), dest_operand, string)
                return
            mm = re.match('^(\d+)to(\d+)$', operation)
            if mm:
                dest_operand = new_var(int(mm.group(2)))
                add_operation("To%s"%mm.group(2), var, mm.group(1), mm.group(2), dest_operand, string)
                return
            add_operation(operation, var, None, None, var, string)
            return
        # For opt(s,d,d)
        m = re.match('^Sar(\d+)_\(%s,(\d+),(\d+)\)$'%re.escape(constraint), string)
        if m:
            dest_operand = new_var(int(m.group(1)))
            #shift_by_var[var] = int(m.group(1))
            #mask_by_var[var] = int(m.group(2))
            add_operation(operation, var, m.group(2), m.group(3), dest_operand, string)
            return
        # For opt(s,d)
        m = re.match('^[a-zA-Z]+(\d+)\(%s,(\d+)\)$'%re.escape(constraint), string)
        if m:
            dest_operand = new_var(int(m.group(1)))	
            add_operation(operation, var, m.group(2), None, dest_operand, string)
            return		
        
        m = re.match('^GetElem(\d+)x(\d)\(%s,(\d+)\)$'%re.escape(constraint), string)
        if m:
            dest_operand = new_var(int(m.group(1)))	
            add_operation(operation, var, m.group(3), None, dest_operand, string)
            return		
        
        # For opt(d,s)
        m = re.match('^[a-zA-Z]+(\d+)\((\d+),%s\)$'%re.escape(constraint), string)
        if m:
            #resize = realsize_by_var.get(var, size_by_var[var])
            dest_operand = new_var(int(m.group(1)))
            # size_by_var[dest_operand] = realsize_by_var.get(var, size_by_var[var])			
            #signedness_by_var[dest_operand] = signedness_by_var[var]
            add_operation(operation, m.group(2), var, None, dest_operand, string)
            return
        
        # For opt(d,d,s,d)
        #m = re.match('^x86g_calculate_condition\((\d+),\d+,%s,(\d+)\)$'%re.escape(constraint), string)
        m = re.match('^armg_calculate_condition\((\d+),\d+,%s,(\d+)\)$'%re.escape(constraint), string)
        if m:
            add_operation(operation, int(m.group(1)), var, None, int(m.group(2)), string)
            return
	
	var3 = None
	for var1,constraint1 in constraint_by_var.iteritems():
            for var2,constraint2 in constraint_by_var.iteritems():
                #print "str: %s\nco1: %s\nco2: %s" % (string, constraint1, constraint2)
                # For opt(s,s)
                m = re.match('^[a-zA-Z0-9:_]+\(%s,%s\)$'%(re.escape(constraint1),re.escape(constraint2)), string)
                if m:
                    mm = re.match('\d+HLto\d+', operation)
                    if mm:
                        dest_operand = var2
                        add_operation(operation, var1, var2, var3, dest_operand, string)
                        return
                    
                    mm = re.match('^Cas(\d+)_', operation)
                    if mm:
                        dest_operand = new_var(int(mm.group(1)))
                        var3 = str(size_by_var[var1])
                        add_operation(operation, var1, var2, var3, dest_operand, string)
                        return
                    mm = re.match('^CmpEQ(\d+)', operation)
                    if mm:
                        dest_operand = new_var(int(mm.group(1)))
                        var3 = str(size_by_var[var1])
                        add_operation(operation, var1, var2, var3, dest_operand, string)
                        return
                    #resize = realsize_by_var.get(var1, size_by_var[var1])
                    resize = size_by_var[var1]
                    dest_operand = new_var(resize)
                    signedness_by_var[dest_operand] = 'S'
                    add_operation(operation, var1, var2, var3, dest_operand, string)
                    return
                # For opt(s,%d,s)
                m = re.match('^SetElem(\d+)x(\d)\(%s,(\d+),%s\)$'%(re.escape(constraint1),re.escape(constraint2)), string)
                if m:
                    dest_operand = new_var(64)
                    add_operation(operation, var1, m.group(3), var2, dest_operand, string)
                    return
        print "Unknown %s" % string
        #sys.exit(0)

def init_global_vars():
    global constraint_by_var, offset_by_var, signedness_by_var, size_by_var, constant_by_var, string_by_var
    constraint_by_var = {}
    offset_by_var = {}
    signedness_by_var = {}
    size_by_var = {}
    constant_by_var = {}
    string_by_var = {}

def parse_constraint_group(con_group):
    global valgrind_operations, size_by_var, offset_by_var
    init_global_vars()

    lparen = Literal("(")
    rparen = Literal(")")
    func = Word(alphanums, alphanums+":_")
    integer = Word(nums)

    expression = Forward()

    arg = expression | func | integer
    args = arg + ZeroOrMore(","+arg)

    expression << func + lparen + args + rparen
    expression.setParseAction(parse_function)

    valgrind_operations_group = []

    for con in con_group:
        valgrind_operations = []
        #print "con: %s" % con
        expression.parseString(con)
        valgrind_operations_group.append(valgrind_operations)
    #print valgrind_operations_group
    return (valgrind_operations_group, size_by_var, offset_by_var, constant_by_var, string_by_var)

##############################################################################


z3_prologue = '''
from z3 import *

s = Solver()
'''

z3_epilogue = '''
if s.check() == sat:
        # print s
        print s.model()
'''

def assign(lhs_op, rhs_op, oldsize_newsize_and_signedness, z3_operations):
    oldsize, newsize, signedness = oldsize_newsize_and_signedness
    if newsize > oldsize:
        if signedness == 'S':
            z3_operations.append('%s = SignExt(%d, %s)' % (lhs_op, newsize-oldsize, rhs_op))
        else:
            z3_operations.append('%s = ZeroExt(%d, %s)' % (lhs_op, newsize-oldsize, rhs_op))
    else:
        z3_operations.append('%s = Extract(%d, %d, %s)' % (lhs_op, newsize-1, 0, rhs_op))

def translate_valgrind_operations_group(valgrind_operations_group):
    z3_operations = []
    z3_constraints = []
    # print "oprations group:"
    # print valgrind_operations_group
    str_id = 0
    for valgrind_operations in valgrind_operations_group:
        for i, (operation, first_op, second_op, third_op, dest_op) in enumerate(valgrind_operations):	
            if operation == 'assign':
                assign(first_op, second_op, dest_op, z3_operations)
                continue
            
            # m = re.match('(Add|Sub|Mul|Shl|Shr|Sar|Div(?:Mod)?[S|U]|Or|And|Xor)\d+', operation)
            m = re.match('(Fix|Add|Sub|ITE|Shl|Shr|Sar|Cas|Div(?:Mod)?[S|U]|Or|And|Xor|Not|To|Str)(\d+)', operation)
            if m:
                if m.group(1) == 'Sar':
                    size = int(size_by_var[dest_op])
                    z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, third_op, dest_op).Sar(size))
                elif m.group(1) == 'Fix':
                    z3_operations.append(valgrind.Operation(m.group(1), first_op, m.group(2), third_op, dest_op).to_z3())
                elif m.group(1) == "Str":
                    z3_operations.append(valgrind.Operation(m.group(1), first_op, m.group(2), str_id, dest_op).to_z3())
                    str_id += 1
                elif m.group(1) == 'Cas':
                    ext1 = int(m.group(2)) - int(size_by_var[first_op])
                    ext2 = int(m.group(2)) - int(size_by_var[second_op])
                    z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, third_op, dest_op).Cas(ext1, ext2))
                elif m.group(1) in ['Shl', 'Shr', 'Sar']:
                    size_by_var[second_op] = 0
                    z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, third_op, dest_op).to_z3())
                else:
                    z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, third_op, dest_op).to_z3())
                continue

            m = re.match('\d+HLto\d+', operation)
            if m:
                z3_operations.append(valgrind.Operation('HLto', first_op, second_op, third_op, dest_op).to_z3())
                continue

            m = re.match('SetElem(\d+)x(\d)', operation)
            if m:
                z3_operations.append(valgrind.Operation('SetElem', first_op, second_op, third_op, dest_op).SetElem(int(m.group(1))))
                continue

            m = re.match('GetElem(\d+)x(\d)', operation)
            if m:
                z3_operations.append(valgrind.Operation('GetElem', first_op, second_op, third_op, dest_op).GetElem(int(m.group(1))))
                continue

            m = re.match('(Cmp(?:EQ|NE|LT|LE))\d+(S|U)?', operation)
            if m:
                op = m.group(1)+m.group(2) if m.group(2) else m.group(1)
                negate_constraint = any(item[0] == 'Not_' for item in valgrind_operations[i:])
                #print valgrind_operations[i:]
                #print negate_constraint
                z3_constraints.append(valgrind.Operation(op, first_op, second_op,  third_op, negate_constraint).to_z3())
                break
            
            if operation == 'x86g_calculate_condition':
                op = valgrind.X86Condcode[first_op]		
                negate_constraint = any(item[0] == 'Not_' for item in valgrind_operations[i:])
                z3_constraints.append(valgrind.Operation(op, second_op, third_op,  dest_op, negate_constraint).to_z3())
                break
            print "Unknown opt: %s" % operation
    
    return z3_operations, z3_constraints

def dump(vg_opt_group, size_by_var, offset_by_var, constant_by_var, string_by_var, index):
    global z3_prologue, z3_epilogue
    #print vg_opt_group
    z3_operations, z3_constraints = translate_valgrind_operations_group(vg_opt_group)
    z3_file = "out_%d.py" % index
    f = open(z3_file, 'w')
    f.write(z3_prologue+'\n\n\n')
    for var, size in size_by_var.iteritems():
        if var in string_by_var.keys():
            continue
        elif not var in constant_by_var.keys():
            f.write("%s = BitVec('%s', %d)\n" % (var, var, size))
        else:
            if size > 0:
                f.write("%s = BitVecVal(%d, %d)\n" % (var, constant_by_var[var], size))
            else:
                f.write("%s = %d\n" % (var, constant_by_var[var]))
    f.write('\n')

    f.write("c_1 = BitVecVal(-1, 1)\n")
    f.write("c_8 = BitVecVal(-1, 8)\n")
    f.write("c_16 = BitVecVal(-1, 16)\n")
    f.write("c_32 = BitVecVal(-1, 32)\n")
    f.write("c_64 = BitVecVal(-1, 64)\n\n")
    f.write('\n')

    for op in z3_operations:
        f.write(op+'\n')
    f.write('\n')

    for constraint in z3_constraints:
        f.write('s.add(%s)\n'%constraint)
    f.write('\n')

    for i, var in enumerate(offset_by_var):
        for j, var2 in enumerate(offset_by_var):
            if (i < j) and (offset_by_var[var] == offset_by_var[var2]):
                f.write('s.add(%s == %s)\n' % (var, var2))
    f.write("\n")
    '''
    for var in offset_by_var:
        f.write('s.add(%s >= 65)\n' % var)
        f.write('s.add(%s <= 122)\n' % var)
    f.write("\n")
    '''
    f.write(z3_epilogue)
    f.close()
    return z3_file

def translate_z3_model(offset_by_var, size_by_var, z3_file):
    offsets_values_sizes = []
    model = commands.getoutput('python '+z3_file)
    if model:
        vars_and_values = model.split(',')
        for var_and_value in vars_and_values:
            m = re.search('(_\d+) = (\d+)', var_and_value)
            if m:
                var = m.group(1)
                value = int(m.group(2))
                #print "%s = %d" % (var, value)
                if var not in offset_by_var.keys():
                    continue
                offset = offset_by_var[var]
                size = size_by_var[var]
                offsets_values_sizes.append((offset, value, size))
    else:
        print "Cannot solve %s" % z3_file
    return offsets_values_sizes

def solve(con_group, index):
    valgrind_operations_group, size_by_var, offset_by_var, constant_by_var, string_by_var =  parse_constraint_group(con_group)
    z3_file = dump(valgrind_operations_group, size_by_var, offset_by_var, constant_by_var, string_by_var, index)
    return translate_z3_model(offset_by_var, size_by_var, z3_file)
