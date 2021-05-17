import re
import sys
import commands
import parser
import valgrind

z3_file = 'out.py'

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
	
	for valgrind_operations in valgrind_operations_group:
		for i, (operation, first_op, second_op, dest_op) in enumerate(valgrind_operations):	
			if operation == 'assign':
				assign(first_op, second_op, dest_op, z3_operations)
				continue
			
			m = re.match('(Add|Sub|Mul|Shl|Shr|Sar|Div(?:Mod)?[S|U]|Or|And|Xor)\d+', operation)
			if m:
				z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, dest_op).to_z3())
				continue
			
			m = re.match('\d+HLto\d+', operation)
			if m:
				z3_operations.append(valgrind.Operation('HLto', first_op, second_op, dest_op).to_z3())
				continue
			
			m = re.match('(Cmp(?:EQ|NE|LT|LE))\d+(S|U)?', operation)
			if m:
				op = m.group(1)+m.group(2) if m.group(2) else m.group(1)
				negate_constraint = any(item[0] == 'Not_' for item in valgrind_operations[i:])
				z3_constraints.append(valgrind.Operation(op, first_op, second_op, negate_constraint).to_z3())
				break
		
			if operation == 'x86g_calculate_condition':
				op = valgrind.X86Condcode[first_op]		
				negate_constraint = any(item[0] == 'Not_' for item in valgrind_operations[i:])
				z3_constraints.append(valgrind.Operation(op, second_op, dest_op, negate_constraint).to_z3())
				break
	
	return z3_operations, z3_constraints
	
def dump(valgrind_operations_group, size_by_var, offset_by_var):
	global z3_file, z3_prologue, z3_epilogue
	
	print valgrind_operations_group
	z3_operations, z3_constraints = translate_valgrind_operations_group(valgrind_operations_group)
	
	f = open(z3_file,'w')	
	f.write(z3_prologue+'\n')
	for var, size in size_by_var.iteritems():
		f.write("%s = BitVec('%s', %d)\n" % (var, var, size))
	f.write('\n')
	for op in z3_operations:
		f.write(op+'\n')
	f.write('\n')
	for constraint in z3_constraints:
		f.write('s.add(%s)\n'%constraint)

	f.write("\n")
	for i, var in enumerate(offset_by_var):
		for j, var2 in enumerate(offset_by_var):
			if (i < j) and (offset_by_var[var] == offset_by_var[var2]):
				f.write('s.add(%s == %s)\n' % (var, var2));
	f.write("\n")
	for var in offset_by_var:
		f.write('s.add(%s >= 65)\n' % var)
		f.write('s.add(%s <= 122)\n' % var)
	f.write("\n")
		
	f.write(z3_epilogue)
	f.close()
	
def translate_z3_model(offset_by_var, size_by_var, realsize_by_var, shift_by_var):
	global z3_file
	offsets_values_sizes = []
	
	model = commands.getoutput('python '+z3_file)
	if model:
		vars_and_values = model.split(',')
		for var_and_value in vars_and_values:
			m = re.search('(_\d+) = (\d+)', var_and_value)		
			if m:
				var = m.group(1)
				value = int(m.group(2))
				
				offset = offset_by_var[var]
				size = realsize_by_var.get(var, size_by_var[var])
				
				if var in shift_by_var:
					value >>= shift_by_var[var]
					
				offsets_values_sizes.append((offset, value, size))
				
		print model
	else:
		print "Cannot solve"

	
	return offsets_values_sizes
	
def correct_offset_by_var(offset_by_var, shift_by_var):
	for var in shift_by_var:
		offset_by_var[var] += shift_by_var[var]/8
			
def solve(constraint_group):
	valgrind_operations_group, size_by_var, offset_by_var, realsize_by_var, shift_by_var = parser.parse_constraint_group(constraint_group)
	correct_offset_by_var(offset_by_var, shift_by_var)
	dump(valgrind_operations_group, size_by_var, offset_by_var)	
	return translate_z3_model(offset_by_var, size_by_var, realsize_by_var, shift_by_var)

def solve1(constraint_group, con_file):
	global z3_file
	z3_file = con_file
	valgrind_operations_group, size_by_var, offset_by_var, realsize_by_var, shift_by_var = parser.parse_constraint_group(constraint_group)
	correct_offset_by_var(offset_by_var, shift_by_var)
	dump(valgrind_operations_group, size_by_var, offset_by_var)	
	return translate_z3_model(offset_by_var, size_by_var, realsize_by_var, shift_by_var)

