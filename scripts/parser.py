from pyparsing import Literal, Word, alphanums, nums, Forward, ZeroOrMore
import re

var_cnt = 0
constraint_by_var = None
offset_by_var = None
size_by_var = None
realsize_by_var = None
shift_by_var = None
signedness_by_var = None
cast_signedness_by_var = None
valgrind_operations = None

def new_var():
	global var_cnt
	var_cnt += 1
	return '_%d' % var_cnt

def resize(oldvar, oldsize, newsize, signedness, valgrind_op_after_resize):
	global size_by_var, signedness_by_var
	
	newvar = new_var()
	size_by_var[newvar] = newsize
	signedness_by_var[newvar] = signedness
	
	valgrind_op_after_resize.append(('assign', newvar, oldvar, (oldsize, newsize, signedness)))
	
	return newvar

def check_operand_size(operand, operation_size, valgrind_op_after_resize):
	global size_by_var, signedness_by_var
	
	if operand in size_by_var:
		operand_size = size_by_var[operand]
		if operand_size != operation_size:
			operand = resize(operand, operand_size, operation_size, signedness_by_var[operand], valgrind_op_after_resize)
	
	return operand
	
def is_arithmetic_operation(operation):
	return re.match('(Add|Sub|Mul|Shl|Shr|Sar|Div(?:Mod)?[S|U]|Or|And|Xor)\d+', operation)
	
def replace_operand(oldoperand, i, valgrind_op_after_resize):
	global size_by_var, realsize_by_var, cast_signedness_by_var, valgrind_operations
	
	size = size_by_var[oldoperand]
	realsize = realsize_by_var[oldoperand]
	
	if size != realsize:
		newoperand = resize(oldoperand, size, realsize, cast_signedness_by_var[oldoperand], valgrind_op_after_resize)
		
		for j in range(i, len(valgrind_operations)):
			operation, first_operand, second_operand, dest_operand = valgrind_operations[j]
			
			first_operand = newoperand if (first_operand == oldoperand) else first_operand
			second_operand = newoperand if (second_operand == oldoperand) else second_operand
			dest_operand = newoperand if (dest_operand == oldoperand) else dest_operand
		
			valgrind_operations[j] = (operation, first_operand, second_operand, dest_operand)

def resize_operands():
	global valgrind_operations, size_by_var
	valgrind_op_after_resize = []
	
	for i, (operation, first_operand, second_operand, dest_operand) in enumerate(valgrind_operations):
		m = re.match('^Sar\d+_$', operation)
		if m:
			valgrind_op_after_resize.append((operation, first_operand, second_operand, dest_operand))	
			replace_operand(first_operand, i, valgrind_op_after_resize)		
		else:		
			if is_arithmetic_operation(operation):
				first_operand = check_operand_size(first_operand, size_by_var[dest_operand], valgrind_op_after_resize)
				second_operand = check_operand_size(second_operand, size_by_var[dest_operand], valgrind_op_after_resize)
	
			valgrind_op_after_resize.append((operation, first_operand, second_operand, dest_operand))
		
	valgrind_operations = valgrind_op_after_resize
	
def add_operation(operation, first_operand, second_operand, dest_operand, constraint):
	global valgrind_operations, constraint_by_var
	
	valgrind_operations.append((operation, first_operand, second_operand, dest_operand))
	constraint_by_var[dest_operand] = constraint
	
def update_var_size_ldle(var, size):
	global size_by_var, realsize_by_var, shift_by_var
	
	if var not in size_by_var:
		size_by_var[var] = size
	elif (var in size_by_var) and (var not in shift_by_var) and (var not in realsize_by_var):
		size_by_var[var] = realsize_by_var[var] = size
	elif (var in size_by_var) and (var in shift_by_var) and (var not in realsize_by_var):
		realsize_by_var[var] = size
		
def update_var_size_cast(var, size, signedness):
	global size_by_var, realsize_by_var, shift_by_var, cast_signedness_by_var
	
	if (var in realsize_by_var) and (var not in shift_by_var):
		size_by_var[var] = realsize_by_var[var] = size
		signedness_by_var[var] = signedness
	elif (var in realsize_by_var) and (var in shift_by_var):
		realsize_by_var[var] = size
		cast_signedness_by_var[var] = signedness
	
def parse_function(s, loc, toks):
	global constraint_by_var, offset_by_var, signedness_by_var


	operation = toks[0]
	string = ''.join(toks)
	# print string
	
	m = re.match('^INPUT\((\d+)\)$', string)
	if m:
		newvar = new_var()
		constraint_by_var[newvar] = string
		offset_by_var[newvar] = int(m.group(1))
		signedness_by_var[newvar] = 'S'
		return
		
	for var, constraint in constraint_by_var.iteritems():
		m = re.match('^[a-zA-Z0-9:_]+\(%s\)$'%re.escape(constraint), string)
		if m:
			m = re.match('^LDle:(\d+)$', operation)
			if m:
				update_var_size_ldle(var, int(m.group(1)))
			
			m = re.match('^(\d+)([U|S])to\d+$', operation)
			if m:
				update_var_size_cast(var, int(m.group(1)), m.group(2))
			
			add_operation(operation, var, None, var, string)			
			return
			
		m = re.match('^[a-zA-Z0-9:_]+\(%s,(\d+)\)$'%re.escape(constraint), string)
		if m:
			mm = re.match('^Sar\d+_$', operation)
			if mm:
				dest_operand = var
				shift_by_var[var] = int(m.group(1))
			else:
				dest_operand = new_var()			
				size_by_var[dest_operand] = realsize_by_var.get(var, size_by_var[var])				
				signedness_by_var[dest_operand] = signedness_by_var[var]
			
			add_operation(operation, var, m.group(1), dest_operand, string)
			return		
		m = re.match('^[a-zA-Z0-9:]+\((\d+),%s\)$'%re.escape(constraint), string)
		if m:
			dest_operand = new_var()			
			size_by_var[dest_operand] = realsize_by_var.get(var, size_by_var[var])			
			signedness_by_var[dest_operand] = signedness_by_var[var]
			
			add_operation(operation, m.group(1), var, dest_operand, string)
			return
			
		#m = re.match('^x86g_calculate_condition\((\d+),\d+,%s,(\d+)\)$'%re.escape(constraint), string)
		m = re.match('^armg_calculate_condition\((\d+),\d+,%s,(\d+)\)$'%re.escape(constraint), string)
		if m:
			add_operation(operation, int(m.group(1)), var, int(m.group(2)), string)
			return
			
	for var1,constraint1 in constraint_by_var.iteritems():
		for var2,constraint2 in constraint_by_var.iteritems():
			m = re.match('^[a-zA-Z0-9:]+\(%s,%s\)$'%(re.escape(constraint1),re.escape(constraint2)), string)
			if m:
				if operation == '\d+HLto\d+':
					dest_operand = var2
				else:
					dest_operand = new_var()
					signedness_by_var[dest_operand] = 'S'
					size_by_var[dest_operand] = realsize_by_var.get(var1, size_by_var[var1])
					
				add_operation(operation, var1, var2, dest_operand, string)
				return
				
def init_global_vars():
	global var_cnt, constraint_by_var, signedness_by_var, cast_signedness_by_var
	global valgrind_operations, size_by_var, offset_by_var, realsize_by_var, shift_by_var
	
	var_cnt = 0
	constraint_by_var = {}
	offset_by_var = {}
	size_by_var = {}
	realsize_by_var = {}
	shift_by_var = {}
	signedness_by_var = {}
	cast_signedness_by_var = {}
	valgrind_operations = []
	
def parse_constraint_group(constraint_group):
	global valgrind_operations, size_by_var, offset_by_var, realsize_by_var, shift_by_var
	
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
	for constraint in constraint_group:
		print "constraint %s" % constraint
		valgrind_operations = []
		
		expression.parseString(constraint)
		resize_operands()
		print valgrind_operations
		valgrind_operations_group.append(valgrind_operations)
	
	return (valgrind_operations_group, size_by_var, offset_by_var, realsize_by_var, shift_by_var)
