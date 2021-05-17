from collections import deque
import time
import commands
import struct
import valgrind

import sys
import _z3
import os

new_files_dir = './newinput'
test_file = ''
input_file = ''

pack_format_by_size = {
	8 : '<B',
	16 : '<H',
	32 : '<I'
}

def generate_new_file(offsets_values_sizes):
	global new_files_dir, test_file, pack_format_by_size
	
	new_file = '%s/%s-%f' % (new_files_dir, test_file, time.time())
        print("cp %s %s" %  (input_file, new_file));
	commands.getoutput('cp %s %s' % (input_file, new_file))

        os.system("cat %s" % new_file);
	for offset, value, size in offsets_values_sizes:
		with open(new_file,'r+b') as f:
			f.seek(offset)			
			f.write(struct.pack(pack_format_by_size[size], value))
		print '%s[%d] = %d (%d)' % (new_file, offset, value, size) 
                f.close();

        sys.exit(0)
	return new_file

def lead(target, infile):
	global new_files_dir, test_file, input_file
	
	commands.getoutput('mkdir %s' % new_files_dir)	
	test_file = infile
	
	fuzzing_files = deque()
	fuzzing_files.append(infile)
	while (fuzzing_files):
		infile = fuzzing_files.popleft()
                input_file = infile
		constraint_groups = valgrind.get_constraint_groups(target, infile)
		for constraint_group in constraint_groups:
			offsets_values_sizes = _z3.solve(constraint_group)
			if offsets_values_sizes:
				fuzzing_files.append(generate_new_file(offsets_values_sizes))


if __name__ == "__main__":
        outfile = sys.argv[1]
        i = 0
        constraint_groups = valgrind.get_constraint_groups1(outfile)
	for constraint_group in constraint_groups:
                i += 1
                z3_file = "out%d.py" % i
                offsets_values_sizes = _z3.solve1(constraint_group, z3_file)
                #if offsets_values_sizes:
                #        fuzzing_files.append(generate_new_file(offsets_values_sizes))

