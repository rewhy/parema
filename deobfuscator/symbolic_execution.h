#ifndef _SYMBOLIC_EXECUTION_H
#define _SYMBOLIC_EXECUTION_H

#include "shadow_memory.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

/* MEMORY */

char* get_memory_dep(UInt addr, UInt size, char* dep, ULong value);
void update_memory_dep(UInt addr, char* dep, unsigned int dep_size);
void free_memory_dep(UInt addr, UInt size);

/* REGISTERS */

char* get_register_dep(UInt offset);
void update_register_dep(UInt offset, UInt size, char* dep);
void free_register_dep(UInt offset);

/* TEMPORARIES */

char* get_temporary_dep(IRTemp tmp);
void update_temporary_dep(IRTemp tmp, char* dep, unsigned int dep_size);
void free_temporary_dep(IRTemp tmp);


#endif // SYMBOLIC_EXECUTION_H

