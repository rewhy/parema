#ifndef _TAINT_ANALYSIS_H
#define _TAINT_ANALYSIS_H

#include "shadow_memory.h"
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

/* MEMORY */

char memory_is_tainted(UInt addr, UInt size);
void flip_memory(UInt addr, UInt size, char val);

/* REGISTERS */

char register_is_tainted(UInt offset);
void flip_register(UInt offset, char val);

/* TEMPORARIES */

char temporary_is_tainted(IRTemp tmp);
char IRTemp_is_tainted(IRTemp tmp);
void flip_temporary(IRTemp tmp);

#endif // TAINT_ANALYSIS_H
