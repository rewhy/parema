#include "taint_analysis.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_machine.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)

#include "util.h"

//
//  MEMORY
//

char memory_is_tainted(UInt addr, UInt size)
{
	Chunk* chunk;
	Shadow* shadow;
	int i;

	for (i = 0; i < size/8; i++)
	{
		chunk = get_chunk_for_reading(addr+i);
		if (chunk == NULL)
			continue;

		shadow = chunk->bytes[(addr+i) & 0xffff];
		if (shadow == NULL)
			continue;

		if (shadow->tainted) {
			return 1;
		}
	}

	return 0;
}

void flip_memory(UInt addr, UInt size, UChar val)
{
	Chunk* chunk;
	Shadow** shadow;
	int i;

	for (i = 0; i < size/8; i++)
	{
		chunk = get_chunk_for_writing(addr+i);
		shadow = &chunk->bytes[(addr+i) & 0xffff];
		if (*shadow == NULL) {
			*shadow = VG_(malloc)("shadow.structure", sizeof(Shadow));
			VG_(memset)(*shadow, 0, sizeof(Shadow));
		}

#ifdef FZ_LOG_TAINT
		VG_(printf)("flip_memory: 0x%08x: %d->%d (8) 0x%02x\n", addr+i, (*shadow)->tainted, val, *((Char*)(addr+i)));
#endif
		(*shadow)->tainted = val;
	}
}

//
//  REGISTERS
//

char register_is_tainted(UInt offset)
{
	UInt reg = get_reg_from_offset(offset);

	if (reg == guest_INVALID)
		return 0;

	return registers[reg].tainted;
}

void flip_register(UInt offset, UChar val)
{
	UInt reg = get_reg_from_offset(offset);

	if (val)
		tl_assert(reg != guest_INVALID);
	else if (reg == guest_INVALID)
		return;

#ifdef FZ_LOG_TAINT
	VG_(printf)("flip_register: %d(%d): %d -> %d\n", offset, reg, registers[reg].tainted, val);
#endif
	registers[reg].tainted = val;
}

//
//  TEMPORARIES
//

char temporary_is_tainted(IRTemp tmp)
{
	if(tmp >= MAX_TEMPORARIES) {
		VG_(printf)("tmp=%d\n", tmp);
		tl_assert(0);
	}
	return shadowTempArray[tmp].tainted;
}

char IRTemp_is_tainted(IRTemp tmp)
{
	if (tmp == IRTemp_INVALID) // Iex_Const
		return 0;
	else
		return temporary_is_tainted(tmp);
}

void flip_temporary(IRTemp tmp)
{
	tl_assert(tmp < MAX_TEMPORARIES);
#ifdef FZ_LOG_TAINT
	VG_(printf)("flip_temporary: %d: %d -> %d\n", tmp, shadowTempArray[tmp].tainted, shadowTempArray[tmp].tainted ^ 1);
#endif
	shadowTempArray[tmp].tainted ^= 1;
}

void clear_temporary(IRTemp tmp)
{
}

