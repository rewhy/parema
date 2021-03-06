#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)
#include "pub_tool_guest.h"

void init_shadow_memory(void)
{
	//VG_(printf)("EXP: init_shadow_memory()\n");
	VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);
	VG_(memset)(registers, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);
	VG_(memset)(shadowTempArray, 0, sizeof(Shadow)*MAX_TEMPORARIES);
}

void clear_shadow_memory(void)
{
	//VG_(printf)("EXP: clear_shadow_memory()\n");
	destroy_shadow_memory();
	VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);
	VG_(memset)(registers, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);
	VG_(memset)(shadowTempArray, 0, sizeof(Shadow)*MAX_TEMPORARIES);
}

void destroy_shadow_memory(void)
{
	Chunk* chunk;
	Shadow* shadow;
	unsigned int i, j;

	for (i = 0; i < MMAP_SIZE; i++)
	{
		chunk = MemoryMap[i];
		if (chunk != NULL)
		{
			for (j = 0; j < CHUNK_SIZE; j++)
			{
				shadow = chunk->bytes[j];
				if (shadow != NULL)
				{
					if (shadow->buffer != NULL) {
						VG_(free)(shadow->buffer);
					}

					VG_(free)(shadow);
				}
			}

			VG_(free)(chunk);
		}
	}
}

//
//  MEMORY
//

Chunk* get_chunk_for_reading(UInt addr)
{
	return MemoryMap[(addr >> 16) & 0xffff];
}

Chunk* get_chunk_for_writing(UInt addr)
{
	UInt x = (addr >> 16) & 0xffff;

	if (MemoryMap[x] == NULL)
	{
		MemoryMap[x] = VG_(malloc)("", sizeof(Chunk));
		VG_(memset)(MemoryMap[x], 0, sizeof(Chunk));
	}

	return MemoryMap[x];
}

// 
// REGISTER
//

UInt get_reg_from_offset(UInt offset)
{
	if (offset >= sizeof(VexGuestArchState))
		return guest_INVALID;
	return offset/4;
}
