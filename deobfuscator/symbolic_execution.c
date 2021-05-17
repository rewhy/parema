#include "symbolic_execution.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)

#include "util.h"

	static
int update_dep(Shadow* shadow, char* dep, UInt size)
{
	int res = 0;
	tl_assert(DEP_MAX_SIZE >= size);
	//VG_(printf)("update_dep(): 0x%08x %s (%u)\n", (Addr)shadow, dep, size);

	if (shadow->buffer == NULL) {
		shadow->buffer = VG_(malloc)("shadow_buffer", DEP_MAX_LEN);
	} else {
		res = shadow->size;
	}
	VG_(snprintf)(shadow->buffer, DEP_MAX_LEN, "%s", dep);
	shadow->size = size;

	//VG_(printf)("update_dep(): %s (%u)\n", shadow->buffer, shadow->size);
	return res;
}

	static
void free_dep(Shadow* shadow)
{
	if (shadow->buffer != NULL) {
		// VG_(printf)("free_dep(): %s (%u)\n", shadow->buffer, shadow->size);
#ifdef FZ_EXE_TAINT
		VG_(free)(shadow->buffer);
		shadow->buffer = NULL;
#else
		shadow->buffer[0] = '\0';
#endif
	}
	shadow->size = 0;
}

//
//  MEMORY
//

	static
Addr get_memory_dep_forward(Addr addr, UInt size, UInt *shadow_size, char* dep)
{
	int i = 0, left_size = 0, tmp_size = 0; 
	Addr beg_addr = 0;
	Chunk* chunk		= NULL;
	Shadow* shadow	= NULL;
	for(i = 0; i < size/8; i++) {
		beg_addr	= addr+i;
		left_size = size - i*8;
		chunk = get_chunk_for_reading(beg_addr);
		if (chunk == NULL) {
			continue;
		}
		shadow = chunk->bytes[(beg_addr) & 0xffff];
		if (shadow == NULL) {
			continue;
		}
		if (shadow->buffer == NULL) {
			continue;
		}
		//*shadow_size = (left_size >= shadow->size) ? shadow->size : left_size;
		*shadow_size = shadow->size;

		tmp_size = left_size >= shadow->size ? shadow->size : left_size;
		if(tmp_size == shadow->size) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer);
		}	else {
			VG_(snprintf)(dep, DEP_MAX_LEN, "Sar%d_(%s,0,%d)",
					tmp_size,
					shadow->buffer, 
					shadow->size);
		}
		break;
	}
	return beg_addr;
}

char* get_memory_dep(UInt addr, UInt size, char *dep, ULong load_value)
{
	int left_size = 0, overlap_size = 0, sub_shadow_size = 0, gap_size = 0;// tmp_len = 0;
	int i = 0, first_op_size = 0, dist_op_size = 0;
	Addr beg_addr, sub_addr, sub_shadow_addr;
	Chunk* chunk;
	Shadow* shadow;
	ULong fix_value = 0;
	UChar *fix_buf = NULL;
	char sub_dep[DEP_MAX_LEN] = {'\0'};
	char first_dep[DEP_MAX_LEN] = {'\0'};
	for (i = 0; i < DEP_MAX_SIZE/8; i++)
	{
		beg_addr = addr - i;
		chunk = get_chunk_for_reading(beg_addr);
		if (chunk == NULL) {
			//VG_(printf)("Find no chunk for 0x%08x\n", beg_addr);
			continue;
		}
		shadow = chunk->bytes[(beg_addr) & 0xffff];
		if ( shadow == NULL ) {
			//VG_(printf)("Find no shadow for 0x%08x\n", beg_addr);
			continue;
		}
		if ( shadow->buffer == NULL ) {
			//VG_(printf)("Find no shadow buffer for 0x%08x\n", beg_addr);
			continue;
		}
		break;
	}

	left_size = size;
	
	overlap_size = 0;
	if(i < DEP_MAX_SIZE/8) {
		overlap_size = shadow->size - (addr-beg_addr) * 8;
		overlap_size = overlap_size > size ? size : overlap_size;
	}

	//VG_(printf)("backward: %d %d\n", i, overlap_size);
	if(i == DEP_MAX_SIZE/8 || overlap_size <= 0) { // Find no dep through looking up backword
		/*MY_LOGE("Dep of 0x%08x:I%d is NULL\n", addr, size);
			return dep;*/
		overlap_size = 0;
		sub_addr = addr;
		//VG_(snprintf)(dep, DEP_MAX_LEN, "Cas%d_(", size);
	} else {
		tl_assert(shadow->buffer);
		if(overlap_size == shadow->size && addr == beg_addr) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", shadow->buffer);
		} else {
			VG_(snprintf)(dep, DEP_MAX_LEN, "Sar%d_(%s,%d,%d)", 
					overlap_size,
					shadow->buffer,
					(addr-beg_addr) * 8, 
					shadow->size
					);
		}
		
		left_size = (addr-beg_addr) * 8 + (size - shadow->size);
		if( left_size <= 0) {
			return dep;
		}
		
		VG_(strcpy)(first_dep, dep);
		first_op_size = overlap_size;

		sub_addr = addr + overlap_size / 8;
	}	

	// Lookup dep for the left bytes
	while(left_size > 0) {
		sub_shadow_addr = get_memory_dep_forward(sub_addr, left_size, &sub_shadow_size, sub_dep);
		if(sub_shadow_size > 0)
			gap_size = (sub_shadow_addr-sub_addr) * 8;
		else
			gap_size = left_size;

		tl_assert(gap_size <= left_size);
		
		//VG_(printf)("sub dep: 0x%08x %d %d %d\n", sub_shadow_addr, sub_shadow_size, gap_size, first_op_size);

		if(gap_size > 0) {
			fix_buf = (UChar*)sub_addr;
			fix_value = 0;
			for(i = 0; i < gap_size/8; i++) {
				fix_value |= fix_buf[i] << 8;
			}

			//VG_(printf)("Shift: 0x%08x, %d, 0x%llx\n", (Addr)fix_buf, i, fix_value);
			if(first_op_size > 0) {
				dist_op_size = first_op_size + gap_size;
				VG_(snprintf)(dep, DEP_MAX_LEN, "Cas%d_(%s,Fix:%d(%lld))",
						dist_op_size, first_dep, gap_size, fix_value);
				first_op_size = dist_op_size;
				VG_(strcpy)(first_dep, dep);
			} else {
				first_op_size = gap_size;
				VG_(snprintf)(dep, DEP_MAX_LEN, "FIX:%d(%lld)", first_op_size, fix_value);
				VG_(strcpy)(first_dep, dep);
			}
		}

		left_size = left_size - gap_size;
		
		tl_assert(left_size >= 0);
	
		if(left_size <= 0) {
			break;
		} else {
			dist_op_size = first_op_size + ((sub_shadow_size > left_size) ? left_size : sub_shadow_size);
			if(first_op_size > 0) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "Cas%d_(%s,%s)", dist_op_size, first_dep, sub_dep);
				VG_(strcpy)(first_dep, dep);
			} else {
				VG_(snprintf)(dep, DEP_MAX_LEN, "%s", sub_dep);
				VG_(strcpy)(first_dep, dep);
			}
			first_op_size = dist_op_size;
			left_size = left_size - ((sub_shadow_size > left_size) ? left_size : sub_shadow_size);
		} 
		sub_addr = sub_shadow_addr + sub_shadow_size/8;
	}

	if(dep[0] == '\0')
		MY_LOGE("Dep of 0x%08x:I%d is NULL\n", addr, size);
	return dep;
}

void update_memory_dep(UInt addr, char* dep, UInt size)
{
	Chunk* chunk;
	Shadow** shadow;

	chunk = get_chunk_for_writing(addr);

	shadow = &chunk->bytes[addr & 0xffff];

#ifdef FZ_EXE_TAINT
	tl_assert(shadow != NULL);
#else
	if (*shadow == NULL) {
		*shadow = VG_(malloc)("shadow.structure", sizeof(Shadow));
		VG_(memset)(*shadow, 0, sizeof(Shadow));
	}
#endif

	update_dep(*shadow, dep, size);
	free_memory_dep(addr+1, size-8);
#ifdef FZ_SYM_EXE
	VG_(printf)("update_memory_dep(0x%08x, %d): %s\n", addr, size, dep);
#endif
}

void free_memory_dep(UInt addr, UInt size)
{
	Chunk* chunk;
	Shadow* shadow;
	int i;
	Bool is_freed = False;

	for (i = 0; i < size/8; i++)
	{
		chunk = get_chunk_for_reading(addr+i);
		if (chunk == NULL)
			continue;

		shadow = chunk->bytes[(addr+i) & 0xffff];
		if (shadow == NULL)
			continue;

		free_dep(shadow);
		is_freed = True;
	}
	// VG_(printf)("free_memory_dep(): 0x%08x %d\n", addr, size);
	// VG_(printf)("free_memory_dep()\n");
	//if( is_freed )
	//	VG_(printf)(" 0x%08x %d\n", addr, size);
}

//
//  REGISTERS
//

char* get_register_dep(UInt offset)
{
	//guest_register reg;
	UInt reg;
	Shadow shadow;

	reg = get_reg_from_offset(offset);
	if(reg == guest_INVALID) {
		MY_LOGE("ffset %d is guest_INVALID!!!\n", offset);
		return NULL;
	}
	//tl_assert(reg != guest_INVALID);

	shadow = registers[reg];
	if(shadow.buffer == NULL) {
		MY_LOGE("Shadow buffer of offset %d is NULL!!!\n", offset);
		//tl_assert(shadow.buffer != NULL);
	} else {
		if(VG_(strlen)(shadow.buffer) == 0) {
			MY_LOGE("Shadow buffer of offset %d is Empty!!!\n", offset);
			//tl_assert(shadow.buffer != NULL);
		}
	}

	return shadow.buffer;
}

void update_register_dep(UInt offset, UInt size, char* dep)
{
	//guest_register reg = get_reg_from_offset(offset);
	UInt reg = get_reg_from_offset(offset);
	tl_assert(reg != guest_INVALID);

	update_dep(&registers[reg], dep, size);
#ifdef FZ_SYM_EXE
	VG_(printf)("update_register_dep(%d): %s\n", offset, dep);
#endif
}

void free_register_dep(UInt offset)
{
	//guest_register reg = get_reg_from_offset(offset);
	UInt reg = get_reg_from_offset(offset);
	tl_assert(reg != guest_INVALID);

	free_dep(&registers[reg]);
}

//
//  TEMPORARIES
//

char* get_temporary_dep(IRTemp tmp)
{
	Shadow shadow;

	if(tmp >= MAX_TEMPORARIES) {
		MY_LOGE("tmp=0x%08X fail\n", tmp);
		tl_assert(0);
	}
	shadow = shadowTempArray[tmp];
	if(shadow.buffer == NULL) {
		MY_LOGE("Shadow buffer of t%d is NULL!!!\n", tmp);
		//tl_assert(shadow.buffer != NULL);
	}
	return shadow.buffer;
}

void update_temporary_dep(IRTemp tmp, char* dep, UInt dep_size)
{
	tl_assert(tmp < MAX_TEMPORARIES);
	update_dep(&shadowTempArray[tmp], dep, dep_size);
#ifdef FZ_SYM_EXE
	VG_(printf)("update_temporary_dep(t%d): %d %s\n",tmp, dep_size, dep);
#endif
}

void free_temporary_dep(IRTemp tmp)
{
	tl_assert(tmp < MAX_TEMPORARIES);

	free_dep(&shadowTempArray[tmp]);
}
