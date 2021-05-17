#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)
#include "pub_tool_guest.h"
#include "pub_tool_debuginfo.h"

#include "util.h"

/*------------- For memory trace ----------------*/
/*------------------ End ------------------------*/

void init_shadow_memory(void)
{
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
//  REGISTERS
//

/*guest_register VexGuestState[] = {
	host_EvC_FAILADDR,
	host_EvC_FAILADDR,
	host_EvC_FAILADDR,
	host_EvC_FAILADDR,
	host_EvC_COUNTER,
	host_EvC_COUNTER,
	host_EvC_COUNTER,
	host_EvC_COUNTER,
	guest_EAX,
	guest_EAX,
	guest_EAX,
	guest_EAX,
	guest_ECX,
	guest_ECX,
	guest_ECX,
	guest_ECX,
	guest_EDX,
	guest_EDX,
	guest_EDX,
	guest_EDX,
	guest_EBX,
	guest_EBX,
	guest_EBX,
	guest_EBX,
	guest_ESP,
	guest_ESP,
	guest_ESP,
	guest_ESP,
	guest_EBP,
	guest_EBP,
	guest_EBP,
	guest_EBP,
	guest_ESI,
	guest_ESI,
	guest_ESI,
	guest_ESI,
	guest_EDI,
	guest_EDI,
	guest_EDI,
	guest_EDI,
	guest_CC_OP,
	guest_CC_OP,
	guest_CC_OP,
	guest_CC_OP,
	guest_CC_DEP1,
	guest_CC_DEP1,
	guest_CC_DEP1,
	guest_CC_DEP1,
	guest_CC_DEP2,
	guest_CC_DEP2,
	guest_CC_DEP2,
	guest_CC_DEP2,
	guest_CC_NDEP,
	guest_CC_NDEP,
	guest_CC_NDEP,
	guest_CC_NDEP,
	guest_DFLAG,
	guest_DFLAG,
	guest_DFLAG,
	guest_DFLAG,
	guest_IDFLAG,
	guest_IDFLAG,
	guest_IDFLAG,
	guest_IDFLAG,
	guest_ACFLAG,
	guest_ACFLAG,
	guest_ACFLAG,
	guest_ACFLAG,
	guest_EIP,
	guest_EIP,
guest_EIP,
	guest_EIP,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG0,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG1,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG2,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG3,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG4,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG5,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG6,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPREG7,
	guest_FPTAG0,
	guest_FPTAG1,
	guest_FPTAG2,
	guest_FPTAG3,
	guest_FPTAG4,
	guest_FPTAG5,
	guest_FPTAG6,
	guest_FPTAG7,
	guest_FPROUND,
	guest_FPROUND,
	guest_FPROUND,
	guest_FPROUND,
	guest_FC3210,
	guest_FC3210,
	guest_FC3210,
	guest_FC3210,
	guest_FTOP,
	guest_FTOP,
	guest_FTOP,
	guest_FTOP,
	guest_SSEROUND,
	guest_SSEROUND,
	guest_SSEROUND,
	guest_SSEROUND,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM0,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM1,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM2,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM3,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM4,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM5,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM6,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_XMM7,
	guest_CS,
	guest_CS,
	guest_DS,
	guest_DS,
	guest_ES,
	guest_ES,
	guest_FS,
	guest_FS,
	guest_GS,
	guest_GS,
	guest_SS,
	guest_SS
	};*/

UInt get_reg_from_offset(UInt offset)
{
	if (offset >= sizeof(VexGuestArchState))
		return guest_INVALID;

	return offset/8;//VexGuestState[offset];
}

/*----------- Add memory filter func --------------------*/
extern Addr dlopen_addr;
extern Addr dlsym_addr;

struct LibList *llist = NULL;
static Int filterNum = 0;

static struct FilterList *sysLibList = NULL; /* Memory list of system libraries */
static struct FilterList *monLibList = NULL; /* Memory list of monitoring libraries */
static struct FilterList *monMemList = NULL; /* memory mapped executable segments */
static struct FilterList *dumpMemList = NULL; /* dumpped mapped executable segments */

void dumpFilterList(struct FilterList *pfl) {
	struct FilterList* ttt = pfl;
	while(ttt) {
		VG_(printf)("Filter map: 0x%08x - 0x%08x info:%s\n", 
				ttt->begin, ttt->end, ttt->info);
		ttt = ttt->next;
	}
}

	static
void delFilterList(struct FilterList** ppfl, const HChar *info, Addr avma, SizeT size )
{
	struct FilterList *tfl, *nlfl = NULL, *llfl = NULL, *lfl, *lffl = NULL, *ffl = *ppfl;
	Addr b = avma;
	Addr e = avma+size;
	Int  isDel = 0;
	if( ffl == NULL ) 
		return;

	while( ffl ) {
		if( ffl->begin >= b)
			break;
		lffl = ffl;
		ffl  = ffl->next;
	};

	lfl = *ppfl;
	while( lfl ) {
		if( lfl->end > e)
			break;
		llfl = lfl;
		lfl = lfl->next;
	}

	// VG_(printf)("Del filter range: 0x%08x 0x%08x - 0x%08x %10d(0x%08x)\n", ffl, b, e, size, size);
	if( lffl ) {
		if ( lfl == lffl ) { /* b-e is loacated in the same range */
			tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
			tfl->begin = e;
			tfl->end = lfl->end;
			VG_(strcpy)(tfl->info, lfl->info);
			lfl->end = b;
			tfl->next = lfl->next;
			lfl->next = tfl;
			isDel = 1;
			VG_(printf)("Del filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", 
					isDel, ffl, b, e, size, size, lfl->info);
			return;
		}
	}
	if(ffl == NULL) { /* b is larger than the begin addr of the last range */
		if (lfl == NULL) { /* e is larger than the end addr of the last range */
			tl_assert( llfl == lffl );
			if ( lffl->end > b ) {  /* Overlap is (lffl->end->end - b) */
				lffl->end = b;
				isDel = 2;
			}
		}
	} else { /* b < ffl->begin */
		nlfl = lfl;
		/* Delete ranges between b and e */
		while( ffl != nlfl ) {
			tfl = ffl;
			ffl = ffl->next;
			VG_(free)(tfl);
			isDel = 3;
		}
		/* process the overlab */
		if( lffl ) { /* the first range is not freed */
			if( b < lffl->end ) { /* overlab is ( b - lffl->end ) */
				lffl->end = b;
				isDel = 4;
			}
			if( nlfl ) {
				if ( nlfl->begin < e ) { /* overlab is ( nlfl->begin - e) */
					nlfl->begin = e;
					isDel = 5;
				}
			}
			lffl->next = nlfl;
		} else { /* the first range node is also deleted */
			if( nlfl ) {
				if ( nlfl->begin < e ) { /* overlab is ( nlfl->begin - e) */
					nlfl->begin = e;
					isDel = 6; 
				}
			}
			*ppfl = nlfl;
		}
	}
	if( isDel > 0)
	{
		VG_(printf)("Del filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", 
				isDel, ffl, b, e, size, size, info);
	}
}

static
void addFilterList(struct FilterList** ppfl, const HChar* info, Addr avma, SizeT size ) {
	struct FilterList *tfl, *llfl = NULL, *lfl = NULL, *lffl = NULL, *ffl = *ppfl;
	Addr b = avma;
	Addr e = avma+size;
	struct FilterList *nfl = NULL;
	Int isAdd = 0;
	if( size < 1 )
		return;

	if( ffl == NULL ) {
		tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
		tfl->begin = b;
		tfl->end = e;
		tfl->next = NULL;
		*ppfl = tfl;
		//VG_(printf)("Add filter range(1): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", ffl, b, e, size, size, info);
		if(info)
			VG_(strcpy)(tfl->info, info);
		else
			VG_(memset)(tfl->info, 0, 255);
		return;
	}
	while( ffl ) {
		if( ffl->begin >= b)
			break;
		lffl = ffl;
		ffl = ffl->next;
	}

	lfl = *ppfl;
	while( lfl ) {
		if ( lfl->end > e )
			break;
		llfl = lfl;
		lfl = lfl->next;
	}

	if( lffl && (lfl == lffl) ) {
		/* b-e is loacated in the same range */
		return;
	}

	if(ffl == NULL) { /* b is larger than the begin addr of the last range */
		if (lfl == NULL) { /* e is larger than the end addr of the last range */
			tl_assert( llfl == lffl );
			if ( lffl->end > b )  {/* new range is (lffl->end->end - e) */
				lffl->end = e;
			}	else { /* new range is ( b - e ) */
				tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
				nfl = tfl;
				isAdd = 1;
				tfl->begin = b;
				tfl->end = e;
				tfl->next = NULL;
				lffl->next = tfl;
			}
		}
	} else { /* b < ffl->begin */
		/* if lfl is NULL, b-e include all ranges */
		/* Delete ranges between b and e */
		while( ffl != lfl ) {
			tfl = ffl;
			ffl = ffl->next;
			VG_(free)(tfl);
		}
		/* process the overlab */
		if( lffl ) { /* the first range is not freed */
			if( lfl == NULL) {
				if ( b < lffl->end ) { /* new range is (lffl->end - e ) */
					lffl->end = e;
					lffl->next = NULL;
				} else { /* new range is ( b - e ) */
					tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
					nfl = tfl;
					isAdd = 2;
					tfl->begin = b;
					tfl->end = e;
					tfl->next = NULL;
					lffl->next = tfl;
				}
			} else {
				if ( b <= lffl->end ) { /* new range is (lffl->end - e ) */
					if ( e < lfl->begin ) {
						lffl->end = e;
						lffl->next = lfl;
					} else { /* new range is (lffl->end - lfl->begin) */
						lffl->end = lfl->end;
						lffl->next = lfl->next;
						VG_(free)(lfl);
					}
				} else { /* b > lffl->end */
					if ( e < lfl->begin ) { /* new range is (b-e) */
						tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
						nfl = tfl;
						isAdd = 3;
						tfl->begin = b;
						tfl->end = e;
						tfl->next = lfl;
						lffl->next = tfl;
					} else { /* e >= lfl->begin */
						/* new range is (b-lfl->begin) */
						lfl->begin = b;
						lffl->next = lfl;
					}
				}
			}
		} else { /* first range node is also freed */
			if ( lfl == NULL ||  e < lfl->begin ) { /* new range is (b-e) */
				tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
				nfl = tfl;
				isAdd = 4;
				tfl->begin = b;
				tfl->end = e;
				tfl->next = lfl;
				*ppfl = tfl;
			} else { /* e >= lfl->begin */
				/* new range is (b-lfl->begin) */
				lfl->begin = b;
				*ppfl = lfl;
			}
		}
	}
	if( isAdd > 0 ) {
		tl_assert(nfl);
		//VG_(printf)("Add filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", isAdd, ffl, b, e, size, size, info);
		if(info) {
			VG_(strncpy)(nfl->info, info, 254);
			nfl->info[255] = '\0';
		} else {
			VG_(memset)(nfl->info, 0, 255);
		}
	}
	//if( size == 4668 )
	//dumpFilterList(*ppfl);
}

static
Addr isInFilterList(struct FilterList* pfl, Addr a, HChar** pInfo) {
	struct FilterList* tfl = pfl;
	while ( tfl ) {
		if( a < tfl->begin )
			return 0;
		if( a < tfl->end ) {
			if(pInfo)
				*pInfo = tfl->info;
			return tfl->begin;
		}
		tfl = tfl->next;
	}
	return 0;
}

static
void releaseFilterList(struct FilterList** ppfl) {
	struct FilterList* tfl = *ppfl, *nfl;
	while ( tfl ) {
		nfl = tfl->next;
		VG_(free) ( tfl );
		tfl = nfl;
	}
	*ppfl = NULL;
}
void addMonitorLib(const HChar* libname) {
	HChar *soname;
	Addr avma;
	SizeT size;
	DebugInfo* di = VG_(next_DebugInfo) ( NULL );
	MY_LOGI("Try to add mon lib %s di=0x%08x\n", libname, (Addr)di);
	while(di) {
		soname = VG_(DebugInfo_get_filename)(di);
		if( VG_(strcmp)(libname, soname) == 0 ) {
			Int i = 0;
			VG_(print_sym_table)(di);
			while(VG_(get_rx_mapping_index) (di, i, &avma, &size)) {
				addFilterList( &sysLibList, soname, avma, size );
				MY_LOGI("Add mon lib rx map: 0x%08x-0x%08x %s\n", avma, avma+size, soname);
				i++;
			}
			//addFilterList( &monLibList, soname, avma, size );
		}
		di = VG_(next_DebugInfo)(di);
	}
}
Bool isMonitorLib(Addr addr, HChar** libname)
{
	if (isInFilterList(monLibList, addr, libname) > 0)
		return True;
	return False;
}

void initSysLib() {
	HChar *soname;
	Addr avma;
	SizeT size;
	DebugInfo* di = VG_(next_DebugInfo) ( NULL );
	MY_LOGI("first di_0x%x\n", (Addr)di);
	Int i = 0;
	while(di) {
		soname = VG_(DebugInfo_get_filename)(di);
		// soname = VG_(DebugInfo_get_soname)(di);
		// avma = VG_(DebugInfo_get_text_avma) (di);
		// size = VG_(DebugInfo_get_text_size) (di);
		i = 0;
		while(VG_(get_rx_mapping_index) (di, i, &avma, &size)) {
			if(soname[1] == 's') {
				addFilterList( &sysLibList, soname, avma, size );
				delMonMap(avma, size);
				MY_LOGI("Add sys rx map: 0x%08x-0x%08x %s\n", avma, avma+size, soname);
			}
			i++;
		}
#if 0
		if(VG_(strcmp)("/system/bin/linker", soname) == 0) {
			//VG_(print_sym_table)(di);
			VG_(get_symbol_range_SLOW)(di, "__dl_dlopen", &dlopen_addr, &size);
			MY_LOGI("__dl_dlopen: 0x%08x-0x%08x\n", dlopen_addr, dlopen_addr+size);
			dlopen_addr = dlopen_addr & 0xfffffffe;
			VG_(get_symbol_range_SLOW)(di, "__dl__Z19dlsym_handle_lookupP6soinfoPS0_PKc", &dlsym_addr, &size);
			MY_LOGI("__dl_dlsym: 0x%08x-0x%08x\n", dlsym_addr, dlsym_addr+size);
			dlsym_addr = dlsym_addr & 0xfffffffe;

		}
#endif
		di = VG_(next_DebugInfo)(di);
	}
}


Addr isSysLib(Addr addr, HChar** libname)
{
	return isInFilterList(sysLibList, addr, libname);
}

void addMonMap(Addr addr, Int size, Int prot, HChar *info)
{
	addFilterList(&monMemList, info, addr, size);
	MY_LOGI("Add mon mem map: 0x%08x-0x%08x %s\n", addr, addr+size, info);
}

UInt getMonMapSize(Addr a) {
	struct FilterList* tfl = monMemList;
	while ( tfl ) {
		if( a == tfl->begin ) {
			return tfl->end - tfl->begin;
		}
		tfl = tfl->next;
	}
	return 0;
}

Addr isMonMap(Addr addr, HChar** libname)
{
	return isInFilterList(monMemList, addr, libname);
}

Bool getMemMapInfo(Addr addr, Int prot, HChar **pinfo)
{
	Addr a = isInFilterList(monMemList, addr, pinfo);
	if(a > 0) {
		return True;
	} else {
		return False;
	}
}

void delMonMap(Addr addr, Int size)
{
	delFilterList(&monMemList, "memory.map",  addr, size);
}

/* If fnname is null, all the .text section is added to the filter list;
 * else only the code range of symbol funname in soname is added */
Bool addFilterFun(const HChar* soname, const HChar* fnname) {
	struct LibList *tll = llist;
	struct FunList *tfl, *nfl;
	tl_assert(soname);
	while( tll ) {
		if( VG_(strcmp)(soname, tll->name) == 0) {
			break;
		}
		tll = tll->next;
	}
	/* add new library to the head of the filter list */
	if( !tll ) {
		tll = (struct LibList*)VG_(malloc)("addFilterFun.1", sizeof(struct LibList));
		tl_assert(tll);
		VG_(strcpy)(tll->name, soname);
		tll->flist = NULL;
		tll->next = llist;
		llist = tll;
	}
	/* the libaray alread exists in filter list */
	tfl = tll->flist;
	if( fnname ) {
		while( tfl ) {
			if(VG_(strcmp)(fnname, tfl->name) == 0) {
				MY_LOGI("add %s in %s already existed\n", fnname, soname);
				return False;
			}
			tfl = tfl->next;
		}
		/* Add one new function node to the head of lib's function list */
		tfl = (struct FunList*)VG_(malloc)("addFilterFun.2", sizeof(struct FunList));
		VG_(strcpy)(tfl->name, fnname);
		tfl->next = tll->flist;
		tll->flist = tfl;
		//MY_LOGI("add %s in %s\n", fnname, soname);
		return True;
	} else { /* Add all lib's .text section to filter list */
		while( tfl ) {
			nfl = tfl->next;
			VG_(free)(tfl);
			tfl = nfl;
		}
		tll->flist = NULL;
		//MY_LOGI("all .text in %s added\n", soname);
		return True;
	}
}

/* Get the library filter node of soname */
static struct LibList* findLib(const HChar* soname) {
	MY_LOGI("Check so %s\n", soname);
	struct LibList *tll = llist;
	while ( tll ) {
		if( VG_(strcmp) ( soname, tll->name ) == 0 )
			return tll;
		tll = tll->next;
	}
	return NULL;
}

void freeAllList(void) 
{
	releaseFilterList(&sysLibList);
	releaseFilterList(&monLibList);
	releaseFilterList(&monMemList);
	releaseFilterList(&dumpMemList);
}


void dumpMemMap(Addr a) {
	UInt s = 0, size = 0;
	VG_(printf)("Try to dump map memory.\n");
	Addr beg = isInFilterList(dumpMemList, a, NULL);
	if(beg > 0) {
			return;
	}
	beg = isMonMap(a, NULL);
	if(beg == 0) {
		return;
	}
	s = getMonMapSize(beg);
	while ( s > 0 ) {
		size = size + s;
		s = getMonMapSize(beg + size);
	}
	if (size > 0) {
		dumpBinary(beg, size);
	}
	addFilterList(&dumpMemList, NULL, beg, size);
}

/*-------------------- End ------------------------------*/
