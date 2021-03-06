#ifndef _FZ_WRAPPERS_h
#define _FZ_WRAPPERS_h

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"


#define	STACK_TRACE_SIZE					20
#define	BG_MALLOC_REDZONE_SZB			16


struct iovec {
	Addr  iov_base;
	Int		iov_len;
};


enum OpenedFdType { 
	FdSystemLib = 1,
	FdFrameworkJar,
	FdFrameworkDex,
	FdDevice,
	FdProcMap,
	FdAppLib,
	FdAppDex,
	FdAppApk,
	FdAppJar,
	FdUnknown
};

struct fd_info {
	HChar name[255];
	UInt	offset;
	enum OpenedFdType  type;
};

struct MemList {
	HChar	name[255];
	Addr	addr;
	Int		size;
	Int   prot;
	struct MemList *next;
};

/* This describes a heap block. Nb: first two fields must match core's 
 * VgHashNode. */
typedef struct _HP_Chunk {
	struct	_HP_Chunk *next;
	Addr		data;								// Address of the actual block
	SizeT		req_szB;						// Size requested
	SizeT		slop_szB;						// Extra bytes given above those requested
} HP_Chunk;

extern	VgHashTable	*fz_malloc_list;

void* fz_malloc			          ( ThreadId tid, SizeT n );                                                                                                                      
void* fz_builtin_new		      ( ThreadId tid, SizeT n );                                                                                                                      
void* fz_builtin_vec_new		  ( ThreadId tid, SizeT n );                                                                                                                      
void* fz_memalign			        ( ThreadId tid, SizeT align, SizeT n );                                                                                                         
void* fz_calloc		            ( ThreadId tid, SizeT nmemb, SizeT size1 );                                                                                                     
void  fz_free		              ( ThreadId tid, void* p );                                                                                                                      
void  fz_builtin_delete		    ( ThreadId tid, void* p );                                                                                                                      
void  fz_builtin_vec_delete		( ThreadId tid, void* p );                                                                                                                      
void* fz_realloc							( ThreadId tid, void* p, SizeT new_size );                                                                                                      
SizeT fz_malloc_usable_size		( ThreadId tid, void* p );

#endif
