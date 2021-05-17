#ifndef _DT_WRAPPERS_h
#define _DT_WRAPPERS_h

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"

#include "dt_taint.h"

#define	STACK_TRACE_SIZE					20
#define	DT_MALLOC_REDZONE_SZB			16

enum InvokeType {
   kStatic,     // <<static>>
   kDirect,     // <<direct>>
   kVirtual,    // <<virtual>>
   kSuper,      // <<super>>
   kInterface,  // <<interface>>
   kMaxInvokeType = kInterface
};

enum PrimType {                      
   kPrimNot = 0,
   kPrimBoolean,
   kPrimByte,
   kPrimChar,
   kPrimShort,
   kPrimInt,
   kPrimLong,
   kPrimFloat,
   kPrimDouble,
   kPrimVoid,
};  


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

/*------------------------------------------------------------*/
/*--- Profiling of memory events                           ---*/
/*------------------------------------------------------------*/

/* Define to collect detailed performance info. */
#define DT_PROFILE_MEMORY
#undef  DT_PROFILE_MEMORY

#ifdef DT_PROFILE_MEMORY
#  define N_PROF_EVENTS 500

UInt   DT_(event_ctr)[N_PROF_EVENTS];
HChar* DT_(event_ctr_name)[N_PROF_EVENTS];

#  define PROF_EVENT(ev, name) \
	do { tl_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);     \
		/* crude and inaccurate check to ensure the same */  \
		/* event isn't being used with > 1 name */           \
		if (DT_(event_ctr_name)[ev])                         \
		tl_assert(name == DT_(event_ctr_name)[ev]);          \
		DT_(event_ctr)[ev]++;                                \
		DT_(event_ctr_name)[ev] = (name);                    \
	} while (False);
#else
#  define PROF_EVENT(ev, name) /* */
#endif   /* DT_PROFILE_MEMORY */

/* This describes a heap block. Nb: first two fields must match core's 
 * VgHashNode. */
typedef struct _HP_Chunk {
	struct	_HP_Chunk *next;
	Addr		data;								// Address of the actual block
	SizeT		req_szB;						// Size requested
	SizeT		slop_szB;						// Extra bytes given above those requested
} HP_Chunk;

extern	VgHashTable	*DT_(malloc_list);

void* DT_(malloc)               ( ThreadId tid, SizeT n ); 
void* DT_(__builtin_new)        ( ThreadId tid, SizeT n );
void* DT_(__builtin_vec_new)    ( ThreadId tid, SizeT n );
void* DT_(memalign)             ( ThreadId tid, SizeT align, SizeT n );
void* DT_(calloc)               ( ThreadId tid, SizeT nmemb, SizeT size1 );
void  DT_(free)                 ( ThreadId tid, void* p );
void  DT_(__builtin_delete)     ( ThreadId tid, void* p );
void  DT_(__builtin_vec_delete) ( ThreadId tid, void* p );
void* DT_(realloc)              ( ThreadId tid, void* p, SizeT new_size );
SizeT DT_(malloc_usable_size)   ( ThreadId tid, void* p );


/* Functions defined in dt_syswrap.c */
/* System call wrappers */
extern void DT_(syscall_execv)(tid, args, nArgs);
extern void DT_(syscall_pre_unlinkat)(tid, args, nArgs);

extern void DT_(syscall_unlink)(tid, args, nArgs, res);
extern void DT_(syscall_unlinkat)(tid, args, nArgs, res);
extern void DT_(syscall_mmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_mprotect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_munmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);

extern void DT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_readv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_writev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_pwritev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern Bool DT_(syscall_allowed_check)(ThreadId tid, int syscallno);
extern void DT_(syscall_send)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_sendto)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);

extern void DT_(syscall_setuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_setreuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_setgid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_setregid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_connect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DT_(syscall_rt_sigreturn)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);

/* SOAAP-related data */
extern HChar* client_binary_name;
#define FNNAME_MAX 100

//extern UInt persistent_sandbox_nesting_depth;
//extern UInt ephemeral_sandbox_nesting_depth;
//extern Bool have_created_sandbox;

#define FD_MAX			256              
#define FD_MAX_PATH	256
#define FD_READ			0x1
#define FD_WRITE		0x2
#define FD_STAT			0x4
#define TG_N_THREADS 500 

extern Bool tainted_fds[TG_N_THREADS][FD_MAX];
extern Bool DT_(dex_is_open);
extern struct fd_info	fds[TG_N_THREADS][FD_MAX];

extern UInt shared_fds[];
#define VAR_MAX			100
#define	VAR_READ		0x1
#define VAR_WRITE		0x2

enum VariableType { Local = 3, Global = 4 };
enum VariableLocation { GlobalFromApplication = 5, GlobalFromElsewhere = 6 };

//#define IN_SANDBOX (persistent_sandbox_nesting_depth > 0 || ephemeral_sandbox_nesting_depth > 0)


#define SYSCALLS_MAX	500
extern Bool allowed_syscalls[];
#define IS_SYSCALL_ALLOWED(no) (allowed_syscalls[no] == True)

#endif // _DT_WRAPPERS_H
