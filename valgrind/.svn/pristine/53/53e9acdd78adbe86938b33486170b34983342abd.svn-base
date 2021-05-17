#ifndef _FZ_WRAPPERS_h
#define _FZ_WRAPPERS_h

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"

#include "util.h"

#define	STACK_TRACE_SIZE					20
#define	BG_MALLOC_REDZONE_SZB			16

#define FNNAME_MAX 100

#define FD_MAX      256               
#define FD_MAX_PATH 256 
#define FD_READ     0x1
#define FD_WRITE    0x2 
#define FD_STAT     0x4
#define TG_N_THREADS 500 
    
  
#define VAR_MAX     100
#define VAR_READ    0x1 
#define VAR_WRITE   0x2


struct iovec {
	Addr  iov_base;
	Int		iov_len;
};


enum OpenedFdType { 
	FdSystemLib = 1,
	FdFrameworkJar,
	FdFrameworkDex,
	FdFrameworkOat,
	FdDevice,
	FdProcMap,
	FdAppLib,
	FdAppDex,
	FdAppOat,
	FdAppOdex,
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


/* Copy from mman.h */
#define PROT_NONE       0x00            /* page can not be accessed */
#define PROT_READ       0x01            /* page can be read */
#define PROT_WRITE      0x02            /* page can be written */
#define PROT_EXEC       0x04            /* page can be executed */

#define MAP_SHARED	0x01			/* Share changes.  */
#define MAP_PRIVATE	0x02			/* Changes are private.  */

#define MAP_FIXED	0x10				/* Interpret addr exactly.  */
#define MAP_FILE	0
#define MAP_ANONYMOUS	0x20    /* Don't use a file.  */
#define MAP_ANON	MAP_ANONYMOUS

#define MAP_DENYWRITE	0x0800  /* ETXTBSY */
#define MAP_FOOBAR	0x0800  /* ETXTBSY */


extern VgHashTable	*do_malloc_list;
extern struct FilterList *fl; /* Filter list of system libraries */
extern struct FilterList *dml;
extern struct FilterList *dlibl; /* List of the importy address realated to file data (mmap/read) */
extern struct FilterList *m_list;

void* do_malloc			          ( ThreadId tid, SizeT n );                                                                                                                      
void* do_builtin_new		      ( ThreadId tid, SizeT n );                                                                                                                      
void* do_builtin_vec_new		  ( ThreadId tid, SizeT n );                                                                                                                      
void* do_memalign			        ( ThreadId tid, SizeT align, SizeT n );                                                                                                         
void* do_calloc		            ( ThreadId tid, SizeT nmemb, SizeT size1 );                                                                                                     
void  do_free		              ( ThreadId tid, void* p );                                                                                                                      
void  do_builtin_delete		    ( ThreadId tid, void* p );                                                                                                                      
void  do_builtin_vec_delete		( ThreadId tid, void* p );                                                                                                                      
void* do_realloc							( ThreadId tid, void* p, SizeT new_size );                                                                                                      
SizeT do_malloc_usable_size		( ThreadId tid, void* p );


/* Functions defined in dt_syswrap.c */
/* System call wrappers */
extern void DO_(syscall_pre_execve)(ThreadId tid, UWord* args, UInt nArgs);
extern void DO_(syscall_pre_fork)(ThreadId tid, UWord* args, UInt nArgs);
extern void DO_(syscall_pre_exit)(ThreadId tid, UWord* args, UInt nArgs);
extern void DO_(syscall_pre_unlinkat)(ThreadId tid, UWord* args, UInt nArgs); 
extern void DO_(syscall_pre_ptrace)( ThreadId tid, UWord* args, UInt nArgs);
extern void DO_(syscall_pre_rt_sigreturn)( ThreadId tid, UWord* args, UInt nArgs);
 
extern void DO_(syscall_futex)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_flock)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_ptrace)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_fork)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_execv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_unlink)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_unlinkat)(ThreadId tid, UWord* args, UInt nArgs, SysRes res); 
extern void DO_(syscall_mmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_mprotect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_munmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_readv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_preadv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_writev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_pwritev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_madvise)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern Bool DO_(syscall_allowed_check)(ThreadId tid, int syscallno);
extern void DO_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_setuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_setreuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_setgid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_setregid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_connect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_rt_sigreturn)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_fstatat)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void DO_(syscall_rt_inotify_add_watch)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);

#endif
