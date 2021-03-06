#ifndef _UTIL_H
#define _UTIL_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

#define FZ_SYM_EXE
#undef  FZ_SYM_EXE

#define REPLACE_GETTIMEOFDAY


#ifdef DE_VMP_TRACE
#undef DE_VMP_TRACE
#endif

#define BAIDU_VMP
#undef  BAIDU_VMP

#define DBG_TENCENT		0

#define FZ_DEBUG
#undef  FZ_DEBUG

#define DBG_MOD_IR
#undef	DBG_MOD_IR

//
#define DBG_SYSCALL
//#undef DBG_SYSCALL

#define DO_INSTRUMENTATION
#undef	DO_INSTRUMENTATION

#define DO_INS_LOAD
#undef  DO_INS_LOAD

#define DO_INS_STORE
#undef  DO_INS_STORE

#ifndef INLINE
#define INLINE      inline __attribute__((always_inline))
#endif

#define DO_(str)    VGAPPEND(vgDeofuscator_,str)



typedef	unsigned short	sa_family_t;
typedef int							socklen_t;

struct sockaddr {
	UShort sa_family;
	UChar sa_data[14];
};

struct in_addr {
	unsigned long s_addr;
};

struct sockaddr_in {
	Short	sa_family;
	UShort	sa_port;
	struct	in_addr	addr;
	HChar		sa_zero[8];
};

#define AF_UNSPEC       0
#define AF_UNIX         1       /* Unix domain sockets          */
#define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
#define AF_INET         2       /* Internet IP Protocol         */

#define NTOHL(n)	((((n) & 0xff) << 24)	\
		| (((n) & 0xff00) << 8) \
		| (((n) & 0xff0000) >> 8) \
		| (((n) & 0xff000000) >> 24))

#define HTONL(n)	((((n) & 0xff) << 24)	\
		| (((n) & 0xff00) << 8) \
		| (((n) & 0xff0000) >> 8) \
		| (((n) & 0xff000000) >> 24))

#define NTOHS(n)	((((UShort)(n) & 0xff00) >> 8) \
		| (((UShort)(n) & 0x00ff) << 8))

#define HTONS(n)	((((UShort)(n) & 0xff00) >> 8) \
		| (((UShort)(n) & 0x00ff) << 8))

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


typedef
enum {
	VG_USERREQ__WRAPPER_DLOPEN_PRE,
	VG_USERREQ__WRAPPER_DLOPEN,
	VG_USERREQ__WRAPPER_DLSYM_PRE,
	VG_USERREQ__WRAPPER_DLSYM,
	VG_USERREQ__WRAPPER_LIBC_STRLEN,
	VG_USERREQ__WRAPPER_LIBC_STRDUP,
	VG_USERREQ__WRAPPER_LIBC_STRCPY,
	VG_USERREQ__WRAPPER_LIBC_MEMCPY,
	VG_USERREQ__WRAPPER_LIBC_KILL,
	VG_USERREQ__WRAPPER_LIBC_EXIT,
	VG_USERREQ__WRAPPER_LIBC_EXIT_GROUP,
	VG_USERREQ__WRAPPER_LIBC_ABORT,
	VG_USERREQ__WRAPPER_LIBC_GETTIMEOFDAY,
	VG_USERREQ__WRAPPER_LIBC_CLOCK_GETTIME,
	VG_USERREQ__WRAPPER_LIBC_INOTIFY_ADD_WATCH,
	VG_USERREQ__WRAPPER_LIBC_SOCKET,
	VG_USERREQ__WRAPPER_LIBC_LISTEN,
	VG_USERREQ__WRAPPER_LIBC_BIND,
	VG_USERREQ__WRAPPER_LIBC_ACCEPT,
	VG_USERREQ__WRAPPER_LIBC_CONNECT_PRE,
	VG_USERREQ__WRAPPER_LIBC_CONNECT,
	VG_USERREQ__WRAPPER_LIBC_SEND,
	VG_USERREQ__WRAPPER_LIBC_SENDTO,
	VG_USERREQ__WRAPPER_LIBC_RECV_PRE,
	VG_USERREQ__WRAPPER_LIBC_RECV,
	VG_USERREQ__WRAPPER_LIBC_RECVFROM_PRE,
	VG_USERREQ__WRAPPER_LIBC_RECVFROM,
	VG_USERREQ__WRAPPER_REP_STRLEN,
	VG_USERREQ__WRAPPER_REP_STRCMP,
	VG_USERREQ__WRAPPER_REP_STRCASECMP,
	VG_USERREQ__WRAPPER_REP_STRNCMP,
	VG_USERREQ__WRAPPER_REP_STRNCASECMP,
	VG_USERREQ__WRAPPER_REP_MEMCMP,
	VG_USERREQ__WRAPPER_REP_MEMCPY,
	VG_USERREQ__WRAPPER_REP_MEMSET,
	VG_USERREQ__WRAPPER_REP_STRSTR,
	VG_USERREQ__WRAPPER_REP_STRCPY,
	VG_USERREQ__WRAPPER_REP_STRNCPY,
	VG_USERREQ__WRAPPER_REP_MEMMOVE_OR_MEMCPY,
	VG_USERREQ__WRAPPER_ART_FINDNATIVEMETHOD,
	VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE,
	VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY,
	VG_USERREQ__WRAPPER_ART_OPENMEMORY_PRE,
	VG_USERREQ__WRAPPER_ART_OPENMEMORY,
	VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE,
	VG_USERREQ__WRAPPER_ART_DEFINECLASS,
	VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS_PRE,
	VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS,
	VG_USERREQ__WRAPPER_ART_LOADCLASS_PRE,
	VG_USERREQ__WRAPPER_ART_LOADCLASS,
	VG_USERREQ__WRAPPER_ART_CALLMETHODV,
	VG_USERREQ__WRAPPER_ART_CALLMETHODA,
	VG_USERREQ__WRAPPER_ART_INVOKEMETHOD,
	VG_USERREQ__WRAPPER_ART_GETSTRINGUTFCHARS,
	VG_USERREQ__WRAPPER_ART_JNIFINDCLASS,
	VG_USERREQ__WRAPPER_ART_INVOKEWITHVARARGS,
	VG_USERREQ__WRAPPER_ART_INVOKEWITHJVALUES,
	VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHJVALUES,
	VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHVARARGS,
	VG_USERREQ__WRAPPER_ART_JNIGETMETHODID,
	VG_USERREQ__WRAPPER_ART_INVOKEWITHARGARRAY,
	VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID,
	VG_USERREQ__WRAPPER_ART_DEXFILE,
	VG_USERREQ__WRAPPER_ART_INVOKE_PRE,
	VG_USERREQ__WRAPPER_ART_INVOKE,
	VG_USERREQ__WRAPPER_ART_REGISTERNATIVE,
	VG_USERREQ__WRAPPER_ART_CALLSTATICOBJECTMETHODV_PRE,
	VG_USERREQ__WRAPPER_ART_JNI_NEWGLOBALREF,
	VG_USERREQ__WRAPPER_ART_JNI_NEWCHARARRAY,
	VG_USERREQ__WRAPPER_ART_JNI_NEWBYTEARRAY,
	VG_USERREQ__WRAPPER_ART_JNI_NEWINTARRAY,
	VG_USERREQ__WRAPPER_ART_JNI_NEWOBJECTARRAY,
	VG_USERREQ__WRAPPER_ART_CALLSTATICOBJECTMETHODV,
	VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD,
	VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE
} Vg_MethodTraceClientRequest;



#define REG(offset) armRegs[(offset - 8) / 4]

UChar pformat2[256];
#define WRAP_INVOKE(fmt, x...) \ 
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[WRAP] %s", fmt); \
			VG_(printf)(pformat3, ##x); \
	} while(0)

UChar pformat3[256];
#define ART_INVOKE(fmt, x...) \ 
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[CALL] %s", fmt); \
			VG_(printf)(pformat3, ##x); \
	} while(0)

#define ART_RETURN(fmt, x...) \
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[RETU] %s", fmt); \
		VG_(printf)(pformat3, ##x); \
	} while(0)


UChar pformat[256];
#define SYS_LOGI(fmt, x...) \
	do{\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[SYSC] %s", fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)
#define	MY_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[INFO] %s", fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)
#define	MY_LOGW(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[WARN] %s", fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)
#define	MY_LOGE(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[ERRO] %d %s", __LINE__, fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)


#if 0
#endif
#define	ST_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[STMT] %d %s", VG_(get_running_tid)(), fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)

//	VG_(printf)(fmt, ##x)
//#define ST_LOGI(fmt, x...) do{}while(0)

UChar pformat4[256];
#define TNT_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat4, sizeof(pformat4), \
				"\t%s", fmt);	\
		VG_(printf)(pformat4, ##x);	\
	} while(0)


#define T380
#undef  T380


//typedef unsigned int size_t;

#undef DO_CREQ_v_W
#undef DO_CREQ_W_W
#undef DO_CREQ_v_WW
#undef DO_CREQ_W_WW
#undef DO_CREQ_v_WWW
#undef DO_CREQ_W_WWW
#undef DO_CREQ_v_WWWW
#undef DO_CREQ_v_WWWWW

#define DO_CREQ_v_W(_creqF, _ty1F,_arg1F)                \
	do {                                                  \
		long int _arg1;                                    \
		_arg1 = (long int)(_arg1F);                        \
		VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
				(_creqF),               \
				_arg1, 0,0,0,0);        \
	} while (0)

#define DO_CREQ_W_W(_resF, _dfltF, _creqF, _ty1F,_arg1F) \
	do {                                                  \
		long int _arg1;                                    \
		_arg1 = (long int)(_arg1F);                        \
		_qzz_res = VALGRIND_DO_CLIENT_REQUEST_EXPR(        \
				(_dfltF),               \
				(_creqF),               \
				_arg1, 0,0,0,0);        \
		_resF = _qzz_res;                                  \
	} while (0)

#define DO_CREQ_v_WW(_creqF, _ty1F,_arg1F, _ty2F,_arg2F) \
	do {                                                  \
		long int _arg1, _arg2;                             \
		_arg1 = (long int)(_arg1F);                        \
		_arg2 = (long int)(_arg2F);                        \
		VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
				(_creqF),               \
				_arg1,_arg2,0,0,0);     \
	} while (0)

#define DO_CREQ_v_WWW(_creqF, _ty1F,_arg1F,              \
		_ty2F,_arg2F, _ty3F, _arg3F)       \
do {                                                  \
	long int _arg1, _arg2, _arg3;                      \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
			(_creqF),               \
			_arg1,_arg2,_arg3,0,0); \
} while (0)

#define DO_CREQ_W_WWW(_resF, _creqF, _ty1F,_arg1F, \
		_ty2F,_arg2F, _ty3F, _arg3F)       \
do {                                                  \
	long int _qzz_res;                                 \
	long int _arg1, _arg2, _arg3;                      \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	_qzz_res = VALGRIND_DO_CLIENT_REQUEST_EXPR(        \
			(-2),               \
			(_creqF),               \
			_arg1,_arg2,_arg3,0,0); \
	_resF = _qzz_res;                                  \
} while (0)

#define DO_CREQ_v_WWWW(_creqF, _ty1F,_arg1F,         \
		_ty2F, _arg2F, _ty3F, _arg3F,     \
		_ty4F, _arg4F)                    \
do {                                                 \
	Word _arg1, _arg2, _arg3, _arg4;                   \
	_arg1 = (Word)(_arg1F);                            \
	_arg2 = (Word)(_arg2F);                            \
	_arg3 = (Word)(_arg3F);                            \
	_arg4 = (Word)(_arg4F);                            \
	VALGRIND_DO_CLIENT_REQUEST_STMT((_creqF),          \
			_arg1,_arg2,_arg3,_arg4,0); \
} while (0)

#define DO_CREQ_W_WWWW(_resF, _creqF,        \
		_ty1F,_arg1F,                                    \
		_ty2F, _arg2F, _ty3F, _arg3F, _ty4F, _arg4F)     \
do { Word _qzz_res;																	 \
	Word _arg1, _arg2, _arg3, _arg4;                   \
	_arg1 = (Word)(_arg1F);                            \
	_arg2 = (Word)(_arg2F);                            \
	_arg3 = (Word)(_arg3F);                            \
	_arg4 = (Word)(_arg4F);                            \
	_qzz_res = VALGRIND_DO_CLIENT_REQUEST_EXPR(				 \
			(-2),					 \
			(_creqF),          \
			_arg1,_arg2,_arg3,_arg4,0); \
	_resF = _qzz_res;								\
} while (0)

#define DO_CREQ_v_WWWWW(_creqF, _ty1F,_arg1F,        \
		_ty2F, _arg2F, _ty3F, _arg3F,     \
		_ty4F, _arg4F, _ty5F, _arg5F)     \
do {                                                 \
	long int _arg1, _arg2, _arg3, _arg4, _arg5;        \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	_arg4 = (long int)(_arg4F);                        \
	_arg5 = (long int)(_arg5F);                        \
	VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
			(_creqF),                       \
			_arg1,_arg2,_arg3,_arg4,_arg5); \
} while (0)


HChar *inet_ntoa(struct in_addr in);
Int inet_aton(UChar *cp, struct in_addr *ap);
HChar* mmap_proto2a(Int flag);

void IROp_to_str(IROp op, char* buffer);
int IRLoadGOp_to_str(IRLoadGOp lop, char* buffer);

Bool dumpBinary(UChar* buf, UInt size);

#endif // UTIL_H
