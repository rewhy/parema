#ifndef _UTIL_H
#define _UTIL_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

#define FZ_LOG_TAINT
#undef  FZ_LOG_TAINT

#define FZ_LOG_SYM
#undef  FZ_LOG_SYM

#define FZ_EXE_TAINT
//#undef  FZ_EXE_TAINT

#define FZ_LOG_IR
//#undef  FZ_LOG_IR


typedef
enum {
	VG_USERREQ__WRAPPER_ART_OPENMEMORY_PRE,
	VG_USERREQ__WRAPPER_ART_OPENMEMORY,
	VG_USERREQ__WRAPPER_ART_DEXFILE
} Vg_MethodTraceClientRequest;

#define REG(offset) armRegs[(offset - 8) / 4]

UChar pformat3[256];
#define ART_INVOKE(fmt, x...) \ 
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[Invoke %3d]: %s", stackSize, fmt); \
			VG_(printf)(pformat3, ##x); \
	} while(0)

#define ART_RETURN(fmt, x...) \
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[Return %3d]: %s", stackSize, fmt); \
		VG_(printf)(pformat3, ##x); \
	} while(0)


UChar pformat[256];
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


#ifdef FZ_LOG_IR
UChar pformat1[256];
//if(isExploring == False) return;
#define	ST_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[STMT %d] %s", VG_(get_running_tid)(), fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)
#else
#define ST_LOGI(fmt, x...) do{}while(0)
#endif

UChar pformat3[256];
#define	EXP_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[EXP %d] %s", VG_(get_running_tid)(), fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)

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

#define DO_CREQ_W_WWW(_resF, _dfltF, _creqF, _ty1F,_arg1F, \
		_ty2F,_arg2F, _ty3F, _arg3F)       \
do {                                                  \
	long int _qzz_res;                                 \
	long int _arg1, _arg2, _arg3;                      \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	_qzz_res = VALGRIND_DO_CLIENT_REQUEST_EXPR(        \
			(_dfltF),               \
			(_creqF),               \
			_arg1,_arg2,_arg3,0,0); \
	_resF = _qzz_res;                                  \
} while (0)

#define DO_CREQ_v_WWWW(_creqF, _ty1F,_arg1F,             \
		_ty2F, _arg2F, _ty3F, _arg3F,     \
		_ty4F, _arg4F)                    \
do {                                                  \
	Word _arg1, _arg2, _arg3, _arg4;                   \
	_arg1 = (Word)(_arg1F);                            \
	_arg2 = (Word)(_arg2F);                            \
	_arg3 = (Word)(_arg3F);                            \
	_arg4 = (Word)(_arg4F);                            \
	VALGRIND_DO_CLIENT_REQUEST_STMT((_creqF),          \
			_arg1,_arg2,_arg3,_arg4,0); \
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


void IROp_to_str(IROp op, char* buffer);
int IRLoadGOp_to_str(IRLoadGOp lop, char* buffer);

#endif // UTIL_H
