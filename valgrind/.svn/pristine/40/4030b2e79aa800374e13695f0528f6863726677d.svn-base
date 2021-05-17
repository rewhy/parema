#ifndef _DT_DEBUG_H
#define _DT_DEBUG_H

/*----------------------------------------------------*/
/*----- Debug output helpers for client wrapper  -----*/
/*----------------------------------------------------*/
#define DT_DEBUG		0
#define DBG_MEM			0
#define DBG_SYSCALL	0
//#define DBG_LOAD		1
//#define DBG_STORE		1

//#define DBG_TAINT_SET 1

extern Bool output_log_info;
#define DBG_INSTRUMENT	0
#define DBT_TAINT_INFO	0

#define DBG_FRAMEWORK		0
#define DBG_PARAMETER_PARSE 0

#define DBG_CURRENT_LINE	VG_(printf)("[L][%-12s:%-4d] [%-24s]\n", __FILE__, __LINE__, __func__)

#ifdef	DEBUG_CLIENT_REQUEST
#define DBG_REQUEST_INFO(fmt, x...)	\
	do {															\
		VG_(printf)(fmt, ##x);					\
	} while(0)
#else
#define DBG_REQUEST_INFO(fmt, x...)	\
	do { } while(0)
#endif // DEBUG_CLIENT_REQUEST

#ifdef	DEBUG_FRAMEWORK
#undef  DEBUG_FRAMEWORK
#define FRM_LOGI(fmt, x...)	\
	if(output_log_info) {															\
		VG_(printf)(fmt, ##x);					\
	}
#else
#define FRM_LOGI(fmt, x...)	\
	do { } while(0)
#endif // DEBUG_CLIENT_REQUEST
/*-------------------- End ---------------------------*/

/*----------------------------------------------------*/
/*----- Debug output helpers for force execution -----*/
/*----------------------------------------------------*/
#if 0
	//do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[I][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)
#endif
#ifdef DT_DEBUG
UChar pformat[256];
#define	DT_LOGI(fmt, x...) \
	if(output_log_info) {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[I]%s", fmt);	\
		VG_(printf)(pformat, ##x);	\
	}

#define	DT_LOGE(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[I][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat, ##x);	\
		tl_assert(0); \
	} while(0)

#define DT_EXE_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[F][%-12s:%-4d] [%-24s] %s",     \
				__FILE__, __LINE__, __func__, fmt); \
		VG_(printf)(pformat, ##x);  \
	} while(0) 
#define DT_ASSERT(aaa) \
	tl_assert(aaa)
#else
#define DT_LOGI(fmt, x...) ;
#define DT_LOGE(fmt, x...) ;
#define DT_ASSERT(aaa) \
	tl_assert(aaa)
#define DT_EXE_LOGI(fmt, x...) ;
#endif // DT_DEBUG

#ifdef DBG_MEM
UChar pformat1[256];
#define DBG_MEM_INFO(fmt, x...) \
	if(output_log_info) {\
		VG_(snprintf)(pformat1, sizeof(pformat1), \
				"[I][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat1, ##x);	\
	}
#else
#define DBG_MEM_INFO(fmt, x...) ;
#endif // DBG_MEM

#ifdef DBG_SYSCALL
UChar pformat2[256];
#define DBG_SYSCALL_INFO(fmt, x...) \
	if(output_log_info) {\
		VG_(snprintf)(pformat2, sizeof(pformat2), \
				"[S] %s", fmt);	\
		VG_(printf)(pformat2, ##x);	\
	}
#else
#define DBG_SYSCALL_INFO(fmt, x...) ;
#endif // DBG_SYSCALL

UChar pformat3[256];
#define ART_INVOKE(fmt, x...) \
	if(output_log_info){ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"Invoke: %s", fmt); \
		VG_(printf)(pformat3, ##x); \
	}
#define ART_RETURN(fmt, x...) \
	if(output_log_info){ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"Return: %s", fmt); \
		VG_(printf)(pformat3, ##x); \
	}
#define ART_LOGI(fmt, x...) \
	if(output_log_info){ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[I]: %s", fmt); \
		VG_(printf)(pformat3, ##x); \
	};
#define ART_LOGW(fmt, x...) \
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), \
				"[W]: %s", fmt); \
		VG_(printf)(pformat3, ##x); \
	} while(0)

#ifdef DBT_TAINT_INFO
UChar pformat4[256];
#define TNT_LOGI(fmt, x...) \
	if(output_log_info) {\
		VG_(snprintf)(pformat4, sizeof(pformat4), \
				"\t%s", fmt);	\
		VG_(printf)(pformat4, ##x);	\
	}
#else
#define TNT_LOGI(fmt, x...) do{}while(0); 
#endif // DBT_TAINT_INFO

/*------------------------  End  --------------------------*/
#endif // _DT_DEBUG_H
