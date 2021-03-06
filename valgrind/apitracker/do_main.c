#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"    // tl_assert()
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_machine.h"       // VG_(fnptr_to_fnentry)
#include "pub_tool_libcbase.h"      // VG_(strcmp)
#include "pub_tool_options.h"
#include "pub_tool_libcfile.h"      // VG_(readlink)
#include "pub_tool_vki.h"           // keeps libcproc.h happy, syscall nums

#include "pub_tool_guest.h"
#include "pub_tool_debuginfo.h"

#include "pub_core_threadstate.h"

#include "unistd-asm-arm.h"

#include "util.h"
#include "copy.h"
#include "do_oatplus.h"
#include "do_wrappers.h"
#include "do_oatplus.h"
#include "do_framework.h"
#include "do_oatdexparse.h"

#include "shadow_memory.h"
#include "taint_analysis.h"
#include "symbolic_execution.h"

#include "do_string.h"

#define MAX_DEXFILE_NUM	16

#define STR_COMPARE
#undef  STR_COMPARE

#define PARSE_RET_PARAMETER
#undef  PARSE_RET_PARAMETER

#define FZ_DEBUG
#undef  FZ_DEBUG

#define DBG_MOD_IR
#undef	DBG_MOD_IR

#define FZ_LOG_IR
//#undef  FZ_LOG_IR

#if DBG_OAT_PARSE
Bool is_parse_oat = False;
#endif 


Addr target_mem_addr = 0;
UInt target_mem_len  = 0;
static Addr dexFileObjs[MAX_DEXFILE_NUM] = {0};

HChar *mth_index_name[MAX_MTH_NUM] = {'\0'};

static Bool mytest = False;

static HChar* unknown_str = "????";
// export VALGRIND_LIB=/home/fanatic/valgrind-3.8.1/inst/lib/valgrind/

UChar codeLayer[TG_N_THREADS] = {0};

static Char* clo_fnname = NULL;
int fd_to_taint = 0;

static HChar *libartFunc = NULL;
static Addr libartFuncReturnAddr = 0;

static DebugInfo *di_libart = NULL;
static Addr libart_text_addr = 0;
static UInt libart_text_size = 0;

static Addr base_oatdata_addr = 0;
static UInt base_oatdata_size = 0;
static Addr base_oatexec_addr = 0;
static UInt base_oatexec_size = 0;

static Addr boot_oatdata_addr = 0;
static UInt boot_oatdata_size = 0;
static Addr boot_oatexec_addr = 0;
static UInt boot_oatexec_size = 0;

Int   do_start_method_index = -1;
HChar *do_start_method_name = NULL;
HChar *do_start_method_shorty = NULL;
Int   do_stop_method_index = -1;
HChar *do_stop_method_name = NULL;
Addr  do_exit_addr = 0;
HChar *do_start_clazz = NULL;
HChar *do_main_activity = NULL;
HChar *do_stop_clazz = NULL;
UInt  do_time_slower = 1;

Bool do_is_start = False;
UInt is_trace_irst = 0;
UInt start_trace_irst = 0;
UInt is_in_vm = 0;

UInt is_monitor_memory_alloc = 0;

struct DexFilePlus *pMDexFileObj = NULL;
static Bool do_method_trace = False;

Bool is_in_openmemory = False;

Bool is_dump_raw = False;

const HChar* SHUTDOWN_HOW[3] = {
	"SHUT_RD",
	"SHUT_WR",
	"SHUT_RDWR"
};
/* Address family has 42 types in total, now we only suports the 11 most popular types */
const HChar* ADDRESS_FAMILY[11] = {
	/* 0*/"AF_UNSPEC",
	/* 1*/"AF_UNIX/LOCAL",
	/* 2*/"AF_INET",
	/* 3*/"AF_AX25",
	/* 4*/"AF_IPX",
	/* 5*/"AF_APPLETALK",
	/* 6*/"AF_NETROM",
	/* 7*/"AF_BRIDGE",
	/* 8*/"AF_ATMPVC",
	/* 9*/"AF_X25",
	/*10*/"AF_INET6",
	/*11*/"AF_ROSE",     /* Amateur Radio X.25 PLP       */
	/*12*/"AF_UNKNOWN",
	/*13*/"AF_MAX",      /* For now.. */
	/*14*/"AF_UNKNOWN",
	/*15*/"AF_UNKNOWN",
	/*16*/"AF_UNKNOWN",
	/*17*/"AF_PACKET"    /* Forward compat hook          */
};
/* Protocol family also has 42 types, each of which has one corresponding addres type */
const char* PROTOCOL_FAMILY[11] = {
	/* 0*/"PF_UNSPEC",
	/* 1*/"PF_UNIX/LOCAL",
	/* 2*/"PF_INET",
	/* 3*/"PF_AX25",
	/* 4*/"PF_IPX",
	/* 5*/"PF_APPLETALK",
	/* 6*/"PF_NETROM",
	/* 7*/"PF_BRIDGE",
	/* 8*/"PF_ATMPVC",
	/* 9*/"PF_X25",
	/*10*/"PF_INET6"
		/*11*/"PF_ROSE",   
	/*12*/"PF_UNKNOWN",
	/*13*/"PF_MAX",   
	/*14*/"PF_UNKNOWN",
	/*15*/"PF_UNKNOWN",
	/*16*/"PF_UNKNOWN",
	/*17*/"PF_PACKET" 
};

/* Socket type */
const HChar* SOCKET_TYPE[11] = {
	/* 0*/"SOCK_UNKNOWN",
	/* 1*/"SOCK_STREAM",
	/* 2*/"SOCK_DGRAM",
	/* 3*/"SOCK_RAM",
	/* 4*/"SOCK_RDM",
	/* 5*/"SOCK_SEQPACKET",
	/* 6*/"SOCK_UNKNOWN",
	/* 7*/"SOCK_UNKNOWN",
	/* 8*/"SOCK_UNKNOWN",
	/* 9*/"SOCK_UNKNOWN",
	/*10*/"SOCK_PACKET",
};

/* dexFileParse flags */
const HChar* DEXFILEPARSE_FLAG[3] = { 
	"kDexParseDefault",					//     = 0,
	"kDexParseVerifyChecksum",	//     = 1,
	"kDexParseContinueOnError"  //     = (1 << 1),
};


static UInt raw_file_index = 0;

static void dumpMemory(UInt index, UChar* a, UInt size) {
	tl_assert(a != 0);
	Int fout;
	HChar fpath[255];
	VG_(sprintf)(fpath, "/data/local/tmp/fuzz/0x%08x-0x%X-%d-%d.raw", (Addr)a, index, size, raw_file_index++);
	fout = VG_(fd_open)(fpath, VKI_O_WRONLY|VKI_O_TRUNC, 0);
	if (fout <= 0) {
		fout = VG_(fd_open)(fpath, VKI_O_CREAT|VKI_O_WRONLY, VKI_S_IRUSR|VKI_S_IWUSR);
		if( fout <= 0 ) {
			OAT_LOGI("Create raw file error.\n");
			return;
		}
	} 
	VG_(write)(fout, a, size);
	VG_(close)(fout);
	return True;
}
/*------------- Added for ART framework tracking ------------------*/


DebugInfo* di_art = NULL;

typedef
enum {
	NOTART_ADDR = 0,
	LIBART_ADDR,
	BASE_OATDATA_ADDR,
	BASE_OATEXEC_ADDR,
	BOOT_OATDATA_ADDR,
	BOOT_OATEXEC_ADDR
} exeAddressType;

static INLINE
UInt isBaseAddr(Addr addr) {
	if( (addr >= (base_oatdata_addr & 0xfffffffc)) && (addr < (base_oatdata_addr + base_oatdata_size)) )
		return 2; //BASE_OATDATA_ADDR;
	if( (addr >= (base_oatexec_addr & 0xfffffffc)) && (addr < (base_oatexec_addr + base_oatexec_size)) )
		return 3; //BASE_OATEXEC_ADDR;
	return 0;//NOTART_ADDR;
}
	static INLINE
UInt isSysAddr(Addr addr) 
{
	return isSysLib(addr, NULL);
}
	static INLINE
UInt isArtAddr(Addr addr) 
{
	if( (addr >= (libart_text_addr & 0xfffffffc))  && (addr < (libart_text_addr + libart_text_size)) )
		return 1; //LIBART_ADDR;
	if( (addr >= (base_oatdata_addr & 0xfffffffc)) && (addr < (base_oatdata_addr + base_oatdata_size)) )
		return 2; //BASE_OATDATA_ADDR;
	if( (addr >= (base_oatexec_addr & 0xfffffffc)) && (addr < (base_oatexec_addr + base_oatexec_size)) )
		return 3; //BASE_OATEXEC_ADDR;
	if( (addr >= (boot_oatdata_addr & 0xfffffffc)) && (addr < (boot_oatdata_addr + boot_oatdata_size)) )
		return 4; //BOOT_OATDATA_ADDR;
	if( (addr >= (boot_oatexec_addr & 0xfffffffc)) && (addr < (boot_oatexec_addr + boot_oatexec_size)) )
		return 5; //BOOT_OATEXEC_ADDR;
	return 0;//NOTART_ADDR;
}

static INLINE
Bool addDexFileObj(Addr addr) {
	struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)addr;
	for( UInt i = 0; i < MAX_DEXFILE_NUM; i++ ) {
		if(dexFileObjs[i] == 0) {
			if( pDexFileObj->begin_ > 0 && pDexFileObj->size_ > 0 ) {
				VG_(printf)("Added new Dex file object 0x%08x mem:0x%08x - 0x%08x\n", 
						addr, pDexFileObj->begin_, pDexFileObj->begin_ + pDexFileObj->size_);
				dexFileObjs[i] = addr;
				//dumpRawData(pDexFileObj->begin_, pDexFileObj->size_, 0);
				//DexMemParse(pDexFileObj->begin_, pDexFileObj->size_);
				return True;
			}
			break;
		} /*else if (dexFileObjs[i] == addr) {
				VG_(printf)("Added repeat Dex file object 0x%08x mem:0x%08x - 0x%08x\n", 
				addr, pDexFileObj->begin_, pDexFileObj->begin_ + pDexFileObj->size_);
			if( (pDexFileObj->begin_ > 0) && (pDexFileObj->size_ > 0) && (pDexFileObj == pMDexFileObj) ) {
				VG_(printf)("Added repeat Dex file object 0x%08x mem:0x%08x - 0x%08x\n", 
				addr, pDexFileObj->begin_, pDexFileObj->begin_ + pDexFileObj->size_);
				dumpRawData(pDexFileObj->begin_, pDexFileObj->size_, 0);
			} 
			break;
		}*/
	}
	return False;
}

void parseOatFile(HChar *oatFile) {
	HChar *soname = NULL;
	Addr avma, oatdata, oatexec;
	SizeT size, oatdataSize, oatexecSize;

	DebugInfo* di = VG_(next_DebugInfo) (NULL);
	while(di) {
		soname = VG_(DebugInfo_get_soname)(di);
		if(VG_(DebugInfo_is_oat)(di)) {
			MY_LOGI("Meet oat file: %s\n", soname);
			if((oatFile != NULL) && (VG_(strcmp)(soname, oatFile) != 0))
				continue;
			if(VG_(get_symbol_range_SLOW)(di, "oatdata", &oatdata, &oatdataSize)) {
				MY_LOGI("oatdata: 0x%08x - 0x%08x len=%d\n", oatdata, oatdata+oatdataSize, oatdataSize);
				if(VG_(get_symbol_range_SLOW)(di, "oatexec", &oatexec, &oatexecSize)) {
					MY_LOGI("oatexec: 0x%08x - 0x%08x len=%d\n", oatexec, oatexec+oatexecSize, oatexecSize);
					if( (VG_(strcmp)("classes.oat", soname) == 0) ) // Custom oat file of Qihoo
					//if( (VG_(strcmp)("base.odex", soname) == 0) ) // Custom oat file of Baidu
					{
#if DBG_OAT_PARSE
						is_parse_oat = True;
						//is_parse_oat = False;
#endif
						oatDexParse(oatdata, oatdataSize, oatexec, oatexecSize);
#if DBG_OAT_PARSE
						is_parse_oat = False;
#endif
						base_oatdata_addr = oatdata;
						base_oatdata_size = oatdataSize;
						base_oatexec_addr = oatexec;
						base_oatexec_size = oatexecSize;
					} else if (( VG_(strcmp)("system@framework@boot.oat", soname) == 0) ) { // Framework oat file
						if(boot_oatdata_addr == 0) {
							//is_parse_oat = True;
							oatDexParse(oatdata, oatdataSize, oatexec, oatexecSize);
							//is_parse_oat = False;
							boot_oatdata_addr = oatdata;
							boot_oatdata_size = oatdataSize;
							boot_oatexec_addr = oatexec;
							boot_oatexec_size = oatexecSize;
						}
					} else {
#if DBG_OAT_PARSE
						is_parse_oat = True;
						//is_parse_oat = False;
#endif
						oatDexParse(oatdata, oatdataSize, oatexec, oatexecSize);
#if DBG_OAT_PARSE
						is_parse_oat = False;
#endif
					}
				}
			}
		} else if(oatFile == NULL){
			MY_LOGI("Meet so file: %s\n", soname);
			if(VG_(strcmp)("libart.so", soname) == 0) {
				di_libart = di;
				libart_text_addr = VG_(DebugInfo_get_text_avma) (di);
				libart_text_size = VG_(DebugInfo_get_text_size) (di);
				MY_LOGI("Meet so file: %s 0x%08x - 0x%08x\n", soname, libart_text_addr, libart_text_addr + libart_text_size);
				//VG_(print_sym_table)(di);
			}
		}
		di = VG_(next_DebugInfo)(di);
	}
}

static void do_set_instrumentate(const HChar *reason, Bool state) {
	do_method_trace = state; // Represent the instrumentation state

	VG_(discard_translations_safely)( (Addr)0x1000, ~(SizeT)0xfff, "datatrace");
	MY_LOGI("%s: Switch instrumentation %s ... \n",
			reason, state ? "ON" : "OFF");

	if (VG_(clo_verbosity) > 1)
		VG_(message)(Vg_DebugMsg, "%s: instrumentation switched %s\n",
				reason, state ? "ON" : "OFF");
}


static
INLINE Bool is_base_apk(Char *path) {
	Int i = 0, j = 0, len = VG_(strlen)(path);
	Char *fileName = NULL;
	for(i = 0; i < len; i++) {
		if(path[i] == '/')
			j = i;
	}
	fileName = &path[j+1];
	if(VG_(strcmp)("base.apk", fileName) == 0) {
		return True;
	}
	return False;
}

static
Bool isFrameworkClass(HChar* desc) {
	return False;
}


ULong do_ptrace(UWord req, UInt pid, void *addr, void *data) {
	MY_LOGI("Try to invoke patrae req=0x%x pid=%d addr=0x%08x data=0x%08x\n",
			req, pid, (Addr)addr, (Addr)data);
	ULong res = VG_(ptrace)(req, pid, addr, data);
	return res;
}



#ifdef REPLACE_GETTIMEOFDAY
static UInt last_ttt = 0;
static ULong last_nts[4];
static ULong first_nts[4];

#define DBG_SHOW_STRING 0
#endif

static
Bool do_handle_client_requests( ThreadId tid, UWord *arg, UWord *ret) {
	//if(tid != 1) // Only parse the requests from the main thread
	//	return False;
	switch (arg[0]) {
#ifdef REPLACE_GETTIMEOFDAY
		case VG_USERREQ__WRAPPER_LIBC_GETTIMEOFDAY:
			{
				struct vki_timeval* tv = (struct vki_timeval*)arg[1];
				if(do_time_slower == 1)
					break;
				if(first_nts[0] == 0)
					first_nts[0] = tv->tv_sec * 1000000000ULL + tv->tv_usec * 1000ULL;
				//if(tid != 1)
				//	break;
				ULong  current_nts = tv->tv_sec * 1000000000ULL + tv->tv_usec;
				if( do_time_slower != 1 && do_time_slower != 0) {
					Double slower = (Double)do_time_slower;
					current_nts = ((current_nts - first_nts[0]) / slower) + first_nts[0];
					tv->tv_sec  = (current_nts) / 1000000000ULL;
					tv->tv_usec = ((current_nts) % 1000000000ULL) / 1000ULL;
				}
				//VG_(printf)("[LIBC] %d gettimeofday() res=%u.%u (%llu)\n",
				//		tid, tv->tv_sec, tv->tv_usec, last_ts[0]);
				last_nts[0] = current_nts;
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_CLOCK_GETTIME:
			{
				struct vki_timespec *tp = (struct vki_timespec*)arg[2];
				UInt clockid = arg[1];
				if(arg[2] == 0 || do_time_slower == 1)
					break;
				//VG_(printf)("[LIBC] %d clock_gettime() res=%u.%u (%llu) 0x%08x 0x%08x 0x%08x\n",
				//		tid, tp->tv_sec, tp->tv_nsec, last_ts[0], arg[0], arg[1], arg[2]);
				if(first_nts[clockid] == 0)
					first_nts[clockid] = tp->tv_sec * 1000000000ULL + tp->tv_nsec;
				ULong  current_nts = tp->tv_sec * 1000000000ULL + tp->tv_nsec;
				if( do_time_slower != 1 && do_time_slower != 0) {
					Double slower = (Double)do_time_slower;
					current_nts = ((current_nts - first_nts[clockid]) / slower) + first_nts[clockid];
					tp->tv_sec  = (current_nts) / 1000000000ULL;
					tp->tv_nsec = (current_nts) % 1000000000ULL;
				}
				//VG_(printf)("[LIBC] %d clock_gettime() res=%u.%09u (%llu) 1\n",
				//		tid, tp->tv_sec, tp->tv_nsec, current_nts-last_nts[0]);
				last_nts[0] = current_nts;
				break;

			}
#endif
		case VG_USERREQ__WRAPPER_LIBC_STRLEN:
			{
				if(is_in_vm > 0)
					MY_LOGI("[LIBC] %d strlen() strAddr=0x%08x res=%d\n",
							tid, (Addr)arg[1], (int)arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_STRDUP:
			{
				if(is_in_vm > 0)
					MY_LOGI("[LIBC] %d strdup() oldChar=0x%08x newChar=0x%08x\n",
							tid, (Addr)arg[1], (Addr)arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_STRCPY:
			{
				if(is_in_vm > 0)
					MY_LOGI("[LIBC] %d strcpy() srcChar=0x%08x dstChar=0x%08x\n",
							tid, (Addr)arg[1], (Addr)arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_MEMCPY:
			{
				if(is_in_vm > 0)
					MY_LOGI("[LIBC] %d memcpy() srcChar=0x%08x dstChar=0x%08x len=%d\n",
							tid, (Addr)arg[1], (Addr)arg[2], (int)arg[3]);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_KILL:
			{
				VG_(printf)("[LIBC] %d kill() pid=%d sig=%d res=%d\n",	tid, arg[1], arg[2], arg[3]);
				break;
			} 
		case VG_USERREQ__WRAPPER_LIBC_EXIT:
			{
				VG_(printf)("[LIBC] %d exit()\n",	tid);
				break;
			} 
		case VG_USERREQ__WRAPPER_LIBC_EXIT_GROUP:
			{
				VG_(printf)("[LIBC] %d exit_group()\n",	tid);
				break;
			} 
		case VG_USERREQ__WRAPPER_LIBC_ABORT:
			{
				VG_(printf)("[LIBC] %d abort()\n",	tid);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_INOTIFY_ADD_WATCH:
			{
				Int fd = (Int)arg[1];
				HChar *path = (HChar*)arg[2];
				UInt mask = (UInt)arg[3];
				VG_(printf)("[LIBC] %d inotify_add_watch() fd=%d path=%s mask=0x%x\n",
						tid, fd, path, mask);
				break;
			}
#if 0
		case VG_USERREQ__WRAPPER_ART_TEST_PRE:
			{
				Addr	this = (Addr)arg[1];
				HChar *std = (HChar*)arg[2];
				HChar *str = (HChar*)arg[3];
				MY_LOGI("[0]LIBART(%d):RewhyTest() 0x%8x 0x%08x %s\n", 
						tid, (Addr)std, (Addr)str, str);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_TEST:
			{
				Addr	this = (Addr)arg[1];
				HChar *std = (HChar*)arg[2];
				HChar *str = (HChar*)arg[3];
				MY_LOGI("[1]LIBART(%d):RewhyTest() 0x%8x 0x%08x %s\n", 
						tid, (Addr)sErrortd, (Addr)str, str);
				break;
			}
#endif
#if 1
		case VG_USERREQ__WRAPPER_LIBC_SOCKET:
			{
				Int namespace = (Int)arg[1];
				Int style			= (Int)arg[2];
				Int protocol	= (Int)arg[3];
				Int sk        = (Int)arg[4];
				VG_(printf)("[LIBC] %d socket() %d(%s) %d(%s) %d(%s) res_sk=%d\n", 
						tid, namespace, ADDRESS_FAMILY[namespace],
						style, SOCKET_TYPE[style],
						protocol, PROTOCOL_FAMILY[protocol],
						sk);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_BIND:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				if (sa->sa_family == AF_INET)
					addr = inet_ntoa(sa->addr);
				else
					addr = ((struct sockaddr*)sa)->sa_data;
				VG_(printf)("[LIBC] %d bind() sk=%d, family=%d, addr=%s\n",
						tid, sk, sa->sa_family, addr);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_CONNECT_PRE:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				if (sa->sa_family == AF_INET) {
					addr = inet_ntoa(sa->addr);
					VG_(printf)("[LIBC] %d connect() sk=%d, AF_INET, addr=%s:%d\n",
							tid, sk, addr, NTOHS(sa->sa_port));
					inet_aton("10.10.0.1", &sa->addr);
					addr = inet_ntoa(sa->addr);
					VG_(printf)("[LIBC] %d connect() target address modified to %s\n",
							tid, addr);
				}
				else {
					addr = ((struct sockaddr*)sa)->sa_data;
					VG_(printf)("[LIBC] %d connect() sk=%d, AF_UNIX, addr=%s\n",
							tid, sk, addr);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_CONNECT:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				Int* res = (Int*)arg[3];
				if (sa->sa_family == AF_INET) {
					addr = inet_ntoa(sa->addr);
					VG_(printf)("%d connect() sk=%d, AF_INET, addr=%s:%d, res=%d (taint)\n",
							tid, sk, addr, NTOHS(sa->sa_port), *res);
				}
				else {
					addr = ((struct sockaddr*)sa)->sa_data;
					VG_(printf)("%d connect() sk=%d, AF_UNIX, addr=%s, res=%d\n",
							tid, sk, addr, *res);
				}
				if(*res < 0) {
					*res = 0;
					VG_(printf)("%d connect() res modified to %d\n", tid, *res);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_LISTEN:
			{
				Int sk = (Int)arg[1];
				Int bl = (Int)arg[2];
				MY_LOGI("POSTREQ(%d):listen sk=%d, backlog=%d\n", tid, sk, bl);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_ACCEPT:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				Int rk = (Int)arg[3];
				HChar *addr;
				if (sa->sa_family == AF_INET)
					addr = inet_ntoa(sa->addr);
				else
					addr = ((struct sockaddr*)sa)->sa_data;
				MY_LOGI("POSTREQ(%d):accept sk=%d, family=%d, addr=%s, res=%d\n", 
						tid, sk, sa->sa_family, addr, rk);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_SEND:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *res = (Int*)arg[4];

				MY_LOGI("POSTREQ(%d):send sk=%d, 0x%08x(%s), len=%d\n", 
						tid, sk, (Int)buf, buf, *res);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_SENDTO:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int *rlen = (Int*)arg[5];
				HChar *addr;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						MY_LOGI("POSTREQ(%d):sendto sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						MY_LOGI("POSTREQ(%d):sendto sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
				} else {
					MY_LOGI("POSTREQ(%d):sendto sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, buf, *rlen);
				}

				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_RECV_PRE:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *bufsize = (Int*)arg[4];

				MY_LOGI("PREVREQ(%d):recv sk=%d, 0x%08x, size=%d\n", 
						tid, sk, (Int)buf, *bufsize);
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_RECV:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *res = (Int*)arg[4];

				MY_LOGI("POSTREQ(%d):recv sk=%d, 0x%08x(%s), len=%d\n", 
						tid, sk, (Int)buf, buf, *res);

				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_RECVFROM_PRE:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int* rlen = (Int*)arg[5];
				HChar *addr;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						MY_LOGI("PREVREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						MY_LOGI("PREVREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
				} else {
					MY_LOGI("PREVREQ(%d):recvfrom sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, (HChar*)buf, *rlen);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_LIBC_RECVFROM:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int* rlen = (Int*)arg[5];
				HChar *addr;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						MY_LOGI("POSTREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						MY_LOGI("POSTREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
				} else {
					MY_LOGI("POSTREQ(%d):recvfrom sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, (HChar*)buf, *rlen);
				}
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_DLOPEN_PRE:
			{
				MY_LOGI("[0]LIBDL(%d):dlopen() %s 0x%x\n",
						tid, (HChar*)arg[1], arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_DLOPEN:
			{
				MY_LOGI("[1]LIBDL(%d):dlopen() %s 0x%x res=0x%08x\n",
						tid, (HChar*)arg[1], arg[2], arg[3]);
				break;
			}
		case VG_USERREQ__WRAPPER_DLSYM_PRE:
			{
				MY_LOGI("[0]LIBDL(%d):dlsym() %s handle=0x%08x\n",
						tid, (HChar*)arg[2], arg[1]);
				break;
			}
		case VG_USERREQ__WRAPPER_DLSYM:
			{
				HChar *symbol = (HChar*)arg[2];
				MY_LOGI("[1]LIBDL(%d):dlsym() %s handle=0x%08x res=0x%08x\n",
						tid, symbol, arg[1], arg[3]);
				*ret = arg[3];
				break;
				if(VG_(strcmp)("ptrace", symbol) == 0
						|| VG_(strcmp)("write", symbol) == 0)
					*ret = NULL;//(Addr)do_ptrace;
				else
					*ret = arg[3];
				break;
			}
		case VG_USERREQ__WRAPPER_ART_FINDNATIVEMETHOD:
			{
				// void* FindNativeMethod(ArtMethod* m, std::string& detail)
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[2];
				struct StdString *library = (struct StdString*)arg[3];
				Addr codeAddr = (Addr)arg[4];
				MY_LOGI("[0]LIBART(%d) FindNativeMethod() method=%s res=0x%08x\n", tid, library ? library->data : "NULL", codeAddr);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE:
			{
				struct StdString *path = (struct StdString*)arg[1];
				if((VG_(memcmp)(path->data, "/data/", 6) == 0)
						//|| (VG_(strcmp)("/system/lib/libwebviewchromium_loader.so", path->data) == 0)
					) {
					do_set_instrumentate("start instrumentation in LoadNativeLibrary()", True);
					do_is_start = True;
				}
				MY_LOGI("[0]LIBART(%d) LoadNativeLibrary() %s\n", tid, path ? path->data : "Unknown");
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY:
			{
				struct StdString *path = (struct StdString*)arg[2];
				MY_LOGI("[1]LIBART(%d) LoadNativeLibrary() %s\n", tid, path ? path->data : "Unknown");
				if(VG_(memcmp)(path->data, "/data/data/", 11) == 0 
						|| VG_(memcmp)(path->data, "/data/user/", 11) == 0 
						|| VG_(memcmp)(path->data, "/data/app/", 10) == 0) {
					//|| (VG_(strcmp)("/system/lib/libwebviewchromium_loader.so", path->data) == 0) )
					if (is_monitor_memory_alloc > 0 && VG_(strstr)(path->data, "libbaiduprotect.so")) 
					{
						is_monitor_memory_alloc = 0;
						is_dump_raw = False;
						start_trace_irst = 0;
						is_in_vm = 0;
					}
					initSysLib();
					parseOatFile(NULL);
				} else {
					if(do_is_start && path) {
						addMonitorLib(path->data);
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENMEMORY_PRE:
			{
				struct StdString	 *location		= (struct StdString*)arg[1];
				struct MemMapPlus	 *pMemMapObj	= (struct MemMapPlus*)arg[2];
				MY_LOGI("[0]LIBART(%d) OpenMemory() pMemMapObj=0x%08x, location=%s\n",
						tid, (Addr)pMemMapObj, location->data);
				is_in_openmemory = True;
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENMEMORY:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct StdString	 *location		= (struct StdString*)arg[2];
				struct MemMapPlus	 *pMemMapObj	= (struct MemMapPlus*)arg[3];
				MY_LOGI("[1]LIBART(%d) OpenMemory() pMemMapObj=0x%08x, location=%s, pDexFileObj=0x%08x, addr=0x%08x, size=%d\n",
						tid, (Addr)pMemMapObj, location->data, (Addr)pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_);
				if(addDexFileObj((Addr)arg[1]))
					addMonMap(pDexFileObj->begin_, pDexFileObj->size_, 0x0, location->data);
				is_in_openmemory = False;
#if 0
				if(location->data) {
					//if(is_base_apk(location->data))
					if(VG_(memcmp)(location->data, "/data/app/", 10) == 0) {
						do_set_instrumentate("start instrumentation", True);
						if( do_is_start == False) {
							initSysLib();
							parseOatFile(NULL);
							do_is_start = True;
						}
					}
				}
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE:
			{
				HChar	 *descriptor = (HChar*)arg[1];
				if(isFrameworkClass(descriptor))
					break;
				//MY_LOGI("[0]LIBART(%d):DefineClass()\n", tid);
				//break;
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[2];
				struct DexClassDef *pDexClassDef = (struct DexClassDef*)arg[3];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader   *pHeader     = pDexFileObj->header_;
				MY_LOGI("[0]LIBART(%d) DefineClass() %s pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d\n",
						tid, descriptor, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader, pHeader->fileSize);
				VG_(printf)("	  classIdx=%d, sourceFileIdx=%d classDataOff=0x%08x staticValuesOff=0x%08x\n",
						pDexClassDef->classIdx, pDexClassDef->sourceFileIdx, pDexClassDef->classDataOff, 
						pDexClassDef->staticValuesOff);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS:
			{
				HChar	 *descriptor = (HChar*)arg[1];
				if(isFrameworkClass(descriptor))
					break;
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[2];
				struct DexClassDef *pDexClassDef = (struct DexClassDef*)arg[3];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader   *pHeader     = pDexFileObj->header_;
				MY_LOGI("[1]LIBART(%d) DefineClass() %s pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d\n",
						tid, descriptor, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader, pHeader->fileSize);
				VG_(printf)("	  classIdx=%d, sourceFileIdx=%d classDataOff=0x%08x staticValuesOff=0x%08x\n",
						pDexClassDef->classIdx, pDexClassDef->sourceFileIdx, pDexClassDef->classDataOff, 
						pDexClassDef->staticValuesOff);

				if( addDexFileObj((Addr)arg[2]) ) {
					addMonMap(pDexFileObj->begin_, pDexFileObj->size_, 0x0, descriptor);
					if(VG_(strcmp)("Lbbbbbbbb1;", descriptor) == 0) {
						meetDexFilePlus(pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_, 2);
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADCLASS_PRE:
			{
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADCLASS:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct DexClassDef *pDexClassDef = (struct DexClassDef*)arg[2];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader   *pHeader     = pDexFileObj->header_;
				MY_LOGI("[1]LIBART(%d) LoadClass() pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d\n",
						tid, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader, pHeader->fileSize);
				VG_(printf)("	  kclass=0x%08x, classIdx=%d, sourceFileIdx=%d classDataOff=0x%08x staticValuesOff=0x%08x\n",
						arg[3], pDexClassDef->classIdx, pDexClassDef->sourceFileIdx, pDexClassDef->classDataOff, 
						pDexClassDef->staticValuesOff);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS_PRE:
			{ //DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS_PRE, void*, dex_file, void*, class_data, void*, klass, void*, oat_class);
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader   *pHeader     = pDexFileObj->header_;
				UChar *class_data = (UChar*)arg[2];
				MY_LOGI("[0]LIBART(%d) LoadClassMembers() pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d class_data=0x%08x\n",
						tid, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader,
						pHeader->fileSize, (Addr)class_data);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS:
			{ //DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS_PRE, void*, dex_file, void*, class_data, void*, klass, void*, oat_class);
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader   *pHeader     = pDexFileObj->header_;
				UChar *class_data = (UChar*)arg[2];
				MY_LOGI("[1]LIBART(%d) LoadClassMembers() pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d class_data=0x%08x\n",
						tid, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader,
						pHeader->fileSize, (Addr)class_data);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CALLMETHODA:
			{
				HChar *fn_name = (HChar*)arg[1];
				Int mid				 = arg[2];
				Int type			 = arg[3];
				Int invoke		 = arg[4];
				MY_LOGI("[0]LIBART(%d) CallMethodA() %s mid=%d type=%dinvoke=%d\n", tid, fn_name, mid, type, invoke);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CALLMETHODV:
			{
				HChar *fn_name = (HChar*)arg[1];
				Int mid				 = arg[2];
				Int type			 = arg[3];
				Int invoke		 = arg[4];
				MY_LOGI("[0]LIBART(%d) CallMethodV() %s mid=%d type=%dinvoke=%d\n", tid, fn_name, mid, type, invoke);
				break;
			}
#if 0
		case VG_USERREQ__WRAPPER_ART_INVOKEWITHVARARGS:
			{
				Int mid = (Int)arg[3];
				MY_LOGI("[1]LIBART(%d):InvokeWithVarArgs(JNI Reflection) mid=%d\n",tid, mid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEWITHJVALUES:
			{
				Int mid = (Int)arg[3];
				MY_LOGI("[1]LIBART(%d):InvokeWithJValues(JNI Reflection) mid=%d\n",tid, mid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHJVALUES:
			{
				Int mid = (Int)arg[3];
				MY_LOGI("[1]LIBART(%d):InvokeVirtualOrInterfaceWithJValues(JNI Reflection) mid=%d\n",tid, mid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHVARARGS:
			{
				Int mid = (Int)arg[3];
				MY_LOGI("[1]LIBART(%d):InvokVirtualOrInterfaceWithVarArgs(JNI Reflection) mid=%d\n",tid, mid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEMETHOD:
			{
				MY_LOGI("[1]LIBART(%d):InvokeMethod(Java Reflection) javaMethod=0x%08x\n", tid, arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEWITHARGARRAY:
			{
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[1];
				MY_LOGI("[1]LIBART(%d):InvokeWithArgArray() pArtMethod=0x%08x\n", tid, (Addr)pAMth);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKE_PRE:
			{
				if(do_is_start == False)
					return False;
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[1];
				MY_LOGI("[0]LIBART(%d):Invoke() pArtMethod=0x%08x index=%d %s()\n", tid, (Addr)pAMth,
						pAMth->dex_method_index_,
						((pAMth->dex_method_index_ < MAX_MTH_NUM) && (mth_index_name[pAMth->dex_method_index_] == NULL)) ? "???" : mth_index_name[pAMth->dex_method_index_]);
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_ART_INVOKE:
			{
				if(do_is_start == False)
					return False;
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[1];
				MY_LOGI("[1]LIBART(%d):Invoke() pArtMethod=0x%08x index=%d %s()\n", tid, (Addr)pAMth,
						pAMth->dex_method_index_,
						((pAMth->dex_method_index_ < MAX_MTH_NUM) && (mth_index_name[pAMth->dex_method_index_] == NULL)) ? "???" : mth_index_name[pAMth->dex_method_index_]);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_REGISTERNATIVE:
			{
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[1];
				if(do_is_start == False)
					return False;
				//MthNode* query_method_node(Addr codeAddr, Int index)
				//MthNode *pNote = (MthNode*)query_method_node(pAMth->codeAddr, pAMth
				HChar *codeInfo;
				codeInfo = VG_(describe_IP) ( arg[2], NULL );
				MY_LOGI("[1]LIBART(%d):RegisterNative() pArtMethod=0x%08x nativeCode=0x%08x (%s)\n", 
						tid, (Addr)pAMth, (Addr)arg[2], codeInfo);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_GETSTRINGUTFCHARS:
			{
				HChar *str = (HChar*)arg[1];
				if(do_is_start == False)
					return False;
				//if(VG_(memcmp)("aGlvZi5lbm", str, 10) == 0)
				//	str[1] = 'b';
				MY_LOGI("[1]LIBART(%d):GetStringUTFChars() res=%s\n", tid, str);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIFINDCLASS:
			{
				HChar *class_name = (HChar*)arg[2];
				Addr  res         = (Addr)arg[3];
				MY_LOGI("[1]LIBART(%d):FindClass() 0x%08x(%s) jclass=0x%08x\n",tid, (Addr)class_name, class_name, res);
				if(do_is_start == False)
					return False;
				if (is_monitor_memory_alloc == 0 && VG_(strstr)(class_name, "bbbbbbbb1")) {
					is_monitor_memory_alloc = tid;
					//start_trace_irst = tid;
					is_in_vm = tid;
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIGETMETHODID:
			{
				Addr cl = (Addr)arg[1];
				HChar* mth_name = (HChar*)arg[2];
				HChar* sig = (HChar*)arg[3];
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[4];
				UInt c_flags = 0;
				if(pAMth) {
					c_flags = get_declaring_class_flags(pAMth->declaring_class_);
				}
				MY_LOGI("[1]LIBART(%d):GetMethodID() jclass=0x%08x %s %s jmethodId=0x%08x, accFlags=0x%08x(0x%08x), declaring_class=0x%08x, dex_method_index=%d, method_idex=%d\n",
						tid, cl, mth_name, sig, (Addr)pAMth,
						pAMth == NULL ? 0  : pAMth->access_flags_,
						c_flags,
						pAMth == NULL ? -1 : pAMth->declaring_class_,
						pAMth == NULL ? -1 : pAMth->dex_method_index_,
						pAMth == NULL ? -1 : pAMth->method_index_);

			  if(pAMth != NULL ) { 
					if(pAMth->dex_method_index_ < MAX_MTH_NUM) {
						mth_index_name[pAMth->dex_method_index_] = mth_name;
					}
				}
				/*if(do_is_start) {
					if(VG_(strcmp)("intern", mth_name) == 0) {
				//start_trace_irst = tid;
				//is_in_vm = tid;
				is_monitor_memory_alloc = tid;
				}
				}*/
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID:
			{
				Addr cl = (Addr)arg[1];
				HChar* mth_name = (HChar*)arg[2];
				HChar* sig = (HChar*)arg[3];
				Addr res = (Addr)arg[4];
				MY_LOGI("[1]LIBART(%d):GetStaticMethodID() 0x%08x %s %s id=0x%08x\n",tid, cl, mth_name, sig, res);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEXFILE:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				Addr base = (Addr)arg[2];
				UInt len  = (UInt)arg[3];
				struct StdString *location = (struct StdString*)arg[4];
				Addr memmap = (Addr)arg[5];
				MY_LOGI("[1]LIBART(%d):DexFile() pMemMapObj=0x%08x, location=%s, pDexFileObj=0x%08s\n",
						tid, (Addr)pMemMapObj, location->data, (Addr)pDexFileObj);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNI_NEWGLOBALREF:
			{
				const Addr oldObj = (Addr)arg[1];
				const Addr newObj = (Addr)arg[2];
				MY_LOGI("[1]LIBART(%d):NewGlobalRef() oldObj=0x%08x newObj=0x%08x\n",
						tid, oldObj, newObj);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNI_NEWCHARARRAY:
			{
				const Addr len = (Addr)arg[1];
				const Addr res = (Addr)arg[2];
				MY_LOGI("[1]LIBART(%d):NewCharArray() len=%d res=0x%08x\n",
						tid, len, res);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNI_NEWBYTEARRAY:
			{
				const Addr len = (Addr)arg[1];
				const Addr res = (Addr)arg[2];
				MY_LOGI("[1]LIBART(%d):NewByteArray() len=%d res=0x%08x\n",
						tid, len, res);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNI_NEWINTARRAY:
			{
				const Addr len = (Addr)arg[1];
				const Addr res = (Addr)arg[2];
				MY_LOGI("[1]LIBART(%d):NewIntArray() len=%d res=0x%08x\n",
						tid, len, res);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNI_NEWOBJECTARRAY:
			{
				const Addr len = (Addr)arg[1];
				const Addr res = (Addr)arg[4];
				MY_LOGI("[1]LIBART(%d):NewObjectArray() len=%d res=0x%08x\n",
						tid, len, res);
				break;
			}
#if 1
		case VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD:
			{
				if(do_is_start == False)
					break;

				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				const Addr jclass = (Addr)arg[2];
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[3];
				Addr dex_code_item_addr = 0; 
				if( pAMth->dex_code_item_offset_ > 0 ) 
					dex_code_item_addr = pDexFileObj->begin_ + pAMth->dex_code_item_offset_;
				MY_LOGI("[1]LIBART[%d]:LoadMethod() ArtMethod=0x%08x dex_method_index=%d method_index=%d kclass=0x%08x pDexFileObj=0x%08x dexCodeItemOffset=0x%08x(0x%08x)\n", 
						tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
						(Addr)jclass, (Addr)pDexFileObj, pAMth->dex_code_item_offset_, dex_code_item_addr);
				//if(pAMth->dex_code_item_offset_ > 0)
				//	dumpCode((const struct DexCode*)dex_code_item_addr);
				// (mth_index_name[pAMth->dex_method_index_] == NULL) ? "???" : mth_index_name[pAMth->dex_method_index_]);
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE:
			{ 
				struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)arg[1];
				MY_LOGI("[1]LIBART[%d]:LinkCode() flags=0x%08x dex_method_index=%d method_index=%d\n", 
						tid, pAMth->access_flags_, pAMth->dex_method_index_, arg[3]);
				break;
			}
		case VG_USERREQ__WRAPPER_REP_MEMSET:
			{
				const HChar *s = (HChar*)arg[1];
				const HChar c = (HChar)arg[2];
				const Int n = (Int)arg[3];
				//if(is_in_vm > 0)
				if(is_monitor_memory_alloc == tid)
					VG_(printf)("[MEM]: %2d memset() s=0x%08x c=0x%02x n=%d\n", tid, (Addr)s, c, n);
#ifdef STR_COMPARE
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_REP_STRCPY:
			{
				if(is_in_vm > 0)
					MY_LOGI("[REP] %d strcpy() srcChar=0x%08x dstChar=0x%08x\n",
							tid, (Addr)arg[1], (Addr)arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_REP_MEMCPY:
			{
				if(is_in_vm > 0)
					MY_LOGI("[REP] %d memcpy() srcChar=0x%08x dstChar=0x%08x\n",
							tid, (Addr)arg[1], (Addr)arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_REP_MEMMOVE_OR_MEMCPY:
			{
				const HChar *s1 = (HChar*)arg[1];
				const HChar *s2 = (HChar*)arg[2];
				const Int n = (Int)arg[3];
				//if(is_in_vm > 0 && tid == 1)
				if(is_monitor_memory_alloc == tid)
				{
					VG_(printf)("[MEM]: %2d memcpy() s1=0x%08x s2=0x%08x n=%d %s\n", tid, (Addr)s1, (Addr)s2, n, s2);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_REP_STRLEN:
			{
				const HChar *s1 = (HChar*)arg[1];
				const Int n = (Int)arg[2];
				//if(is_in_vm > 0)
				if(is_monitor_memory_alloc == tid)
					VG_(printf)("[MEM]: %2d strlen() s=0x%08x(%s) len=%d\n", tid, arg[1], s1, n);
				break;
			}
		case VG_USERREQ__WRAPPER_REP_MEMCMP:
			{
				const HChar *s1 = (HChar*)arg[1];
				const HChar *s2 = (HChar*)arg[2];
				const Int n = (Int)arg[3];
				//if(is_in_vm > 0)
				if(is_monitor_memory_alloc == tid)
					VG_(printf)("[MEM]: %2d memcmp() s1=0x%08x(%s) s2=0x%08x(%s) n=%d\n", tid, arg[1], s1, arg[2], s2, n);
#ifdef STR_COMPARE
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_REP_STRSTR:
			{
				const HChar *s1 = (HChar*)arg[1];
				const HChar *s2 = (HChar*)arg[2];
				if(is_in_vm > 0)
					if(is_monitor_memory_alloc == tid)
						VG_(printf)("[MEM] %2d strstr() s1=0x%08x(%s) s2=0x%08x(%s)\n", tid, arg[1], s1, arg[2], s2); 
#ifdef STR_COMPARE
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_REP_STRCASECMP:
		case VG_USERREQ__WRAPPER_REP_STRCMP:
			{
				const HChar *s1 = (HChar*)arg[1];
				const HChar *s2 = (HChar*)arg[2];
				//if(is_in_vm > 0)
				if(is_monitor_memory_alloc == tid) {
					VG_(printf)("[MEM]: %2d strcmp() s1=0x%08x(%s) s2=0x%08x(%s)\n", tid, arg[1], s1, arg[2], s2);
				}
#ifdef STR_COMPARE
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_REP_STRNCASECMP:
		case VG_USERREQ__WRAPPER_REP_STRNCMP:
			{
				const HChar *s1 = (HChar*)arg[1];
				const HChar *s2 = (HChar*)arg[2];
				const Int len = (Int)arg[3];
				//if(is_in_vm > 0 && tid == 1)
				if(is_monitor_memory_alloc == tid)
					VG_(printf)("[MEM]: %2d strncmp() s1=0x%08x(%s) s2=0x%08x(%s) len=%d\n", tid, arg[1], s1, arg[2], s2, len);
#ifdef STR_COMPARE
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CALLSTATICOBJECTMETHODV_PRE:
			{
				const Addr jclass = (Addr)arg[2];
				const Int  mid = (Addr)arg[3];
				if(codeLayer[tid] == 1)
					MY_LOGI("[0]LIBART[%d]:CallStaticObjectMethodV jclass=0x%08x mid=0x%x\n", tid, jclass, mid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CALLSTATICOBJECTMETHODV:
			{
				const Addr jclass = (Addr)arg[2];
				const Int  mid = (Addr)arg[3];
				if(codeLayer[tid] == 1)
					MY_LOGI("[1]LIBART[%d]:CallStaticObjectMethodV jclass=0x%08x mid=0x%x\n", tid, jclass, mid); 
				break;
			}
		default:
			{
				return False;
			}
	}
	return True;
}

/*-------------------------- End ----------------------------------*/
	static
UInt valueOfConst(IRExpr* data) 
{
	UInt data_value = -1;
	if (data->tag == Iex_Const)
	{
		switch (data->Iex.Const.con->tag)
		{
			case Ico_U1:	data_value = data->Iex.Const.con->Ico.U1; break;
			case Ico_U8:	data_value = data->Iex.Const.con->Ico.U8; break;
			case Ico_U16: data_value = data->Iex.Const.con->Ico.U16; break;
			case Ico_V128:data_value = data->Iex.Const.con->Ico.V128; break;
			case Ico_U32: data_value = data->Iex.Const.con->Ico.U32; break;
			case Ico_F32i:data_value = data->Iex.Const.con->Ico.F32i; break;
			case Ico_V256:data_value = data->Iex.Const.con->Ico.V256; break;
			case Ico_U64:	data_value = data->Iex.Const.con->Ico.U64; break;
			case Ico_F64i:data_value = data->Iex.Const.con->Ico.F64i; break;
			default: ppIRExpr(data); tl_assert(0);
		}
	}
	return data_value;
}


Int sizeofIRType_bits(IRType ty)
{
	switch (ty)
	{
		case Ity_I1: return 1;
		case Ity_I8: return 8;
		case Ity_I16: return 16;
		case Ity_I32: return 32;
		case Ity_I64: return 64;
		case Ity_I128: return 128;
		case Ity_F32: return 32;
		case Ity_F64: return 64;
		case Ity_D32: return 32;
		case Ity_D64: return 64;
		case Ity_D128: return 128;
		case Ity_F128: return 128;
		case Ity_V128: return 128;
		case Ity_V256: return 256;
		default: VG_(tool_panic)("sizeofIRType_bits");
	}
}

/*
	 Bind the given expression to a new temporary, and return the temporary.
	 This effectively converts an arbitrary expression into an IRAtom.
	 */
static IRExpr* assignNew(IRSB* sb_out, IRExpr* expr)
{
	IRTemp tmp = newIRTemp(sb_out->tyenv, typeOfIRExpr(sb_out->tyenv, expr));

	addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, expr));

	return IRExpr_RdTmp(tmp);
}
static IRExpr* assignNew_HWord(IRSB* sb_out, IRExpr* expr)
{
	IRTemp tmp = newIRTemp(sb_out->tyenv, Ity_I32), tmp1;

	switch (typeOfIRExpr(sb_out->tyenv, expr))
	{
		case Ity_I1:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_1Uto32, expr)));
			break;
		case Ity_I8:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_8Uto32, expr)));
			break;
		case Ity_I16:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_16Uto32, expr)));
			break;
		case Ity_I32:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, expr));
			break;
		case Ity_I64:
			tmp1 = newIRTemp(sb_out->tyenv, Ity_I64);
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp1, expr));
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(tmp1))));
			break;
			/*
			 * case Ity_F32:
			 addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_F32toI32U, expr)));
			 break;
			 * case Ity_F64:
			 addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_F64toI32U, expr)));
			 break;*/
		default:
			/*VG_(printf)("Unknown: ");
				ppIRExpr(expr);
				ppIRType(typeOfIRExpr(sb_out->tyenv, expr));
				VG_(printf)("\n");*/
			return mkIRExpr_HWord(0xffffffff);
			tl_assert(0);
			//VG_(tool_panic)("assignNew_HWord");
	}

	return IRExpr_RdTmp(tmp);
}

static IRExpr* assignNew_ULong(IRSB* sb_out, IRExpr* expr)
{
	IRTemp tmp = newIRTemp(sb_out->tyenv, Ity_I64);

	switch (typeOfIRExpr(sb_out->tyenv, expr))
	{
		case Ity_I1:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_1Uto64, expr)));
			break;
		case Ity_I8:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_8Uto64, expr)));
			break;
		case Ity_I16:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_16Uto64, expr)));
			break;
		case Ity_I32:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_32Uto64, expr)));
			break;
		case Ity_I64:
			addStmtToIRSB(sb_out, IRStmt_WrTmp(tmp, expr));
			break;
		default:
			ppIRExpr(expr);
			ppIRType(typeOfIRExpr(sb_out->tyenv, expr));
			tl_assert(0);
			//VG_(tool_panic)("assignNew_HWord");
	}

	return IRExpr_RdTmp(tmp);
}

static VG_REGPARM(4) void helper_instrument_Put(UInt offset, IRTemp data, Int value, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
	if(data == IRTemp_INVALID) {
#ifdef FZ_LOG_IR
		ST_LOGI("0x%04x 0x%04x PUT(%d) <- 0x%x:I%d\n", Ist_Put, 0x1, offset, value, size);
#endif
	} else {
#ifdef FZ_LOG_IR
		ST_LOGI("0x%04x 0x%04x PUT(%d) <- t%d:I%d | (0x%x)\n", Ist_Put, 0x2, offset, data, size, value);
#endif
	}
	return;
}

static VG_REGPARM(4) void helper_instrument_PutI(UInt base, UInt ix, UInt bias, UInt nElems)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	UInt index = base+((ix+bias)%nElems);
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x PutI()[%d:%d]\n", Ist_PutI, 0x0, ix, bias);
#endif
}

static VG_REGPARM(4) void helper_instrument_WrTmp_Get(IRTemp tmp, UInt offset, UInt value, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d <- GET:I%d(%u) | 0x%x\n", Ist_WrTmp, Iex_Get, tmp, size, offset, value);
#endif
	return;
}

static VG_REGPARM(4) void helper_instrument_WrTmp_GetI(UInt base, UInt ix, UInt bias, UInt nElems)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
	UInt index = base+((ix+bias)%nElems);
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x GetI()[%d:%d]\n", Ist_WrTmp, Iex_GetI, ix, bias);
#endif
}

static VG_REGPARM(4) void helper_instrument_WrTmp_RdTmp(IRTemp tmp_lhs, IRTemp tmp_rhs, UInt value, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d <- t%d:I%d | 0x%x\n", Ist_WrTmp, Iex_RdTmp, tmp_lhs, tmp_rhs, size, value);
#endif
	return;
}

static VG_REGPARM(4) void helper_instrument_WrTmp_Triop_SetElem(IRStmt *clone, UInt size, UInt arg1_value, UInt arg3_value)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	IRExpr *e1 = NULL, *e2 = NULL, *e3 = NULL;
	IROp	 op		= clone->Ist.WrTmp.data->Iex.Triop.details->op;
	e1 = clone->Ist.WrTmp.data->Iex.Triop.details->arg1;
	e2 = clone->Ist.WrTmp.data->Iex.Triop.details->arg2;
	e3 = clone->Ist.WrTmp.data->Iex.Triop.details->arg3;
	IRTemp tmp  = clone->Ist.WrTmp.tmp;
	IRTemp arg1 = (e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : IRTemp_INVALID;
	Int    arg2_value = valueOfConst(e2);
	IRTemp arg3 = (e3->tag == Iex_RdTmp) ? e3->Iex.RdTmp.tmp : IRTemp_INVALID;
	Int size0 = size & 0xff, size1 = (size >> 8) & 0xff, size2 = (size >> 16) & 0xff, size3 = (size >> 24) & 0xff;
	char str[32] = {0};
	IROp_to_str(op, str);
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d <- %s(t%d, 0x%x:I8, t%d) | Triop_SetElem(0x%x, 0x%x, 0x%x)\n", Ist_WrTmp, op,
			tmp, str, arg1, arg2_value, arg3, arg1_value, arg2_value, arg3_value);
#endif
	return;
}

static VG_REGPARM(4) void helper_instrument_WrTmp_Binop(IRStmt *clone, UInt size, UInt arg1_value, UInt arg2_value)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	IRExpr *e1 = NULL, *e2 = NULL;
	char str[32] = {0};

	tl_assert(clone);

	e1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
	e2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
	IROp	 op		= clone->Ist.WrTmp.data->Iex.Binop.op;
	IRTemp tmp  = clone->Ist.WrTmp.tmp;
	IRTemp arg1 = (e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp arg2 = (e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : IRTemp_INVALID;
	Int size0 = size & 0xff, size1 = (size >> 8) & 0xff, size2 = (size >> 16) & 0xff;

	IROp_to_str(op, str);
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d <- %s(t%d, t%d) | Binop(0x%x, 0x%x)\n", Ist_WrTmp, op,
			tmp, str, arg1, arg2, arg1_value, arg2_value);
#endif
	return;
}

static VG_REGPARM(3) void helper_instrument_WrTmp_Unop(IRStmt *clone, UInt value, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	IRTemp   dst = clone->Ist.WrTmp.tmp;
	IRExpr* data = clone->Ist.WrTmp.data;
	IROp op = data->Iex.Unop.op;
	IRExpr*  tmp = data->Iex.Unop.arg;
	IRTemp   arg = (tmp->tag == Iex_RdTmp) ? tmp->Iex.RdTmp.tmp : IRTemp_INVALID;
	char str[32] = {0};
	IROp_to_str(op, str);
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d = %s(t%d) | Unop(0x%x)\n", Ist_WrTmp, op,
			dst, str, arg, value);
#endif
	return;
}

static VG_REGPARM(4) void helper_instrument_WrTmp_Load(IRStmt *clone, UInt addr_value, UInt size, UInt load_value)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	IRTemp  dst  = clone->Ist.WrTmp.tmp;
	IRExpr* data = clone->Ist.WrTmp.data;
	IRExpr* tmp  = data->Iex.Load.addr;
	IRTemp  addr = (tmp->tag == Iex_RdTmp) ? tmp->Iex.RdTmp.tmp : IRTemp_INVALID;

	UInt pc = VG_(get_IP)(tid);
	HChar* addrInfo = NULL;
#ifdef FZ_LOG_IR
	addrInfo = VG_(describe_IP) ( addr_value, NULL );
	ST_LOGI("0x%04x 0x%04x t%d:I%d = LD(t%d) | 0x%x <- LD(0x%08x) | %s\n", Ist_WrTmp, Iex_Load,
			dst, size, addr, load_value, addr_value, addrInfo);
#endif
}

static VG_REGPARM(2) void helper_instrument_WrTmp_Const(IRTemp tmp, UInt value)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d = Const(%d)", Ist_WrTmp, Iex_Const, tmp, value);
#endif
	return;
}

static VG_REGPARM(4) void helper_instrument_WrTmp_CCall_armg_calculate_condition(IRStmt* clone, UInt cc_arg1_value, UInt cc_arg2_value, UInt cc_n_op_value)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	IRExpr** args = clone->Ist.WrTmp.data->Iex.CCall.args;

	Int cond = cc_n_op_value >> 4;
	Int cc_op = cc_n_op_value & 0xF;

	IRTemp tmp = clone->Ist.WrTmp.tmp;
	IRTemp cc_n_op = (args[0]->tag == Iex_RdTmp) ? args[0]->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp cc_arg1 = (args[1]->tag == Iex_RdTmp) ? args[1]->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp cc_arg2 = (args[2]->tag == Iex_RdTmp) ? args[2]->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp cc_arg3 = (args[3]->tag == Iex_RdTmp) ? args[3]->Iex.RdTmp.tmp : IRTemp_INVALID;

#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d <- armg_calculate_condition(t%d, t%d, t%d, t%d) | (%d, %d, %d, 0)\n", Ist_WrTmp, Iex_CCall,
			tmp, cc_n_op, cc_arg1, cc_arg2, cc_arg3, cc_n_op_value, cc_arg1_value, cc_arg2_value);
#endif
	return;
}

static VG_REGPARM(0) void helper_instrument_WrTmp_CCall_else()
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x helper_instrument_WrTmp_CCall_else()\n", Ist_WrTmp, Iex_CCall);
#endif
}

static VG_REGPARM(3) void helper_instrument_WrTmp_ITE(IRStmt *clone, UInt cond_value, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
	IRTemp	tmp		= clone->Ist.WrTmp.tmp;
	IRExpr* data	= clone->Ist.WrTmp.data;
	IRExpr* econd  = data->Iex.ITE.cond;
	IRExpr* eexpr0	= data->Iex.ITE.iftrue;
	IRExpr* eexprX	= data->Iex.ITE.iffalse;
	IRTemp  cond    = (econd->tag == Iex_RdTmp) ? econd->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  expr0   = (eexpr0->tag == Iex_RdTmp) ? eexpr0->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  exprX   = (eexprX->tag == Iex_RdTmp) ? eexprX->Iex.RdTmp.tmp : IRTemp_INVALID;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d = ITE(t%d, t%d, t%d) | %c\n", Ist_WrTmp, Iex_ITE,
			tmp, cond, expr0, exprX, cond_value == 0 ? 'F' : 'T' );
#endif
	return;
}

#if 0
typedef
struct {
	IREndness end;    /* Endianness of the load */
	IRLoadGOp cvt;    /* Conversion to apply to the loaded value */
	IRTemp    dst;    /* Destination (LHS) of assignment */
	IRExpr*   addr;   /* Address being loaded from */
	IRExpr*   alt;    /* Value if load is not done. */
	IRExpr*   guard;  /* Guarding value */
} IRLoadG;
t<tmp> = if (<guard>) <cvt>(LD<end>(<addr>)) else <alt>
#endif
//static VG_REGPARM(0) void helper_instrument_LoadG(IRTemp tmp, UInt addr_value, UInt size)
static VG_REGPARM(4) void helper_instrument_LoadG(IRStmt *clone, UInt addr_value, UInt load_value, UInt guard_value)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

	UInt pc = VG_(get_IP)(tid);
	HChar *pcInfo = NULL, *addrInfo = NULL;
	IRLoadG* lg		= clone->Ist.LoadG.details;
	UInt size = 0;
	switch (lg->cvt) {
		case ILGop_Ident32: size = 32; break;
		case ILGop_16Uto32: size = 16; break;
		case ILGop_16Sto32: size = 16; break;
		case ILGop_8Uto32:  size = 8; break;
		case ILGop_8Sto32:  size = 8; break;
		default: VG_(tool_panic)("instrument_LoadG()");
	}
	IRTemp alt    = lg->alt->tag == Iex_RdTmp ? lg->alt->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp addr   = lg->addr->tag == Iex_RdTmp ? lg->addr->Iex.RdTmp.tmp : IRTemp_INVALID;;
	IRTemp dst		= lg->dst;
	if(guard_value != 0)  {
#ifdef FZ_LOG_IR
		addrInfo = VG_(describe_IP) ( addr_value, NULL );
		ST_LOGI("0x%04x 0x%04x t%d <- <cvt>LD(t%d) | 0x%08x <- LD(0x%08x) | %s\n", Ist_LoadG, guard_value,
				dst, addr, load_value, addr_value, pcInfo);
#endif
	}	else {
#ifdef FZ_LOG_IR
		ST_LOGI("0x%04x 0x%04x t%d = <alt>t%d | 0x%08x\n", Ist_LoadG, guard_value, dst, alt, load_value);
#endif
	}
	return;
}
static VG_REGPARM(4) void helper_instrument_Store(IRStmt *clone, UInt addr_value, UInt data_value, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	HChar *srcInfo = NULL, *pcInfo = NULL, *addrInfo = NULL;
	UInt pc = VG_(get_IP)(tid);
	if( do_is_start == False || tid != 1) {
		return;
	}
#ifdef DBG_MOD_IR
	if( (isMonMap(addr_value, &addrInfo) > 0) && (isMonMap(pc, &pcInfo) > 0) ) {
		VG_(printf)("[MODI2] ST(0x%08x) <- 0x%x | %s | %s\n", addr_value, data_value, addrInfo, pcInfo);
	}
	if( pMDexFileObj ) {
		if( (addr_value >= pMDexFileObj->begin_) && (addr_value < pMDexFileObj->begin_ + pMDexFileObj->size_)) {
			addrInfo = VG_(describe_IP) ( addr_value, NULL );
			VG_(printf)("[MODI1] ST(0x%08x) <- 0x%x | %s | ", addr_value, data_value, addrInfo);
			pcInfo = VG_(describe_IP) ( pc, NULL );
			VG_(printf)("%s\n", pcInfo);
		}
	}
#endif
	if (is_trace_irst != tid)
		return;
	IRExpr* tmp1 = clone->Ist.Store.addr;
	IRExpr* tmp2 = clone->Ist.Store.data;
	IRTemp  addr = tmp1->tag == Iex_RdTmp ? tmp1->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  data = tmp2->tag == Iex_RdTmp ? tmp2->Iex.RdTmp.tmp : IRTemp_INVALID;
#ifdef FZ_LOG_IR
	addrInfo = VG_(describe_IP) ( addr_value, NULL );
	ST_LOGI("0x%04x 0x%04x ST(t%d) = t%d:I%d | ST(0x%08x) <- 0x%x | %s\n", Ist_Store, 0x0,
			addr, data, size, addr_value, data_value, addrInfo);
#endif
	return;
}
//static VG_REGPARM(0) void helper_instrument_StoreG(UInt addr, IRTemp data, UInt size, UInt guard)
static VG_REGPARM(4) void helper_instrument_StoreG(UInt addr_value, UInt data, UInt size, UInt guard_value)
{
	// if (<guard>) ST<end>(<addr>) = <data>
	ThreadId tid = VG_(get_running_tid)();
	HChar *addrInfo = NULL, *pcInfo = NULL; 
	UInt pc = VG_(get_IP)(tid);
	if( do_is_start == False || tid != 1) {
		return;
	}
#ifdef DBG_MOD_IR
	if( (isMonMap(addr_value, &addrInfo) > 0) && (isMonMap(pc, &pcInfo) > 0)) {
		VG_(printf)("[MODI2] ST(0x%08x) <? 0x%x:I%d | %s | %s\n", addr_value, data, size, addrInfo, pcInfo);
	}
	if( pMDexFileObj ) {
		if( (addr_value >= pMDexFileObj->begin_) && (addr_value < pMDexFileObj->begin_ + pMDexFileObj->size_)) {
			addrInfo = VG_(describe_IP) ( addr_value, NULL );
			VG_(printf)("[MODI1] ST(0x%08x) <? 0x%x:I%d | %s | \n", addr_value, data, size, addrInfo);
			pcInfo = VG_(describe_IP) ( pc, NULL );
			VG_(printf)("%s\n", pcInfo);
		}
	}
#endif
	if (is_trace_irst != tid || guard_value == 0) {
		return;
	}

#ifdef FZ_LOG_IR
	addrInfo = VG_(describe_IP) ( addr_value, NULL );
	ST_LOGI("0x%04x 0x%04x ST(0x%08x) <? 0x%x:I%d | %s\n", Ist_StoreG, 0x0, addr_value, data, size, addrInfo);
#endif
}

static VG_REGPARM(4) void helper_instrument_CAS_single_element(UInt addr, IRTemp dataLo, UInt size, UInt cas_succeeded)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x 0x%08x:I%d <- CASle(t%d) | cas_succeeded=%d\n", Ist_CAS, 0x1,
			addr, size, dataLo, cas_succeeded);
#endif
	return;
}

static VG_REGPARM(4) void helper_instrument_CAS_double_element(IRStmt* clone, UInt addr, UInt size, UInt cas_succeeded)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
	char dep[DEP_MAX_LEN] = {0};
	char *tmp_rhs = NULL;
	IRCAS*  cas = clone->Ist.CAS.details;
	IRTemp  dataLo = (cas->expdLo->tag == Iex_RdTmp) ? cas->expdLo->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  dataHi = (cas->expdHi->tag == Iex_RdTmp) ? cas->expdHi->Iex.RdTmp.tmp : IRTemp_INVALID;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x 0x%08x:I%d <- CASle(t%d, t%d) | cas_succeeded=%d\n", Ist_CAS, 0x2,
			addr+size, size, dataHi, dataLo, cas_succeeded);
#endif
	return;
}

//static VG_REGPARM(4) void helper_instrument_LLSC_Load_Linked(IRTemp result, UInt addr, UInt size, UInt load_value)
static VG_REGPARM(4) void helper_instrument_LLSC_Load_Linked(IRTemp result, UInt addr, UInt size)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;
#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x t%d <- LDle-Linked(0x%08x:I%d)\n", Ist_LLSC,  0x1,
			result, addr, size);
#endif
	return;
}
static VG_REGPARM(4) void helper_instrument_LLSC_Store_Conditional(UInt addr, IRTemp storedata, UInt size, UInt store_succeeded)
{
	ThreadId tid = VG_(get_running_tid)();
	if (is_trace_irst != tid)
		return;

#ifdef FZ_LOG_IR
	ST_LOGI("0x%04x 0x%04x 0x%08x:I%d <- STle-Cond(t%d) | (%c)\n", Ist_LLSC, 0x2,
			addr, size, storedata, store_succeeded == 0 ? 'F' : 'T');
#endif
	return;
}

static ULong bn = 0;
static void parse_jump_insn(ThreadId tid, UInt guard_value, Addr src, Addr dst, Int type) 
{
	//if (guard_value == 0 || is_trace_irst == 0)
	if (guard_value == 0 || start_trace_irst == 0) {
		return;
	}
	HChar *srcInfo = NULL; //VG_(describe_IP) ( src, NULL );
	HChar *dstInfo = NULL; //VG_(describe_IP) ( src, NULL );
	UWord r0, r1, r2, r3, sp;
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState	*arch_state = &tst->arch.vex;
	HChar tmp[255];
	Addr src_map = 0;
	Addr dst_map = 0;
	UInt size = 0;
#if defined(VGPV_arm_linux_android)
	r0 = arch_state->guest_R0;
	r1 = arch_state->guest_R1;
	r2 = arch_state->guest_R2;
	r3 = arch_state->guest_R3;
	sp = arch_state->guest_R13;
#endif
	if( is_trace_irst == is_in_vm) {
		if( (isMonMap(src, &srcInfo) > 0) && (isMonMap(dst,&dstInfo) == 0)) {
			dstInfo = VG_(describe_IP) ( dst, NULL );
			VG_(printf)("[I] %d Jump from 0x%08x(%s)@%llu to 0x%08x(%s) 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n", 
					tid, src, srcInfo, bn, dst, dstInfo, r0, r1, r2, r3, sp);
			is_trace_irst = 0;
		} else {
			VG_(printf)("[S] %d Jump from 0x%08x(%s)@%llu to 0x%08x(%s) 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n", 
					tid, src, srcInfo, bn, dst, dstInfo, r0, r1, r2, r3, sp);
		}
		bn++;
	} else if(is_trace_irst == 0) {
		src_map = isMonMap(src, &srcInfo);
		dst_map = isMonMap(dst, &dstInfo);
		if( src_map == 0 && dst_map > 0 ) {
			srcInfo = VG_(describe_IP) ( src, NULL );
			VG_(printf)("[R] %d Jump from 0x%08x(%s) to 0x%08x(%s) 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n", 
					tid, src, srcInfo,  dst, dstInfo, r0, r1, r2, r3, sp);
			is_trace_irst = is_in_vm;
			bn = 0;
			dumpMemMap(dst_map);
		} /*else if (is_in_vm > 0) {
			srcInfo = VG_(describe_IP) ( src, NULL );
			VG_(strcpy)(tmp, srcInfo);
			dstInfo = VG_(describe_IP) ( dst, NULL );
			VG_(printf)("[R] %d Jump from 0x%08x(%s) to 0x%08x(%s) 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n", 
					tid, src, tmp,  dst, dstInfo, r0, r1, r2, r3, sp);
		}*/
	}
}
//static VG_REGPARM(0) void helper_instrument_Exit(UInt branch_is_taken, UInt offsIP, UInt size, IRtemp guard)
static VG_REGPARM(4) void helper_instrument_Exit(UInt guard_value, Addr src, Addr dst, IRTemp guard)
{
	ThreadId tid			= VG_(get_running_tid)();
	if(is_in_vm == tid) {
#ifdef FZ_LOG_IR
		if (is_trace_irst == tid) {
			ST_LOGI("0x%04x 0x%04x if(t%d) goto 0x%08x | (%d)\n", Ist_Exit, 0,
					guard, dst, guard_value);
		}
#endif
		parse_jump_insn(tid, guard_value, src, dst, 0);
	}
}

static VG_REGPARM(3) void helper_instrument_Next(Addr src, Addr dst, IRTemp nxt)
{
	ThreadId tid			= VG_(get_running_tid)();
	if(is_in_vm == tid) {
#ifdef FZ_LOG_IR
		if (is_trace_irst == tid) {
			if(nxt != IRTemp_INVALID)
				ST_LOGI("0x%04x 0x%04x goto t%d | 0x%08x\n", 0x1eff, 0x1,	nxt, dst);
			else
				ST_LOGI("0x%04x 0x%04x goto 0x%08x\n", 0x1eff, 0x2, dst);
		}
#endif
		parse_jump_insn(tid, 1, src, dst, 1);
	}
}

//
//  VEX INSTRUMENTATION FUNCTIONS
//

void instrument_Put(IRStmt* st, IRSB* sb_out)
{
	Int offset = st->Ist.Put.offset;
	IRExpr* data = st->Ist.Put.data;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, data));
	IRDirty* di;
	UInt data_value = -1;

	tl_assert(isIRAtom(data));
	// the data transfer type is the type of data
#if 0
	if (data->tag == Iex_Const)
	{
		switch (data->Iex.Const.con->tag)
		{
			case Ico_U1:  data_value = data->Iex.Const.con->Ico.U1; break;
			case Ico_U8:  data_value = data->Iex.Const.con->Ico.U8; break;
			case Ico_U16: data_value = data->Iex.Const.con->Ico.U16; break;
			case Ico_V128:data_value = data->Iex.Const.con->Ico.V128; break;
			case Ico_U32: data_value = data->Iex.Const.con->Ico.U32; break;
			case Ico_F32i:data_value = data->Iex.Const.con->Ico.F32i; break;
			case Ico_V256:data_value = data->Iex.Const.con->Ico.V256; break;
			case Ico_U64: data_value = data->Iex.Const.con->Ico.U64; break;
			case Ico_F64i:data_value = data->Iex.Const.con->Ico.F64i; break;
			default: ppIRStmt(st); tl_assert(0);
		}
	}
#endif
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_Put",
			VG_(fnptr_to_fnentry)(helper_instrument_Put),
			mkIRExprVec_4(mkIRExpr_HWord(offset),
				mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
				(data->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, data) : mkIRExpr_HWord(valueOfConst(data)),
				mkIRExpr_HWord(size))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
/*
	 The PutI statement is used to write guest registers which identity is not known until run time,
	 i.e. not the registers we are shadowing (in principle), no harm in verifying though.
	 */
void instrument_PutI(IRStmt* st, IRSB* sb_out)
{
	IRPutI* details = st->Ist.PutI.details;
	IRRegArray* descr = details->descr;
	Int base = descr->base;
	Int nElems = descr->nElems;
	IRExpr* ix = details->ix;
	Int bias = details->bias;
	IRDirty* di;

	tl_assert(ix->tag == Iex_RdTmp);

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_PutI",
			VG_(fnptr_to_fnentry)(helper_instrument_PutI),
			mkIRExprVec_4(mkIRExpr_HWord(base),
				assignNew_HWord(sb_out, ix),
				mkIRExpr_HWord(bias),
				mkIRExpr_HWord(nElems))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Get(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	Int offset = data->Iex.Get.offset;
	Int size = sizeofIRType_bits(data->Iex.Get.ty);
	IRDirty* di;

	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == data->Iex.Get.ty);

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Get",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Get),
			mkIRExprVec_4(mkIRExpr_HWord(tmp),
				mkIRExpr_HWord(offset),
				assignNew_HWord(sb_out, data),
				mkIRExpr_HWord(size))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
/*
	 The GetI expression is used to read guest registers which identity is not known until run time,
	 i.e. not the registers we are shadowing (in principle), no harm in verifying though.
	 */
void instrument_WrTmp_GetI(IRStmt* st, IRSB* sb_out)
{
	IRExpr* data = st->Ist.WrTmp.data;
	IRRegArray* descr = data->Iex.GetI.descr;
	Int base = descr->base;
	Int nElems = descr->nElems;
	IRExpr* ix = data->Iex.GetI.ix;
	Int bias = data->Iex.GetI.bias;
	IRDirty* di;

	tl_assert(ix->tag == Iex_RdTmp);

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_GetI",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_GetI),
			mkIRExprVec_4(mkIRExpr_HWord(base),
				assignNew_HWord(sb_out, ix),
				mkIRExpr_HWord(bias),
				mkIRExpr_HWord(nElems))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_RdTmp(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp_lhs = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	IRTemp tmp_rhs = data->Iex.RdTmp.tmp;
	Int size = sizeofIRType_bits(typeOfIRTemp(sb_out->tyenv, tmp_rhs));
	IRDirty* di;

	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp_lhs) == typeOfIRTemp(sb_out->tyenv, tmp_rhs));

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_RdTmp",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_RdTmp),
			mkIRExprVec_4(mkIRExpr_HWord(tmp_lhs),
				mkIRExpr_HWord(tmp_rhs),
				assignNew_HWord(sb_out, data),
				mkIRExpr_HWord(size))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

	static
void instrument_WrTmp_Triop_SetElem(IRStmt* st, IRSB* sb_out)
{
	IRTriop *triop = st->Ist.WrTmp.data->Iex.Triop.details;
	IRExpr* arg1 = triop->arg1;
	IRExpr* arg2 = triop->arg2;
	IRExpr* arg3 = triop->arg3;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, st->Ist.WrTmp.data));
	Int size1 = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, arg1));
	Int size2 = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, arg2));
	Int size3 = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, arg3));

	IRStmt* stclone = deepMallocIRStmt(st);
	IRDirty* di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Triop_SetElem",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Triop_SetElem),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				mkIRExpr_HWord(size | (size1 << 8) | (size2 << 16) | (size3 << 24)),
				(arg1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg1) : mkIRExpr_HWord(valueOfConst(arg1)),
				(arg3->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg3) : mkIRExpr_HWord(valueOfConst(arg3)))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));

}
	static
void instrument_WrTmp_Triop(IRStmt* st, IRSB* sb_out)
{
	IRTriop *triop = st->Ist.WrTmp.data->Iex.Triop.details;
	switch(triop->op) {
		case Iop_Slice64:
			break;
		case Iop_SetElem8x8:
		case Iop_SetElem16x4:
		case Iop_SetElem32x2:
			instrument_WrTmp_Triop_SetElem(st, sb_out);
			break;
		default:
			break;
	}
}
void instrument_WrTmp_Binop(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	IROp op = data->Iex.Binop.op;
	IRExpr* arg1 = data->Iex.Binop.arg1;
	IRExpr* arg2 = data->Iex.Binop.arg2;
	UInt arg1_value = 0, arg2_value = 0;
	IRExpr* expr = IRExpr_Binop(op, arg1, arg2);
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, expr));
	Int size1 = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, arg1));
	Int size2 = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, arg2));
	IRDirty* di;

	// we don't care about floating point and SIMD operations
	//if (op > Iop_AddF64)
	//	return;

	tl_assert(isIRAtom(arg1));
	tl_assert(isIRAtom(arg2));
	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, expr));

	if (arg1->tag == Iex_Const)
	{
		switch (arg1->Iex.Const.con->tag)
		{
			case Ico_U1: arg1_value = arg1->Iex.Const.con->Ico.U1; break;
			case Ico_U8: arg1_value = arg1->Iex.Const.con->Ico.U8; break;
			case Ico_U16: arg1_value = arg1->Iex.Const.con->Ico.U16; break;
			case Ico_V128: arg1_value = arg1->Iex.Const.con->Ico.V128; break;
			case Ico_U32:  arg1_value = arg1->Iex.Const.con->Ico.U32; break;
			case Ico_V256: arg1_value = arg1->Iex.Const.con->Ico.V256; break;
			case Ico_U64:  arg1_value = arg1->Iex.Const.con->Ico.U64; break;
			default: ppIRStmt(st); tl_assert(0); VG_(tool_panic)("instrument_WrTmp_Binop");
		}
	}
	if (arg2->tag == Iex_Const)
	{
		switch (arg2->Iex.Const.con->tag)
		{
			case Ico_U1: arg2_value = arg2->Iex.Const.con->Ico.U1; break;
			case Ico_U8: arg2_value = arg2->Iex.Const.con->Ico.U8; break;
			case Ico_U16: arg2_value = arg2->Iex.Const.con->Ico.U16; break;
			case Ico_V128: arg2_value = arg2->Iex.Const.con->Ico.V128; break;
			case Ico_U32:  arg2_value = arg2->Iex.Const.con->Ico.U32; break;
			case Ico_V256: arg2_value = arg2->Iex.Const.con->Ico.V256; break;
			case Ico_U64:  arg2_value = arg2->Iex.Const.con->Ico.U64; break;
			default: ppIRStmt(st); tl_assert(0); VG_(tool_panic)("instrument_WrTmp_Binop");
		}
	}

	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Binop",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Binop),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				mkIRExpr_HWord(size | (size1 << 8) | (size2 << 16)),
				(arg1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg1) : mkIRExpr_HWord(arg1_value),
				(arg2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg2) : mkIRExpr_HWord(arg2_value))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Unop(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	IROp op = data->Iex.Unop.op;
	IRExpr* arg = data->Iex.Unop.arg;
	IRExpr* expr = IRExpr_Unop(op, arg);
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, expr));
	IRDirty* di;

	tl_assert(isIRAtom(arg));
	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, expr));

	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Unop",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Unop),
			mkIRExprVec_3(mkIRExpr_HWord((HWord)stclone),
				(arg->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg) : mkIRExpr_HWord(valueOfConst(arg)),
				mkIRExpr_HWord(size))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Load(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	IRExpr* addr = data->Iex.Load.addr;
	Int size = sizeofIRType_bits(data->Iex.Load.ty);
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == data->Iex.Load.ty);

	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Load",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Load),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord(size),
				assignNew_HWord(sb_out, IRExpr_RdTmp(tmp)))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_WrTmp_Const(IRStmt* st, IRSB* sb_out)
{
	IRTemp  tmp = st->Ist.WrTmp.tmp;
	IRExpr* arg = st->Ist.WrTmp.data;
	UInt	arg_value;
	IRDirty* di;

	switch (arg->Iex.Const.con->tag)
	{
		case Ico_U1: arg_value = arg->Iex.Const.con->Ico.U1; break;
		case Ico_U8: arg_value = arg->Iex.Const.con->Ico.U8; break;
		case Ico_U16: arg_value = arg->Iex.Const.con->Ico.U16; break;
		case Ico_U32: arg_value = arg->Iex.Const.con->Ico.U32; break;
		case Ico_F32i: arg_value = arg->Iex.Const.con->Ico.F32i; break;
		case Ico_U64: arg_value = arg->Iex.Const.con->Ico.U64; break;
		case Ico_F64i: arg_value = arg->Iex.Const.con->Ico.F64i; break;
		default: ppIRStmt(st); tl_assert(0); //VG_(tool_panic)("instrument_WrTmp_Binop");
	}

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Const",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Const),
			mkIRExprVec_2(mkIRExpr_HWord(tmp),
				mkIRExpr_HWord(arg_value))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
/*
	 cc_op
	 add/sub/mul
	 adc/sbb
	 shl/Shl/sar
	 tmp = cond(cc_op(cc_dep1, cc_dep2))
	 and/or/xor
	 inc/dec
	 rol/ror
	 tmp = cond(cc_op(cc_dep1, 0))

	 The taintness of tmp depends on taintness of both args. (we can't handle and(cc_dep1, 0) which gives an untainted result)
	 cf. valgrind guest_x86_defs.h
	 */
void instrument_WrTmp_CCall(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	IRCallee* cee = data->Iex.CCall.cee;
	IRExpr** args = data->Iex.CCall.args;
	IRDirty* di;

	//#if defined(VGPV_arm_linux_android)
	//UInt armg_calculate_condition ( UInt cond_n_op /* (ARMCondcode << 4) | cc_op */,
	//                          UInt cc_dep1,
	//                          UInt cc_dep2, UInt cc_dep3 )
	if (VG_(strcmp)(cee->name, "armg_calculate_condition") == 0)
	{
		IRExpr* cc_n_op = args[0];
		IRExpr* cc_dep1 = args[1];
		IRExpr* cc_dep2 = args[2];
		IRExpr* cc_dep3 = args[3];

		//tl_assert(cc_n_op->tag == Iex_Const && cc_n_op->Iex.Const.con->tag == Ico_U32);
		tl_assert(isIRAtom(cc_n_op));
		tl_assert(isIRAtom(cc_dep1));
		tl_assert(isIRAtom(cc_dep2));
		tl_assert(isIRAtom(cc_dep3));
		if (cc_n_op->tag == Iex_Const) tl_assert(cc_n_op->Iex.Const.con->tag == Ico_U32);
		if (cc_dep1->tag == Iex_Const) tl_assert(cc_dep1->Iex.Const.con->tag == Ico_U32);
		if (cc_dep2->tag == Iex_Const) tl_assert(cc_dep2->Iex.Const.con->tag == Ico_U32);
		if (cc_dep3->tag == Iex_Const) tl_assert(cc_dep3->Iex.Const.con->tag == Ico_U32);
		IRStmt* stclone = deepMallocIRStmt(st);
		di = unsafeIRDirty_0_N(0,
				"helper_instrument_WrTmp_CCall_armg_calculate_condition",
				VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_CCall_armg_calculate_condition),
				mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
					(cc_dep1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep1) : mkIRExpr_HWord(cc_dep1->Iex.Const.con->Ico.U32),
					(cc_dep2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep2) : mkIRExpr_HWord(cc_dep2->Iex.Const.con->Ico.U32),
					//(cc_dep3->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep3) : mkIRExpr_HWord(cc_dep3->Iex.Const.con->Ico.U32))
				(cc_n_op->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_n_op) : mkIRExpr_HWord(cc_n_op->Iex.Const.con->Ico.U32))
			);
		addStmtToIRSB(sb_out, IRStmt_Dirty(di));
	} else {
		di = unsafeIRDirty_0_N(0,
				"helper_instrument_WrTmp_CCall_else",
				VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_CCall_else),
				mkIRExprVec_0()
				);
		addStmtToIRSB(sb_out, IRStmt_Dirty(di));
	}
}
void instrument_WrTmp_ITE(IRStmt* st, IRSB* sb_out)
{
	IRTemp tmp = st->Ist.WrTmp.tmp;
	IRExpr* data = st->Ist.WrTmp.data;
	IRExpr* cond = data->Iex.ITE.cond;
	IRExpr* expr0 = data->Iex.ITE.iftrue;
	IRExpr* exprX = data->Iex.ITE.iffalse;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, expr0));
	IRDirty* di;

	tl_assert(cond->tag == Iex_RdTmp);
	tl_assert(isIRAtom(expr0));
	tl_assert(isIRAtom(exprX));
	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, expr0));
	tl_assert(typeOfIRTemp(sb_out->tyenv, tmp) == typeOfIRExpr(sb_out->tyenv, exprX));

	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_ITE",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_ITE),
			mkIRExprVec_3(mkIRExpr_HWord((HWord)stclone),
				assignNew_HWord(sb_out, cond),
				mkIRExpr_HWord(size))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

void instrument_WrTmp(IRStmt* st, IRSB* sb_out)
{
	switch (st->Ist.WrTmp.data->tag)
	{
		//case Iex_Binder:
		// we don't care about floating point and SIMD operations
		//case Iex_Qop:
		//	break;

		case Iex_Get:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_Get(st, sb_out);
#endif
			break;
		case Iex_GetI:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_GetI(st, sb_out);
#endif
			break;
		case Iex_RdTmp:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_RdTmp(st, sb_out);
#endif
			break;
		case Iex_Unop:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_Unop(st, sb_out);
#endif
			break;
		case Iex_Binop:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_Binop(st, sb_out);
#endif
			break;
		case Iex_Triop:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_Triop(st, sb_out);
#endif
			break;
		case Iex_Const:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_Const(st, sb_out);
#endif
			break;
		case Iex_CCall:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_CCall(st, sb_out);
#endif
			break;
		case Iex_ITE:
#ifdef DO_INSTRUMENTATION
			instrument_WrTmp_ITE(st, sb_out);
#endif
			break;
		case Iex_Load:
#ifdef DO_INS_LOAD
			instrument_WrTmp_Load(st, sb_out);
#endif
			break;
#if 0
		case Iex_Mux0X:
			instrument_WrTmp_Mux0X(st, sb_out);
			break;
#endif
		default:
			ppIRStmt(st);
			tl_assert(0);
	}
}
void instrument_Store(IRStmt* st, IRSB* sb_out)
{
	IRExpr* addr = st->Ist.Store.addr;
	IRExpr* data = st->Ist.Store.data;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, st->Ist.Store.data));
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	tl_assert(isIRAtom(data));
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	// the data transfer type is the type of data

	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_Store",
			VG_(fnptr_to_fnentry)(helper_instrument_Store),
			mkIRExprVec_4( mkIRExpr_HWord((HWord)stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				(data->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, data) : mkIRExpr_HWord(valueOfConst(data)),
				mkIRExpr_HWord(size))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_StoreG(IRStmt* st, IRSB* sb_out)
{
	IRStoreG* sg = st->Ist.StoreG.details;
	IRExpr* addr = sg->addr;
	IRExpr* data = sg->data;
	IRExpr* guard = sg->guard;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, data));
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	tl_assert(isIRAtom(data));
	tl_assert(isIRAtom(guard)); 
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	// the data transfer type is the type of data


	di = unsafeIRDirty_0_N(0,
			"helper_instrument_StoreG",
			VG_(fnptr_to_fnentry)(helper_instrument_StoreG),
			mkIRExprVec_4(
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				(data->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, data) : mkIRExpr_HWord(valueOfConst(data)),
				mkIRExpr_HWord(size),
				assignNew_HWord(sb_out, guard))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

void instrument_LoadG(IRStmt* st, IRSB* sb_out)
{
	IRLoadG* lg = st->Ist.LoadG.details;

	IRTemp  dst		= lg->dst;
	IRExpr* addr	= lg->addr;
	IRExpr* alt		= lg->alt;
	IRExpr* guard	= lg->guard;
	IRDirty* di;

	IROp vwiden = Iop_INVALID;

	tl_assert(isIRAtom(addr));
	tl_assert(isIRAtom(alt));
	tl_assert(isIRAtom(guard));

	IRStmt* stclone = deepMallocIRStmt(st);

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_LoadG",
			VG_(fnptr_to_fnentry)(helper_instrument_LoadG),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				assignNew_HWord(sb_out, IRExpr_RdTmp(dst)),
				assignNew_HWord(sb_out, guard))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_CAS_single_element(IRStmt* st, IRSB* sb_out)
{
	IRCAS* cas = st->Ist.CAS.details;
	IRTemp oldLo = cas->oldLo;
	IRExpr* addr = cas->addr;
	IRExpr* expdLo = cas->expdLo;
	IRExpr* dataLo = cas->dataLo;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, dataLo));
	IROp op;
	IRExpr* expr;
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	tl_assert(isIRAtom(dataLo));
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	tl_assert(typeOfIRExpr(sb_out->tyenv, addr) == typeOfIRExpr(sb_out->tyenv, dataLo));

	switch (size)
	{
		case 8: op = Iop_CasCmpEQ8; break;
		case 16: op = Iop_CasCmpEQ16; break;
		case 32: op = Iop_CasCmpEQ32; break;
		default: VG_(tool_panic)("instrument_CAS_single_element");
	}

	expr = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldLo), expdLo)); // statement has to be flat

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_CAS_single_element",
			VG_(fnptr_to_fnentry)(helper_instrument_CAS_single_element),
			mkIRExprVec_4((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord(size),
				assignNew_HWord(sb_out, expr))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_CAS_double_element(IRStmt* st, IRSB* sb_out)
{
	IRCAS* cas = st->Ist.CAS.details;
	IRTemp oldHi = cas->oldHi, oldLo = cas->oldLo;
	IREndness end = cas->end;
	IRExpr* addr = cas->addr;
	IRExpr *expdHi = cas->expdHi, *expdLo = cas->expdLo;
	IRExpr *dataHi = cas->dataHi, *dataLo = cas->dataLo;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, dataLo));
	IROp op;
#if defined(VGPV_arm_linux_android)
	IROp op1;
#endif
	IRExpr *expr1, *expr2;
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	tl_assert(end == Iend_LE); // we assume endianness is little endian
	tl_assert(isIRAtom(dataLo));
	tl_assert(isIRAtom(dataHi));
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	tl_assert(typeOfIRExpr(sb_out->tyenv, addr) == typeOfIRExpr(sb_out->tyenv, dataLo));

	switch (size)
	{
		case 8: 
			op = Iop_CasCmpEQ8; 
#if defined(VGPV_arm_linux_android)
			op1 =  Iop_And8;
#endif
			break;
		case 16: 
			op = Iop_CasCmpEQ16;
#if defined(VGPV_arm_linux_android)
			op1 =  Iop_And16;
#endif
			break;
		case 32:
			op = Iop_CasCmpEQ32; 
#if defined(VGPV_arm_linux_android)
			op1 =  Iop_And32;
#endif
			break;
		default: 
			VG_(tool_panic)("instrument_CAS_double_element");
	}

	expr1 = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldLo), expdLo)); // statement has to be flat
	expr2 = assignNew(sb_out, IRExpr_Binop(op, IRExpr_RdTmp(oldHi), expdHi)); // statement has to be flat
#if defined(VGPV_arm_linux_android)
	IRExpr *expr = assignNew(sb_out, IRExpr_Binop(op1, expr1, expr2));
	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_CAS_double_element",
			VG_(fnptr_to_fnentry)(helper_instrument_CAS_double_element),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord(size),
				assignNew_HWord(sb_out, expr))
			);
#else
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_CAS_double_element",
			VG_(fnptr_to_fnentry)(helper_instrument_CAS_double_element),
			mkIRExprVec_6((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord((dataLo->tag == Iex_RdTmp) ? dataLo->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord((dataHi->tag == Iex_RdTmp) ? dataHi->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord(size),
				assignNew_HWord(sb_out, expr1),
				assignNew_HWord(sb_out, expr2))
			);
#endif // defined(VGA_arm)
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_CAS(IRStmt* st, IRSB* sb_out)
{
	if (st->Ist.CAS.details->oldHi == IRTemp_INVALID)
	{
		instrument_CAS_single_element(st, sb_out);
	}
	else
	{
		instrument_CAS_double_element(st, sb_out);
	}
}
void instrument_LLSC_Load_Linked(IRStmt* st, IRSB* sb_out)
{
	IRTemp result = st->Ist.LLSC.result;
	IRExpr* addr = st->Ist.LLSC.addr;
	Int size = sizeofIRType_bits(typeOfIRTemp(sb_out->tyenv, result));
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	// the data transfer type is the type of result

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_LLSC_Load_Linked",
			VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Load_Linked),
			mkIRExprVec_3(mkIRExpr_HWord(result),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord(size))
			//assignNew_HWord(sb_out, IRExpr_RdTmp(result)))
				);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_LLSC_Store_Conditional(IRStmt* st, IRSB* sb_out)
{
	IRTemp result = st->Ist.LLSC.result;
	IRExpr* addr = st->Ist.LLSC.addr;
	IRExpr* storedata = st->Ist.LLSC.storedata;
	Int size = sizeofIRType_bits(typeOfIRExpr(sb_out->tyenv, storedata));
	IRExpr* result_expr = IRExpr_RdTmp(result);
	IRDirty* di;

	tl_assert(isIRAtom(addr));
	tl_assert(isIRAtom(storedata));
	if (addr->tag == Iex_Const) tl_assert(addr->Iex.Const.con->tag == Ico_U32);
	// the data transfer type is the type of storedata
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_LLSC_Store_Conditional",
			VG_(fnptr_to_fnentry)(helper_instrument_LLSC_Store_Conditional),
			mkIRExprVec_4((addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord((storedata->tag == Iex_RdTmp) ? storedata->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord(size),
				assignNew_HWord(sb_out, result_expr))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}
void instrument_LLSC(IRStmt* st, IRSB* sb_out)
{
	if (st->Ist.LLSC.storedata == NULL)
	{ /* Load linked 
		 * Just treat it as the normal load statement,
		 * followed by an assignement of the value to .result
		 */
		instrument_LLSC_Load_Linked(st, sb_out);
	}
	else
	{
		/* Store conditional
		 * It writes .result with a value for indicating whether 
		 * the store statment is successful.
		 */
		instrument_LLSC_Store_Conditional(st, sb_out);
	}
}
void instrument_Exit(Addr src, IRStmt* st, IRSB* sb_out)
{
	IRExpr* guard = st->Ist.Exit.guard;
	IRDirty* di = NULL;
	tl_assert(guard->tag == Iex_RdTmp);

	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_Exit",
			VG_(fnptr_to_fnentry)((void*)&helper_instrument_Exit),
			mkIRExprVec_4( assignNew_HWord(sb_out, guard),
				mkIRExpr_HWord(src),
				mkIRExpr_HWord(st->Ist.Exit.dst->Ico.U32),
				mkIRExpr_HWord(guard->Iex.RdTmp.tmp))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}

void instrument_Next(Addr src, IRExpr *next, IRSB* sb_out)
{
	IRDirty* di = NULL;
	di = unsafeIRDirty_0_N(3,
			"helper_instrument_Next",
			VG_(fnptr_to_fnentry)((void*)&helper_instrument_Next),
			mkIRExprVec_3( mkIRExpr_HWord(src),
				assignNew_HWord(sb_out, next),
				next->tag == Iex_RdTmp ? mkIRExpr_HWord(next->Iex.RdTmp.tmp) : mkIRExpr_HWord(IRTemp_INVALID))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
}


//
//  SYSCALL WRAPPERS
//

// #define TEST_FILE   "test.txt"

void handle_sys_read(ThreadId tid, UWord *args, UInt nArgs, SysRes res)
{
	int fd;
	void* buf;
	unsigned long i;

	Int len = sr_Res(res);
	if (len > 0)
	{
		fd = (int)args[0];
		buf = (void*)args[1];

		if (fd == fd_to_taint)
		{
			VG_(printf)("read(%p) = %lu\n", buf, len);

			for (i = 0; i < len; i++)
			{
				if (!memory_is_tainted(((UInt)buf)+i, 8))
				{
					flip_memory(((UInt)buf)+i, 8, 1);
				}

				char dep[DEP_MAX_LEN] = {0};
				VG_(snprintf)(dep, DEP_MAX_LEN, "INPUT(%lu)", i);

				update_memory_dep(((UInt)buf)+i, dep, 8);
			}
		}
	}
}

static void pre_syscall(ThreadId tid, UInt syscall_number, UWord* args, UInt nArgs)
{
	//VG_(printf)("0 %d sysno = %-3d %s\n", tid, syscall_number, syscallnames[syscall_number]);
	switch ((int)syscall_number) {
		case __NR_exit:
			DO_(syscall_pre_exit)(tid, args, nArgs);
			break;
		case __NR_execve:
			DO_(syscall_pre_execve)(tid, args, nArgs);
			break;
		case __NR_unlinkat:
			DO_(syscall_pre_unlinkat)(tid, args, nArgs);
			break;
		default:
			break;
	}
	if(do_is_start == False) 
		return False;
	switch ((int)syscall_number) {
		case __NR_fork:
			DO_(syscall_pre_fork)(tid, args, nArgs);
			break;
		case __NR_ptrace:
			DO_(syscall_pre_ptrace)(tid, args, nArgs);
			break;
		case __NR_rt_sigreturn:
			DO_(syscall_pre_rt_sigreturn)(tid, args, nArgs);
			break;
		default:
			break;
	}
}

static void post_syscall(ThreadId tid, UInt syscall_number, UWord* args, UInt nArgs, SysRes res)
{
	//if(do_is_start == False) 
	//	return False;
	//if(tid != 1)
	//	return;
	//VG_(printf)("1 %d sysno = %d\n", tid, syscall_number);
	switch ((int)syscall_number) {
		// Should be defined by respective include/vki/vki-scnums-arch-os.h
		case __NR_clone:
			DO_(syscall_clone)(tid, args, nArgs, res);
			break;
		case __NR_rt_sigaction:
		case __NR_sigaction:
			DO_(syscall_action)(tid, args, nArgs, res);
			break;
		case __NR_unlink:
			DO_(syscall_unlink)(tid, args, nArgs, res);
			break;
		case __NR_unlinkat:
			DO_(syscall_unlinkat)(tid, args, nArgs, res);
			break;
		case __NR_execve:
			DO_(syscall_execve)(tid, args, nArgs, res);
			break;
		case __NR_read:
			DO_(syscall_read)(tid, args, nArgs, res);
			break;
		case __NR_pread64:
			DO_(syscall_pread)(tid, args, nArgs, res);
			break;
		case __NR_readv:
			DO_(syscall_readv)(tid, args, nArgs, res);
			break;
		case __NR_preadv:
			DO_(syscall_preadv)(tid, args, nArgs, res);
			break;
		case __NR_write:
			DO_(syscall_write)(tid, args, nArgs, res);
			break;
		case __NR_writev:
			DO_(syscall_writev)(tid, args, nArgs, res);
			break;
		case __NR_pwritev:
			DO_(syscall_pwritev)(tid, args, nArgs, res);
			break;
		case __NR_close:
			DO_(syscall_close)(tid, args, nArgs, res);
			break;
		case __NR_mprotect:
			DO_(syscall_mprotect)(tid, args, nArgs, res);
			break;
		case __NR_msync:
			DO_(syscall_msync)(tid, args, nArgs, res);
			break;
		case __NR_munmap:
			DO_(syscall_munmap)(tid, args, nArgs, res);
			break;
		case __NR_mmap2:
			DO_(syscall_mmap)(tid, args, nArgs, res);
			break;
		case __NR_ptrace:
			DO_(syscall_ptrace)(tid, args, nArgs, res);
			break;
		case __NR_open:
		case __NR_openat:
			DO_(syscall_open)(tid, args, nArgs, res);
			break;
		case __NR_fork:
			DO_(syscall_fork)(tid, args, nArgs, res);
			break;
		case __NR_lseek:
			//	DO_(syscall_lseek)(tid, args, nArgs, res);
			break;
		case __NR_madvise:
			DO_(syscall_madvise)(tid, args, nArgs, res);
			break;
		case __NR_futex:
			DO_(syscall_futex)(tid, args, nArgs, res);
			break;
		case __NR_flock:
			DO_(syscall_flock)(tid, args, nArgs, res);
			break;
		case __NR_fstatat64:
			DO_(fstatat)(tid, args, nArgs, res);
			break;
		case __NR_inotify_add_watch:
			DO_(inotify_add_watch)(tid, args, nArgs, res);
			break;
#ifdef __NR_llseek
		case __NR_llseek:
			DO_(syscall_llseek)(tid, args, nArgs, res);
			break;
#endif
#if 0
		case __NR_setuid:
		case __NR_setuid32:
			DO_(syscall_setuid)(tid, args, nArgs, res);
			break;
		case __NR_setreuid:
		case __NR_setreuid32:
			DO_(syscall_setreuid)(tid, args, nArgs, res);
			break;
		case __NR_setgid:
		case __NR_setgid32:
			DO_(syscall_setgid)(tid, args, nArgs, res);
			break;
		case __NR_setregid:
		case __NR_setregid32:
			DO_(syscall_setregid)(tid, args, nArgs, res);
			break;
#ifdef __NR_recv
		case __NR_recv:
			DO_(syscall_recv)(tid, args, nArgs, res);
			break;
#endif
#ifdef __NR_recvfrom
		case __NR_recvfrom:
			DO_(syscall_recvfrom)(tid, args, nArgs, res);
			break;
#endif
		default:
			break;
#endif // VGO_freebsd
	}
}

//
//  BASIC TOOL FUNCTIONS
//
static Bool do_process_cmd_line_option(Char* arg)
{
	if VG_STR_CLO(arg, "--fname", clo_fnname) {}
	else if VG_INT_CLO(arg, "--start-index",		do_start_method_index){}
	else if VG_STR_CLO(arg, "--start-method",		do_start_method_name){VG_(printf)("Start method: %s\n", do_start_method_name);}
	else if VG_STR_CLO(arg, "--start-shorty",		do_start_method_shorty){VG_(printf)("Start shorty: %s\n", do_start_method_shorty);}
	else if VG_INT_CLO(arg, "--stop-index",			do_stop_method_index){}
	else if VG_STR_CLO(arg, "--stop-method",		do_stop_method_name){VG_(printf)("Stop method: %s\n", do_stop_method_name);}
	else if VG_STR_CLO(arg, "--start-class",		do_start_clazz) {VG_(printf)("Start class: %s\n", do_start_clazz);}
	else if VG_STR_CLO(arg, "--main-activity",	do_main_activity) {VG_(printf)("Main activity: %s\n", do_main_activity);}
	else if VG_STR_CLO(arg, "--stop-class",			do_stop_clazz) {VG_(printf)("Stop class: %s\n", do_stop_clazz);}
	else if VG_INT_CLO(arg, "--time-slow",			do_time_slower) {}
	else 
		return VG_(replacement_malloc_process_cmd_line_option)(arg);

	// tl_assert(clo_fnname);
	// tl_assert(clo_fnname[0]);
	return True;
}

static void do_print_usage(void)
{
	VG_(printf)(
			"    --fnname=<filename>								file to taint\n"
			"    --start-index=<Method_index>				the mthod index for starting analysis in detail\n"
			"    --start-method=<Method_name>				the mthod name for starting analysis in detail\n"
			"    --stop-index=<Method_index>				the result of the method for tainting\n"
			"    --stop-name=<Method_name>					the arguments of the method for tainting\n"
			"    --start-class=<Class_name>					the class name for starting analysis\n"
			"    --stop-class=<Class_name>					the class name for stopping analysis\n"
			"    --time-slow=<slower>               the times for making the timestamps slower\n"
			);
}

static void do_print_debug_usage(void)
{
	VG_(printf)(
			"    (none)\n"
			);
}

static void do_post_clo_init(void)
{
	// init_shadow_memory();
}

/*-----------------------------------------------*/
/*------- For tracking ART Methods --------------*/
/*-----------------------------------------------*/
#define TG_N_THREADS		256

static Bool trace_obj_taint = False;
static MthStack mthStack[TG_N_THREADS];


static
INLINE Bool is_framework_bb(Addr *a) {
	IRDirty *di = NULL;
	DebugInfo *dbgInfo = VG_(find_DebugInfo)(a);
	if(dbgInfo) {
		if(VG_(DebugInfo_is_oat)(dbgInfo)) {
			return True;
		}
	}
	return False;
}

static Bool is_mth_stack_full = False;

static 
INLINE Int mth_stack_size(ThreadId tid) {
	return mthStack[tid].size;
}

static
INLINE void mth_stack_print(ThreadId tid) {
}

#define MTH_CALL_DEPTH 4
static
INLINE Int mth_push_stack(ThreadId tid, Addr addr, Addr sp, MthNode *mth, UChar taintTag) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > MTH_CALL_DEPTH) {
			is_mth_stack_full = True;
			return -1;
		}
		if(ms->size < MAX_STACK_SIZE) {
			ms->addr[ms->size] = addr;
			ms->stack[ms->size] = sp;
			ms->mth[ms->size]  = (Addr)mth;
			ms->taintTag[ms->size] = taintTag;
			ms->size++;
		} else {
			MY_LOGI("Method stack overflow!!!\n");
			mth_stack_print(tid);
			tl_assert(0);
		}
		return ms->size;
	}
	return -1;
}

static
INLINE Int mth_pop_stack(ThreadId tid, Int num) {
	MthStack *ms = NULL;
	tl_assert(num > 0);
	UInt i = 0;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > num) {
			ms->size -= num;
			for(i = 0; i < num; i++) {
				ms->mth[ms->size + i] = NULL;
				ms->addr[ms->size + i] = 0;
				ms->stack[ms->size + i] = 0;
				ms->taintTag[ms->size + i] = 0;
			}
		} else {
			ms->size = 0;
		}
		if(is_mth_stack_full) 
			is_mth_stack_full = False;
		return ms->size;
	}
	return -1;
}

static 
INLINE Bool mth_top_stack1(ThreadId tid, Addr *addr, Addr *stack,
		MthNode **mth,
		UChar *taintTag,
		Int index) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size >= index) {
			*addr = ms->addr[ms->size - index];
			*stack = ms->stack[ms->size - index];
			if(mth) {
				*mth = (MthNode*)ms->mth[ms->size - index];
				*taintTag = ms->taintTag[ms->size - index];
			}
			return True;
		}
	}
	return False;
}

static 
INLINE Bool mth_top_stack(ThreadId tid, Addr *addr, Addr *addr1, 
		MthNode **mth, MthNode **mth1, 
		UChar *taintTag, UChar *taintTag1) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > 0) {
			*addr = ms->addr[ms->size - 1];
			if(mth) {
				*mth = (MthNode*)ms->mth[ms->size - 1];
				*taintTag = ms->taintTag[ms->size - 1];
			}
		} else {
			return False;
		}
		if(ms->size > 1) {
			*addr1 = ms->addr[ms->size - 2];
			if(mth1) {
				*mth1 = (MthNode*)ms->mth[ms->size - 2];
				*taintTag1 = ms->taintTag[ms->size - 2];
			}
		} else {
			*addr1 = -1;
		}
		return True;
	}
	return False;
}

static
INLINE MthNode* mth_lookup_stack(ThreadId tid, Addr a) {
	MthStack *ms = NULL;
	Addr addr;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		for(Int i = ms->size; i > 0; i--){
			addr = ms->addr[i - 1];
			if(a & ~0x1 == addr & ~0x1) {
				return (MthNode*)ms->mth[i - 1];
			}
		}
	}
	return NULL;
}

Addr dlopen_addr = 0, dlsym_addr = 0;

//void* dlopen(const char* filename, int flags)
//__dl_dlopen
//
static
void helper_invoke_superblock_dlopen(VexGuestLayout *layout) {
#if defined(VGPV_arm_linux_android)
	ThreadId tid			= VG_(get_running_tid)();
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState	*arch_state = &tst->arch.vex;
	const HChar* filename = (HChar*)arch_state->guest_R0;
	const Int    flags = (Int)arch_state->guest_R1;
	MY_LOGI("Call[%d]: dlopen() filename=%s flags=0x%x\n", tid, filename, flags);
#endif
}
//void* dlsym(void* handle, const char* symbol)
// const ElfW(Sym)* dlsym_handle_lookup(soinfo* si, soinfo** found, const char* name)
//__dl_dlsym
static
void helper_invoke_superblock_dlsym_lookup(VexGuestLayout *layout) {
#if defined(VGPV_arm_linux_android)
	ThreadId tid			= VG_(get_running_tid)();
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState	*arch_state = &tst->arch.vex;
	const Addr        si = (Addr)arch_state->guest_R0;
	const Addr* si_found = (Addr)arch_state->guest_R1;
	const HChar* name = (HChar*)arch_state->guest_R2;
	MY_LOGI("Call[%d]: dlsym() hsi=0x%08x found=0x%08x symbol=%s\n", tid, si, *si_found, name);
#endif
}

/* Check if a framwork is invoked, if so, parse the arguments */
static
void invoke_framework_method(Addr irst_addr, MthList *mList) {
	Int tt = 0, i = 0, s = 0;
	Addr last_lr;
	Bool isSource = False;
	UChar taintTag = 0;
	UWord r0, r1, r2, r3, r4, r8, r9, r10, r11, r12, sp, lr, pc;
	ThreadId tid			= VG_(get_running_tid)();
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState	*arch_state = &tst->arch.vex;
#if defined(VGPV_arm_linux_android)
	r0 = arch_state->guest_R0;
	r1 = arch_state->guest_R1;
	r2 = arch_state->guest_R2;
	r3 = arch_state->guest_R3;
	r4 = arch_state->guest_R4;
	r8 = arch_state->guest_R8;
	r9 = arch_state->guest_R9;
	r10 = arch_state->guest_R10;
	r11 = arch_state->guest_R11;
	r12 = arch_state->guest_R12;
	sp = arch_state->guest_R13;
	lr = arch_state->guest_R14;
	pc = arch_state->guest_R15T;
#endif
	struct ArtMethodPlus *pAMth = (struct ArtMethodPlus *)r0;
	MthNode *mNode = NULL;
	for(i = 0; i < mList->num; i++) {
		mNode = (MthNode *)mList->mthNodes[i];
		if(mNode->mthKey == pAMth->dex_method_index_)
			break;
	}
	if(mNode == NULL || i == mList->num)
		return;
	Bool isStatic = (mNode->accessFlags & ACC_STATIC) ? True : False;
	Bool isEntrance = False;

	
	s = mth_stack_size(tid);
	if(mNode->mthKey == do_start_method_index) {
		if((VG_(strcmp)(mNode->method, do_start_method_name) == 0) /*&& (s == 61 || s == 57 || s == 53)is_in_vm == 0*/) {
			is_in_vm = VG_(get_running_tid)();
			start_trace_irst = VG_(get_running_tid)();
			isEntrance = True;
			do_exit_addr = lr;
			MY_LOGI("Start the detail analysis (ret=0x%08x).\n", lr);
			if (target_mem_addr > 0) {
				UChar *s1 = (UChar*)target_mem_addr;
				for (UInt i = 0; i < target_mem_len; i++) {
					VG_(printf)("0x%02x ", s1[i]);
					if (i % 16 == 0)
						VG_(printf)("\n");
				}
				VG_(printf)("\n");
			}
		}
	} 
	
	if( is_in_vm == 0 ) {
		return;
	}
	// VG_(printf)("[REGS] r8=0x%08x r9=0x%08x r10=0x%08x r11=0x%08x r12=0x%08x sp=0x%08x lr=0x%08x pc=0x%08x\n",
	//		r8, r9, r10, r11, r12, sp, lr, pc);
	ART_INVOKE("%02d %d %05d %s %s() %s isNative=%c flag=0x%8x pArtMethod=0x%08x (0x%08x, 0x%08x, 0x%08x, this=0x%08x, sp=0x%08x)\n",
			tid, s, mNode->mthKey, mNode->clazz, mNode->method, mNode->shorty,
			(pAMth->access_flags_ & ACC_NATIVE) ? '1' : '0',
			pAMth->access_flags_, (Addr)pAMth,
			pAMth->declaring_class_,
			pAMth->ptr_sized_fields_.entry_point_from_jni_,
			pAMth->ptr_sized_fields_.entry_point_from_quick_compiled_code_,
			r0, sp);
	tt = mth_push_stack(tid, lr, sp, mNode, taintTag);
#ifdef PARSE_RET_PARAMETER
	//taintTag = check_mth_invoke(mNode, tid, isSource);
	check_mth_invoke(mNode, tid, isSource);
#else
	if(isEntrance)
		check_mth_invoke(mNode, tid, isSource);
#endif
	mNode->pAMth = (Addr)pAMth;
	if(pAMth->access_flags_ & ACC_NATIVE) {
		codeLayer[tid] = 1;
	}
}

/* Check if a framework returns, if so, parse the results */
static
void return_framework_method(Addr a) {
	ThreadId tid = VG_(get_running_tid)();
	ThreadState *tst = VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	Addr addr, addr1, stack;
	MthNode *mNode = NULL, *mNode1 = NULL;
	UWord sp;
	UChar taintTag = 0, taintTag1 = 0;
	Bool isSource = False;
#if defined(VGPV_arm_linux_android)
	sp = arch_state->guest_R13;
#endif
	Bool isStatic = False;
	Int  index = 0, s = 0;
	while(mth_top_stack1(tid, &addr, &stack, &mNode, &taintTag, ++index)) {
		if(((addr & 0xfffffffe) == (a & 0xfffffffe)) && ((stack & 0xfffffffe) == (sp & 0xfffffffe))) {
			s = mth_pop_stack(tid, index);
			isStatic = (mNode->accessFlags & ACC_STATIC) ? True : False;
			ART_RETURN("%02d %d %05d %s %s() %s isSource=%s pArtMthod=0x%08x (pc=0x%08x, top=0x%08x, sp=0x%08x)\n",
					tid, s, mNode->mthKey, mNode->clazz, mNode->method,	mNode->shorty,
					mNode->type & TYPE_SOURCE ? "True" : "Flase", mNode->pAMth, a, addr, sp);
			if(mNode->accessFlags & ACC_NATIVE) { codeLayer[tid] = 0;	}
			if((do_exit_addr > 0) && ((do_exit_addr & 0xfffffffe) == (a & 0xfffffffe))) 
			{
				is_in_vm = 0;
				do_is_start = False;
				start_trace_irst = 0;
				MY_LOGI("Stop the detail analysis\n");
				if (target_mem_addr > 0) {
					UChar *s1 = (UChar*)target_mem_addr;
					for (UInt i = 0; i < target_mem_len; i++) {
						VG_(printf)("0x%02x ", s1[i]);
						if (i % 16 == 0)
							VG_(printf)("\n");
					}
					VG_(printf)("\n");
				}
#if DBG_OAT_PARSE
				is_parse_oat = True;
#endif
				releaseDexFileList();
#if DBG_OAT_PARSE
				is_parse_oat = False;
#endif
				parseOatFile(NULL);
			}
#ifdef PARSE_RET_PARAMETER
			/*if(do_method_trace) {
				if(isSource) {
				do_taint_source(mNode, tid);
				} else {
				check_mth_return(mNode, tid, taintTag);
				}
				}*/
			check_mth_return(mNode, tid, taintTag);
#endif
		}
		if(is_mth_stack_full == False) {
			break;
		}
		break; // only compare the top address
	}
}


/* The helper dirty function inserted into the beginning of a IRSB */
static VG_REGPARM(0) void helper_instrument_superblock( Addr irst_addr, Addr mListAddr)
{
	if (do_is_start == False)
		return;

	if(do_method_trace && mListAddr > 0) {
		MthList *mList = (MthList *)mListAddr;
		invoke_framework_method(irst_addr, mList);
	}
}

/* The helper dirty function inserted at the end of a IRSB */
static VG_REGPARM(1) UInt helper_instrument_tmp_next(Addr d)
{ 
	Addr dst = d;
	if(do_method_trace)
		return_framework_method(dst);
	return dst;
}


static VG_REGPARM(1) UInt helper_instrument_const_next(Addr d)
{
	Addr dst = d;
	return d;
}

static INLINE
Bool is_instrument_needed( VgCallbackClosure* closure ) {
	Addr a = closure->nraddr;
	return !isSysLib(a, NULL);// || ( a >= libart_text_beg && a <= libart_text_end);
}
	static 
IRSB* do_instrument ( VgCallbackClosure* closure,
		IRSB* sb_in,
		const VexGuestLayout* layout,
		const VexGuestExtents* vge,
		const VexArchInfo* archinfo_host,
		IRType gWordTy, IRType hWordTy )
{
	if((do_is_start == False) && (do_method_trace == False))
		return sb_in;
	Int i;
	IRSB* sb_out;
	IRDirty* di;
	MthList *mList = NULL;
	MthNode *mNode = NULL;
	Bool		isEntry = False;
	Bool		is_debug = False;

	if (gWordTy != hWordTy) {
		ppIRType(gWordTy);
		ppIRType(hWordTy);
		/* We don't currently support this case. */
		VG_(tool_panic)("host/guest word size mismatch");
	}
	/* Set up SB */
	sb_out = deepCopyIRSBExceptStmts(sb_in);

	// Copy verbatim any IR preamble preceding the first IMark
	i = 0;
	while (i < sb_in->stmts_used && sb_in->stmts[i]->tag != Ist_IMark) {
		addStmtToIRSB(sb_out, sb_in->stmts[i]);
		i++;
	}

	/*-------- For method tracking ---------*/
	if(do_method_trace) {
		if (is_framework_bb(vge->base[0])) {
			mList = query_method_list(vge->base[0]&0xfffffffc);
		}
	}
	di = unsafeIRDirty_0_N(2, 
			"helper_instrument_superblock",
			VG_(fnptr_to_fnentry) ( helper_instrument_superblock ),
			mkIRExprVec_2(mkIRExpr_HWord((Addr)vge->base[0]),
				mkIRExpr_HWord((Addr)mList)));
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));

	for (/*use current i*/; i < sb_in->stmts_used; i++)
	{
		IRStmt* st = sb_in->stmts[i];
		if (!st)
			continue;

		switch (st->tag)
		{
			case Ist_NoOp:
			case Ist_IMark:
			case Ist_AbiHint:
			case Ist_Dirty:
			case Ist_MBE:
				addStmtToIRSB(sb_out, st);
				break;

			case Ist_WrTmp:
				addStmtToIRSB(sb_out, st);
				instrument_WrTmp(st, sb_out);
				break;
			case Ist_Put:
#ifdef DO_INSTRUMENTATION
				instrument_Put(st, sb_out);
#endif
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_PutI:
#ifdef DO_INSTRUMENTATION
				instrument_PutI(st, sb_out);
#endif
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_Store:
#ifdef DO_INS_STORE
				instrument_Store(st, sb_out);
#endif
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_StoreG:
				addStmtToIRSB(sb_out, st);
				// if (<guard>) ST<end>(<addr>) = <data>
#ifdef DO_INS_STORE
				instrument_StoreG(st, sb_out);
#endif
				break;
			case Ist_LoadG: 
				// t<tmp> = if (<guard>) <cvt>(LD<end>(<addr>)) else <alt>
				addStmtToIRSB(sb_out, st);
#ifdef DO_INS_LOAD
				instrument_LoadG(st, sb_out);
#endif
				break;
			case Ist_CAS:
				addStmtToIRSB(sb_out, st); // dirty helpers use temporaries (oldHi, oldLo) defined in the instruction
#ifdef DO_INSTRUMENTATION
				instrument_CAS(st, sb_out);
#endif
				break;
			case Ist_LLSC:
				addStmtToIRSB(sb_out, st);
#ifdef DO_INSTRUMENTATION
				instrument_LLSC(st, sb_out);
#endif
				break;
			case Ist_Exit:
				instrument_Exit(closure->nraddr, st, sb_out);
				addStmtToIRSB(sb_out, st);
				break;
			default:
				MY_LOGI("do_main.c: do_instrument(), Unhandled IRStmt.\n");
				ppIRStmt(st);
				VG_(printf)("\n");
				tl_assert(0);
		}
	}
	//if( do_is_start && is_instrument_needed(closure)) {
	if( do_is_start ) {
		IRExpr *next = sb_in->next;
		instrument_Next(closure->nraddr, next, sb_out);
		switch(next->tag) {
			case Iex_Const:
				{
					Addr next_addr = valueOfConst(next);
					IRTemp dst = newIRTemp(sb_out->tyenv, Ity_I32);
					di = unsafeIRDirty_1_N(dst, 0,
							"helper_instrument_const_next",
							VG_(fnptr_to_fnentry)(helper_instrument_const_next),
							mkIRExprVec_1(mkIRExpr_HWord(next_addr))
							);
					addStmtToIRSB(sb_out, IRStmt_Dirty(di));
					sb_out->next = IRExpr_RdTmp(dst);
					break;
				}     
			case Iex_RdTmp:
				{     
					IRTemp dst = newIRTemp(sb_out->tyenv, Ity_I32);
					di = unsafeIRDirty_1_N(dst, 0,
							"helper_instrument_tmp_next",
							VG_(fnptr_to_fnentry)(helper_instrument_tmp_next),
							mkIRExprVec_1(assignNew_HWord(sb_out, sb_in->next))
							);
					addStmtToIRSB(sb_out, IRStmt_Dirty(di));
					sb_out->next = IRExpr_RdTmp(dst);
					break;
				}     
			default:
				tl_assert(0);
		}
	}
#ifdef FZ_DEBUG
	if(is_in_vm > 0) { 
		VG_(printf)("Output (0x%08x) ", vge->base[0]);
		ppIRSB(sb_out);
	}
	if(is_in_vm > 0) {
		if(isMonMap(vge->base[0], NULL) > 0) {
			VG_(printf)("Output (0x%08x) ", vge->base[0]);
			ppIRSB(sb_out);
		}
	}
	if(do_is_start || is_debug) {
		VG_(printf)("Debug output (0x%08x, %d) ", vge->base[0], vge->len[0]);
		ppIRSB(sb_out);
	}
#endif
	return sb_out;
}

static void do_fini(Int exitcode)
{
	destroy_shadow_memory();
	releaseDexFileList();
	do_is_start = False;
}

static void do_pre_clo_init(void)
{
	VG_(details_name)            ("deobfustator");
	VG_(details_version)         ("0.1.2");
	VG_(details_description)     ("A tool for de-obfuscating the packed Android apps");
	VG_(details_copyright_author)("Copyright (C) 2016, Rewhy.");
	VG_(details_bug_reports_to)  (VG_BUGS_TO);

	VG_(details_avg_translation_sizeB) ( 275 );

	VG_(needs_libc_freeres)				();
	VG_(needs_malloc_replacement)	(
			do_malloc,
			do_builtin_new,
			do_builtin_vec_new,
			do_memalign,
			do_calloc,
			do_free,
			do_builtin_delete,
			do_builtin_vec_delete,
			do_realloc,
			do_malloc_usable_size,
			0 );

	do_malloc_list = VG_(HT_construct)( "do_malloc_list" );
	VG_(basic_tool_funcs)        (do_post_clo_init,
			do_instrument,
			do_fini);

	VG_(needs_command_line_options)(do_process_cmd_line_option,
			do_print_usage,
			do_print_debug_usage);

	VG_(needs_syscall_wrapper) (pre_syscall, post_syscall);
	VG_(needs_client_requests) (do_handle_client_requests);
	/* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION(do_pre_clo_init)
