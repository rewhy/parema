// dt_main.c

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

#include "pub_tool_vki.h"           // keeps libcproc.h happy, syscall nums
#include "pub_tool_vkiscnums.h"
#include "pub_tool_aspacemgr.h"     // VG_(am_shadow_alloc)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)
#include "pub_tool_hashtable.h"     // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"    // tl_assert
#include "pub_tool_libcbase.h"      // VG_STREQN
#include "pub_tool_libcprint.h"     // VG_(message)
#include "pub_tool_libcproc.h"      // VG_(getenv)
#include "pub_tool_replacemalloc.h" // VG_(replacement_malloc_process_cmd_line_option)
#include "pub_tool_machine.h"       // VG_(get_IP)
#include "pub_tool_mallocfree.h"    // VG_(out_of_memory_NORETURN)
#include "pub_tool_options.h"       // VG_STR/BHEX/BINT_CLO
#include "pub_tool_oset.h"          // OSet operations
#include "pub_tool_threadstate.h"   // VG_(get_running_tid)
#include "pub_tool_xarray.h"        // VG_(*XA)
#include "pub_tool_stacktrace.h"    // VG_(get_and_pp_StackTrace)
#include "pub_tool_libcfile.h"      // VG_(readlink)
#include "pub_tool_addrinfo.h"      // VG_(describe_addr)
#include "pub_tool_machine.h"
#include "pub_tool_transtab.h"    // VG_(discard_translations_safely)

#include "malton.h"
#include "dt_debug.h"
#include "dt_taint.h"
#include "dt_oatplus.h"
#include "dt_wrappers.h"
#include "dt_instrument.h"
#include "unistd-asm-arm.h"


/*---------- Command arguments -------------------*/
Bool trace_obj_taint  = False;
Bool trace_ins_taint  = False;
Bool trace_art_method = False;
Bool output_log_info  = True;
/* Taintgrind args (Defined in dt_wrappers.h) */
/* Taint args */
Bool          DT_(clo_tainted_ins_only)       = True;
Bool          DT_(clo_critical_ins_only)      = True;
Int           DT_(do_print)                   = 1;
Bool          DT_(clo_smt2)                   = False;

Bool					DT_(clo_taint_begin)						= False;
Bool					DT_(dex_is_open)								= False;

static Bool dt_process_cmd_line_options(const HChar* arg) {
	const HChar* tmp_str;
	if VG_BOOL_CLO(arg, "--tainted-ins-only", DT_(clo_tainted_ins_only)) {}
	else if VG_BOOL_CLO(arg, "--critical-ins-only", DT_(clo_critical_ins_only)) {}
	else if VG_BOOL_CLO(arg, "--smt2", DT_(clo_smt2)) {}
	else if VG_BOOL_CLO(arg, "--trace-ins-taint", trace_ins_taint) {}
	else if VG_BOOL_CLO(arg, "--trace-obj-taint", trace_obj_taint) {}
	else if VG_BOOL_CLO(arg, "--trace-art-method", trace_art_method) {}
	else if VG_BOOL_CLO(arg, "--output-log-info", output_log_info) {}
	else
		return VG_(replacement_malloc_process_cmd_line_option)(arg);

	return True;
}

static void dt_print_usage(void) {
	VG_(printf)(
			"    --tainted-ins-only= no|yes    print tainted instructions only [yes]\n"
			"    --critical-ins-only= no|yes   print critical instructions only [yes]\n"
			"    --smt2= no|yes                output SMT-LIBv2 format [no]\n"
			"    --trace-ins-taint= no|yes     do instruction level taint propagation [no]\n"
			"    --trace-obj-taint= no|yes     do object level taint propagation [no]\n"
			"    --trace-art-method= no|yes    do art method invocation tracking [no]\n"
			"    --output-log-info= no|yes     output loginfo to file or logcat  [yes]\n"
			);

}
static void dt_print_debug_usage(void) {
}
/*-------------------- End -----------------------*/



static const HChar *anonymous_obj = "???";
struct fd_info fds[TG_N_THREADS][FD_MAX];


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

HChar *inet_ntoa(struct in_addr in)
{ 
	static HChar b[18];
	register UChar *p = (UChar*)&in;
	VG_(snprintf)(b, sizeof(b), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return b;	
}

Int inet_aton(UChar *cp,	struct in_addr *ap)
{
	Int dots = 0;
	register UWord acc = 0, addr = 0;

	do {
		register char cc = *cp;

		switch (cc) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				acc = acc * 10 + (cc - '0');
				break;

			case '.':
				if (++dots > 3) {
					return 0;
				}
				/* Fall through */

			case '\0':
				if (acc > 255) {
					return 0;
				}
				addr = addr << 8 | acc;
				acc = 0;
				break;

			default:
				return 0;
		}
	} while (*cp++) ;

	/* Normalize the address */
	if (dots < 3) {
		addr <<= 8 * (3 - dots) ;
	}

	/* Store it if requested */
	if (ap) {
		ap->s_addr = HTONL(addr);
	}
	return 1;    
}

HChar* mmap_proto2a(Int flag) {
	HChar pro[4] = {'\0'};
	pro[0] = (flag & PROT_READ) ? 'r' : '-';
	pro[1] = (flag & PROT_WRITE) ? 'w' : '-';
	pro[2] = (flag & PROT_EXEC) ? 'x' : '-';
	pro[3] = '\0';
	return pro;
}
/*------------------------------------------------------------*/
/*--- Register event handlers                       ---*/
/*------------------------------------------------------------*/
static
void dt_pre_mem_read ( CorePart part, ThreadId tid, const HChar* s,
		Addr base, SizeT size ) {
	if (DT_(clo_taint_begin))
		DT_LOGI("pre_read(%d): 0x%x %d %s\n", tid, base, size, s);
}
static
void dt_pre_mem_read_asciiz ( CorePart part, ThreadId tid, const HChar* s,
		Addr str ) {
	if (DT_(clo_taint_begin))
		DT_LOGI("pre_read_asciiz(%d): 0x%x %s\n", tid, str, s);
}
static
void dt_pre_mem_write ( CorePart part, ThreadId tid, const HChar* s,
		Addr base, SizeT size ) {
	if (DT_(clo_taint_begin))
		DT_LOGI("pre_write(%d): 0x%x %d %s\n", tid, base, size, s);
}
static
void dt_post_mem_write ( CorePart part, ThreadId tid, Addr a, SizeT len) {
	if (DT_(clo_taint_begin))
		DT_LOGI("post_write(%d): 0x%x %d\n", tid, a, len);
}

/* When some chunk of guest state is written, mark the corresponding
	 shadow area as valid.  This is used to initialise arbitrarily large
	 chunks of guest state, hence the _SIZE value, which has to be as
	 big as the biggest guest state.
	 */
static void dt_post_reg_write ( CorePart part, ThreadId tid,
		PtrdiffT offset, SizeT size)
{
#  define MAX_REG_WRITE_SIZE 1712
	if (DT_(clo_taint_begin))
		DT_LOGI("post_reg_write(%d): offset_%d size_%d\n", tid, offset, size);
#if 0
	UChar area[MAX_REG_WRITE_SIZE];
	tl_assert(size <= MAX_REG_WRITE_SIZE);
	VG_(memset)(area, V_BITS8_UNTAINTED, size);
	VG_(set_shadow_regs_area)( tid, 1/*shadowNo*/,offset,size, area );
#endif
#  undef MAX_REG_WRITE_SIZE
}

static void dt_post_reg_write_clientcall ( ThreadId tid,
		PtrdiffT offset, SizeT size, Addr f)
{
	if (DT_(clo_taint_begin))
		DT_LOGI("post_reg_write_clientcall(%d): offset_%d size_%d a_0x%x\n", tid, offset, size, f);
	//dt_post_reg_write(/*dummy*/0, tid, offset, size);
}


/*------------------------------------------------------------*/
/*--- Register-memory event handlers                       ---*/
/*------------------------------------------------------------*/
static void dt_copy_mem_to_reg ( CorePart part, ThreadId tid, Addr a,
		PtrdiffT guest_state_offset, SizeT size ) {
	if (DT_(clo_taint_begin))
		DT_LOGI("mem_to_reg(%d): a_0x%x -> r_%d %d\n", tid, a, guest_state_offset, size);
}

static void dt_copy_reg_to_mem ( CorePart part, ThreadId tid, 
		PtrdiffT guest_state_offset, Addr a, SizeT size ) {
	if (DT_(clo_taint_begin))
		DT_LOGI("reg_to_mem(%d): r_%d -> a_0x%x %d\n", tid, guest_state_offset,a, size);
}

static void dt_new_mem_startup ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx, 
		ULong di_handle ) {
	if (DT_(clo_taint_begin))
		DT_LOGI("new_mem_startup: a_0x%x %d\n", a, len);
}

static void dt_copy_address_range_state ( Addr src, Addr dst, SizeT len) {
	if (DT_(clo_taint_begin))
	{
		DT_LOGI("copy_mem_remap: a_0x%x -> a_0x%x %d\n", src, dst, len);
		DT_(copy_address_range_state) (src, dst, len);
	}
}

static void dt_track_die_mem_stack_signal (Addr a, SizeT len) {
	if (DT_(clo_taint_begin))
	{
		DT_LOGI("die_mem_stack_signal: a_0x%x %d\n", a, len);
		DT_(make_mem_noaccess) ( a, len );
	}
}

static void dt_track_die_mem_brk (Addr a, SizeT len) {
	if (DT_(clo_taint_begin))
	{
		DT_LOGI("die_mem_brk: a_0x%x %d\n", a, len);
		DT_(make_mem_noaccess) ( a, len );
	}
}

static void dt_track_new_mem_mmap ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx,
		ULong di_handle ) {
	if (DT_(clo_taint_begin))
	{
		DT_LOGI("new_mem_mmap: a_0x%x %d\n", a, len);
		DT_(make_mem_untainted) ( a, len );
	}
}

static void dt_track_die_mem_munmap (Addr a, SizeT len) {
	if (DT_(clo_taint_begin))
	{
		DT_LOGI("die_mem_munmap: a_0x%x %d\n", a, len);
		DT_(make_mem_noaccess) ( a, len );
	}
}

/*-----------------------------------------------------------*/
/*--- Instrumentation state switch                        ---*/
/*-----------------------------------------------------------*/
static void DT_(set_instrumentate)(const HChar *reason, Bool state) {
	if( DT_(clo_taint_begin) == state ) {
		DT_LOGI("%s: instrumentation already %s\n",
				reason, state ? "ON" : "OFF");
		return;
	}
	DT_(clo_taint_begin) = state;
#if 1
	VG_(discard_translations_safely)( (Addr)0x1000, ~(SizeT)0xfff, "malton");
#else
	VALGRIND_DISCARD_INS_CACHE(reason);
#endif
	if (state) 
		initFilterlist();
	else
		releaseFilterlist();

	DT_LOGI("%s: Switch instrumentation %s ... \n",
			reason, state ? "ON" : "OFF");

	if (VG_(clo_verbosity) > 1)
		VG_(message)(Vg_DebugMsg, "%s: instrumentation switched %s\n",
				reason, state ? "ON" : "OFF");
}

	static
void dt_discard_superblock_info ( Addr orig_addr, VexGuestExtents vge )
{
	tl_assert(vge.n_used > 0);
	if (1)
		VG_(printf)( "discard_superblock_info: oa_0x%x, ba_%x, %llu, %d\n",
				(void*)orig_addr,
				(void*)vge.base[0], (ULong)vge.len[0],
				vge.n_used);

	// Get BB info, remove from table, free BB info.  Simple!
	// When created, the BB is keyed by the first instruction address,
	// (not orig_addr, but eventually redirected address). Thus, we
	// use the first instruction address in vge.
} 
static ULong init_tv = 0; 
Bool DT_(handle_client_requests) ( ThreadId tid, UWord *arg, UWord *ret) {
#ifdef DEBUG_IDLE
	return False;
#endif
	Int i;
	Addr bad_addr;
	if((DT_(clo_taint_begin) == False) && (DT_(dex_is_open) == True))
		DT_(set_instrumentate)("Invoke", True);

	switch (arg[0]) {
		case VG_USERREQ__WRAPPER_GETTIMEOFDAY:
			{
#if 0
				ULong currt_tv;
				struct vki_timeval* tv = (struct vki_timeval*)arg[1];
				if(init_tv > 0) {
					currt_tv = tv->tv_sec * 1000000ULL + tv->tv_usec;
					currt_tv = (currt_tv - init_tv) / 10 + init_tv;
					tv->tv_sec  = currt_tv / 1000000;
					tv->tv_usec = currt_tv % 1000000;
				} else {
					init_tv = tv->tv_sec * 1000000ULL + tv->tv_usec;
				}
				DT_LOGI("[0]LIBCWRAP(%d):gettimeofday res=%u.%u (%llu)\n", 
						tid, tv->tv_sec, tv->tv_usec, currt_tv);
#endif
				break;
			}
		case VG_USERREQ__COPY_MEM_TAINT:
			{
				DT_(copy_address_range_state)(arg[2], arg[3], arg[4]);
				break;
			}
		case VG_USERREQ__WRAPPER_OPEN:
			{
				HChar* path = (HChar*)arg[1];
				Int  fd = (Int)arg[2];
				if(DT_(clo_taint_begin) == False) { 
					if(fds[tid][fd].type == FdAppDex)
					{
						DT_LOGI("%s\n", "Tracing starts...");
					}
				}
				DT_LOGI("POSTREQ(%d):open(%s) res=%d\n",tid, path, fd);
				break;
			}
		case VG_USERREQ__WRAPPER_SOCKET:
			{
				Int namespace = (Int)arg[1];
				Int style			= (Int)arg[2];
				Int protocol	= (Int)arg[3];
				Int sk        = (Int)arg[4];
				DT_LOGI("POSTREQ(%d):socket %d %d %d res_sk=%d\n", 
						tid, namespace,	style, protocol, sk);
				/*DT_LOGI("POSTREQ(%d):socket %d(%s) %d(%s) %d(%s) res_sk=%d\n", 
					tid, namespace, ADDRESS_FAMILY[namespace],
					style, SOCKET_TYPE[style],
					protocol, PROTOCOL_FAMILY[protocol],
					sk);*/
				break;
			}
		case VG_USERREQ__WRAPPER_BIND:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				if (sa->sa_family == AF_INET)
					addr = inet_ntoa(sa->addr);
				else
					addr = ((struct sockaddr*)sa)->sa_data;
				DT_LOGI("POSTREQ(%d):bind sk=%d, family=%d, addr=%s\n",
						tid, sk, sa->sa_family, addr);
				break;
			}
		case VG_USERREQ__WRAPPER_CONNECT_PRE:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				if (sa->sa_family == AF_INET) {
					addr = inet_ntoa(sa->addr);
					DT_LOGI("PREVREQ(%d):connect sk=%d, AF_INET, addr=%s:%d\n",
							tid, sk, addr, NTOHS(sa->sa_port));
					//inet_aton("10.10.0.1", &sa->addr);
					//addr = inet_ntoa(sa->addr);
					//DT_EXE_LOGI("PREVREQ(%d):connect target address modified to %s\n",
					//		tid, addr);
				}
				else {
					addr = ((struct sockaddr*)sa)->sa_data;
					DT_LOGI("PREVREQ(%d):connect sk=%d, AF_UNIX, addr=%s\n",
							tid, sk, addr);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_CONNECT:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				Int* res = (Int*)arg[3];
				if (sa->sa_family == AF_INET) {
					addr = inet_ntoa(sa->addr);
					DT_LOGI("POSTREQ(%d):connect sk=%d, AF_INET, addr=%s:%d, res=%d (taint)\n",
							tid, sk, addr, NTOHS(sa->sa_port), *res);
					if(*res < 0) {
						*res = 0;
						DT_EXE_LOGI("POSTREQ(%d):connect res modified to %d\n", tid, *res);
					}
				}
				else {
					addr = ((struct sockaddr*)sa)->sa_data;
					DT_LOGI("POSTREQ(%d):connect sk=%d, AF_UNIX, addr=%s, res=%d\n",
							tid, sk, addr, *res);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_LISTEN:
			{
				Int sk = (Int)arg[1];
				Int bl = (Int)arg[2];
				DT_LOGI("POSTREQ(%d):listen sk=%d, backlog=%d\n", tid, sk, bl);
				break;
			}
		case VG_USERREQ__WRAPPER_ACCEPT:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				Int rk = (Int)arg[3];
				HChar *addr;
				if (sa->sa_family == AF_INET)
					addr = inet_ntoa(sa->addr);
				else
					addr = ((struct sockaddr*)sa)->sa_data;
				DT_LOGI("POSTREQ(%d):accept sk=%d, family=%d, addr=%s, res=%d\n", 
						tid, sk, sa->sa_family, addr, rk);
				break;
			}
		case VG_USERREQ__WRAPPER_SEND:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *res = (Int*)arg[4];
				Bool isT = False;
				DT_LOGI("POSTREQ(%d):send sk=%d, 0x%08x(%s), len=%d\n", 
						tid, sk, (Int)buf, buf, *res);
				if(trace_ins_taint) {
					isT = DT_(check_mem_tainted)(buf, *res);
					if(isT) {
						TNT_LOGI("[T] %d: send sk=%d, 0x%08x(%s), len=%d\n", 
								tid, sk, (Int)buf, buf, *res);
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_SENDTO:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int *rlen = (Int*)arg[5];
				HChar *addr;
				Bool isT = False;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						DT_LOGI("POSTREQ(%d):sendto sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						DT_LOGI("POSTREQ(%d):sendto sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
				} else {
					DT_LOGI("POSTREQ(%d):sendto sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, buf, *rlen);
				}

				if(trace_ins_taint) {
					isT = DT_(check_mem_tainted)(buf, *rlen);
					if(isT) {
						DT_LOGI("[T] %d: sendto sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_RECV_PRE:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *bufsize = (Int*)arg[4];

				DT_LOGI("PREVREQ(%d):recv sk=%d, 0x%08x, size=%d\n", 
						tid, sk, (Int)buf, *bufsize);
				break;
			}
		case VG_USERREQ__WRAPPER_RECV:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *res = (Int*)arg[4];

				DT_LOGI("POSTREQ(%d):recv sk=%d, 0x%08x(%s), len=%d\n", 
						tid, sk, (Int)buf, buf, *res);

				break;
			}
		case VG_USERREQ__WRAPPER_RECVFROM_PRE:
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
						DT_LOGI("[0]PREVREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						DT_LOGI("[0]PREVREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
				} else {
					DT_LOGI("[0]PREVREQ(%d):recvfrom sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, (HChar*)buf, *rlen);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_RECVFROM:
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
						DT_LOGI("[1]POSTREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						DT_LOGI("[1]POSTREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
				} else {
					DT_LOGI("[1]POSTREQ(%d):recvfrom sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, (HChar*)buf, *rlen);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_READ:
			{
				Int fd = arg[1];
				DT_LOGI("LIBC(%d):read(%d) a_0x%x, l_%d %s)\n", 
						tid, fd, arg[2], arg[3], (HChar*)arg[2]);
				break;
			}
		case VG_USERREQ__WRAPPER_WRITE:
			{
				Int len = (Int)arg[3];
				DT_LOGI("LIBC(%d):write() a_0x%x, l_%d %s)\n", 
						tid, arg[2], arg[3], (HChar*)arg[2]);
				DT_(check_mem_tainted) ((Addr)arg[2], (SizeT)arg[3]);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKE_PRE:
			{
				DT_LOGI("[0]LIBART(%d) Invoke()\n", tid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKE:
			{
				struct ArtMethodPlus *pArtMth = (struct ArtMethodPlus*)arg[1];
				DT_LOGI("[1]LIBART(%d) Invoke() ArtMethod=0x%08x\n", tid, (Addr)pArtMth);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CALLMETHODA:
			{
				HChar* fn_name = (HChar*)arg[1];
				Int mid				 = arg[2];
				Int type			 = arg[3];
				Int invoke		 = arg[4];
				DT_LOGI("[1]LIBART(%d) CallMethodA() %s mid=%d type=%d invoke=%d\n", 
						tid, fn_name, mid, type, invoke);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CALLMETHODV:
			{
				HChar* fn_name = (HChar*)arg[1];
				Int mid				 = arg[2];
				Int type			 = arg[3];
				Int invoke		 = arg[4];
				DT_LOGI("[1]LIBART(%d) CallMethodV() %s mid=%d type=%d invoke=%d\n", 
						tid, fn_name, mid, type, invoke);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEXFILE:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				Addr	base = (Addr)arg[2];
				UInt  len	 = (UInt)arg[3];
				struct StdString *location = (struct StdString*)arg[4];
				Addr	memmap = (Addr)arg[5];
				DT_LOGI("[1]LIBART(%d):DexFile() pMemMapObj=0x%08x, location=%s, pDexFileObj=0x%08s\n",
						tid, (Addr)pMemMapObj, location->data, (Addr)pDexFileObj);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENMEMORY:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct StdString	 *location		= (struct StdString*)arg[2];
				struct MemMapPlus  *pMemMapObj  = (struct MemMapPlus*)arg[3];
				DT_LOGI("[1]LIBART(%d):OpenMemory() pMemMapObj=0x%08x, location=%s, pDexFileObj=0x%08x\n",
						tid, (Addr)pMemMapObj, location->data, (Addr)pDexFileObj);
			}
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE:
			{
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS:
			{
				HChar* desc = (HChar*)arg[1];
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[2];
				DT_LOGI("[1]LIBART(%d):DefineClass() pDexFileObj=0x%08x %s\n",
						tid, (Addr)pDexFileObj, desc);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY:
			{
				struct StdString* path = (struct StdString*)arg[2];
				DT_LOGI("[1]LIBART(%d):LoadNativeLibrary() %s\n",tid, path->data);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEWITHVARARGS:
			{
				Int mid = (Int)arg[3];
				DT_LOGI("[1]LIBART(%d):InvokeWithVarArgs() mid=%d\n",tid, mid);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_INVOKEWITHJVALUES:
			{
				Int mid = (Int)arg[3];
				DT_LOGI("[1]LIBART(%d):InvokeWithJValues() mid=%d\n",tid, mid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHJVALUES:
			{
				Int mid = (Int)arg[3];
				DT_LOGI("[1]LIBART(%d):InvokeVirtualOrInterfaceWithJValues() mid=%d\n",tid, mid);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHVARARGS:
			{
				Int mid = (Int)arg[3];
				DT_LOGI("[1]LIBART(%d):InvokVirtualOrInterfaceWithVarArgs() mid=%d\n",tid, mid);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_INVOKEMETHOD:
			{
				DT_LOGI("[1]LIBART(%d):InvokeMethod()\n",tid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIFINDCLASS:
			{
				HChar *class_name = (HChar*)arg[2];
				Addr  res					= (Addr)arg[3];
				DT_LOGI("[1]LIBART(%d):FindClass() %s 0x%08x\n",tid, class_name, res);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIGETMETHODID:
			{
				Addr cl = (Addr)arg[1];
				HChar* mth_name = (HChar*)arg[2];
				HChar* sig = (HChar*)arg[3];
				Addr res = (Addr)arg[4];
				DT_LOGI("[1]LIBART(%d):GetMethodID() 0x%08x %s %s id=0x%08x\n",tid, cl, mth_name, sig, res);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID:
			{
				Addr cl = (Addr)arg[1];
				HChar* mth_name = (HChar*)arg[2];
				HChar* sig = (HChar*)arg[3];
				Addr res = (Addr)arg[4];
				DT_LOGI("[1]LIBART(%d):GetStaticMethodID() 0x%08x %s %s id=0x%08x\n",tid, cl, mth_name, sig, res);
				break;
			}
		default:
			{
				return False;
			}
	}
	return True;
}


/* Get the debug info of BB */
	static __inline__
Bool dt_get_debug_info( Addr instr_addr,
		const HChar **dir,
		const HChar **file,
		const HChar **fn_name,
		UInt *line_num,
		DebugInfo **pDebugInfo) 
{
	Bool found_file_line, found_fn, result = True;
	UInt line;

	// DDT_FEXE_PRINTF(6, "  + get_debug_info(%#lx)\n", instr_addr);

	if (pDebugInfo) {
		*pDebugInfo = VG_(find_DebugInfo)(instr_addr);

		// for generated code in anonymous space, pSegInfo is 0
	}

	found_file_line = VG_(get_filename_linenum)(instr_addr,
			file,
			dir,
			&line);
	found_fn = VG_(get_fnname)(instr_addr, fn_name);

	if (!found_file_line && !found_fn) {
		*file = "???";
		*fn_name = "???";
		if (line_num) *line_num=0;
		result = False;

	} else if ( found_file_line &&  found_fn) {
		if (line_num) *line_num=line;

	} else if ( found_file_line && !found_fn) {
		*fn_name = "???";
		if (line_num) *line_num=line;

	} else  /*(!found_file_line &&  found_fn)*/ {
		*file = "???";
		if (line_num) *line_num=0;
	}

	DT_LOGI("- get_debug_info(%#lx): seg '%s', fn %s\n",
			instr_addr,
			!pDebugInfo   ? "-" :
			(*pDebugInfo) ? VG_(DebugInfo_get_filename)(*pDebugInfo) :
			"(None)",
			*fn_name);

	return result;
}

/* Get the general info of the BB */
	static __inline__
void dt_get_bb_info(Addr addr)
{
	const HChar *fnname, *filename, *dirname;
	DebugInfo *di;
	UInt line_num;
	Bool res = False;

	DT_LOGI("+ get_bb_info (BB %#lx)\n", addr);

	res = dt_get_debug_info(addr, &dirname, &filename,
			&fnname, &line_num, &di);
	if(di)
		DT_LOGI("Obj %#lx name: %s\n", addr, fnname);
}
	static
IRSB* dt_instrument ( VgCallbackClosure* closure,
		IRSB* sbIn,
		const VexGuestLayout* layout, 
		const VexGuestExtents* vge,
		const VexArchInfo* archinfo_host,
		IRType gWordTy, IRType hWordTy )
{
	IRSB		*sbOut;
	IRStmt	*st;
	HChar		*obj_name;
	Addr		origAddr;

	Int i;
	VG_(printf)("Input:\n");
	ppIRSB(sbIn);

	sbOut = deepCopyIRSBExceptStmts(sbIn);
	i = 0;
	while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
		addStmtToIRSB( sbOut, sbIn->stmts[i]);
		i++;
	}
	st = sbIn->stmts[i];
	origAddr = st->Ist.IMark.addr + st->Ist.IMark.delta;
	dt_get_bb_info(origAddr);
	return sbIn;
}

/*--------------- adjustment by N bytes ---------------*/

static void dt_new_mem_stack ( Addr a, SizeT len )
{  
	if (DT_(clo_taint_begin))
		DT_LOGI("new mem stack 0x%x %d\n", (Int)a, len );
	DT_(make_mem_untainted) ( -VG_STACK_REDZONE_SZB + a, len ); 
}  

static void dt_die_mem_stack ( Addr a, SizeT len )
{  
	//PROF_EVENT(MCPE_DIE_MEM_STACK);
	if (DT_(clo_taint_begin))
		DT_LOGI("die mem stack 0x%x %d\n", (Int)(-VG_STACK_REDZONE_SZB + a), len );
	DT_(make_mem_noaccess) ( -VG_STACK_REDZONE_SZB + a, len );
}  

static void dt_ban_mem_stack ( Addr a, SizeT len )
{
	if (DT_(clo_taint_begin))
		DT_LOGI("ban mem stack 0x%x %d\n", (Int)a, len );
	DT_(make_mem_noaccess) ( a, len );
}


/*--- Syscall event handlers ---*/
static void dt_pre_syscall(ThreadId tid, UInt syscallno, UWord *args, UInt nArgs) {
}
static void dt_post_syscall(ThreadId tid, UInt syscallno, UWord *args, UInt nArgs, SysRes res) {
#ifdef DEBUG_IDLE
	return;
#endif
	//DT_(syscall_allowed_check)(tid, syscallno);
	if ((DT_(clo_taint_begin) == False)) { 
		if((syscallno != __NR_open) && (syscallno != __NR_openat))
			return;
	}

	switch ((int)syscallno) {
#if defined	VGO_freebsd
#else
		// Should be defined by respective include/vki/vki-scnums-arch-os.h
		case __NR_clone:
			DT_(syscall_clone)(tid, args, nArgs, res);
			break;
		case __NR_rt_sigaction:
		case __NR_sigaction:
			DT_(syscall_action)(tid, args, nArgs, res);
			break;
		case __NR_unlink:
		case __NR_unlinkat:
			//DT_(syscall_unlink)(tid, args, nArgs, res);
			break;
		case __NR_execve:
			DT_(syscall_execve)(tid, args, nArgs, res);
			break;
		case __NR_read:
			DT_(syscall_read)(tid, args, nArgs, res);
			break;
		case __NR_pread64:
			DT_(syscall_pread)(tid, args, nArgs, res);
			break;
		case __NR_readv:
			DT_(syscall_readv)(tid, args, nArgs, res);
			break;
		case __NR_preadv:
			DT_(syscall_preadv)(tid, args, nArgs, res);
			break;
		case __NR_write:
			DT_(syscall_write)(tid, args, nArgs, res);
			break;
		case __NR_writev:
			DT_(syscall_writev)(tid, args, nArgs, res);
			break;
		case __NR_pwritev:
			DT_(syscall_pwritev)(tid, args, nArgs, res);
			break;
		case __NR_close:
			DT_(syscall_close)(tid, args, nArgs, res);
			break;
		case __NR_mprotect:
			DT_(syscall_mprotect)(tid, args, nArgs, res);
			break;
		case __NR_msync:
			DT_(syscall_msync)(tid, args, nArgs, res);
			break;
		case __NR_munmap:
			DT_(syscall_munmap)(tid, args, nArgs, res);
			break;
		case __NR_setuid:
		case __NR_setuid32:
			DT_(syscall_setuid)(tid, args, nArgs, res);
			break;
		case __NR_setreuid:
		case __NR_setreuid32:
			DT_(syscall_setreuid)(tid, args, nArgs, res);
			break;
		case __NR_setgid:
		case __NR_setgid32:
			DT_(syscall_setgid)(tid, args, nArgs, res);
			break;
		case __NR_setregid:
		case __NR_setregid32:
			DT_(syscall_setregid)(tid, args, nArgs, res);
			break;
		case __NR_mmap2:
			DT_(syscall_mmap)(tid, args, nArgs, res);
			break;
		case __NR_ptrace:
			DT_(syscall_ptrace)(tid, args, nArgs, res);
			break;
		case __NR_open:
		case __NR_openat:
			DT_(syscall_open)(tid, args, nArgs, res);
			break;

#if 0
		case __NR_lseek:
			//	DT_(syscall_lseek)(tid, args, nArgs, res);
			break;
#ifdef __NR_llseek
		case __NR_llseek:
			DT_(syscall_llseek)(tid, args, nArgs, res);
			break;
#endif
#endif
#ifdef __NR_send
		case __NR_send:
			DT_(syscall_send)(tid, args, nArgs, res);
			break;
#endif
#ifdef __NR_sendto
		case __NR_sendto:
			DT_(syscall_sendto)(tid, args, nArgs, res);
			break;
#endif
#ifdef __NR_recv
		case __NR_recv:
			DT_(syscall_recv)(tid, args, nArgs, res);
			break;
#endif
#ifdef __NR_recvfrom
		case __NR_recvfrom:
			DT_(syscall_recvfrom)(tid, args, nArgs, res);
			break;
#endif
		default:
			break;
#endif // VGO_freebsd
	}
}


/* Valgrind core functions */
static int dt_isatty(void) {
	HChar buf[256], dev2[11];
	const HChar dev[] = "/dev/pts/";
	int i;
	VG_(readlink)("/proc/self/fd/2", buf, 255);
	for ( i=0; i<10; i++ )
	{
		VG_(sprintf)(dev2, "%s%d", dev, i);
		if ( VG_(strncmp)(buf, dev2, 10) == 0 ) return 1;
	}
	return 0;
}

static void dt_post_clo_init(void) {
	if( DT_(clo_critical_ins_only) )
		DT_(clo_tainted_ins_only) = True;

	// Initialise temporary variables/reg SSA index array
	Int i;
	for( i=0; i< TI_MAX; i++ ) {
		ti[i] = 0;
		tv[i] = 0;
		tt[i] = 0;
	}
	for( i=0; i< RI_MAX; i++ )
		ri[i] = 0;
	for( i=0; i< STACK_SIZE; i++ )
		lvar_i[i] = 0;
	lvar_s.size = 0;

	//   if (DT_(read_syscalls_file)) {
	//	   read_allowed_syscalls();
	//   }

	// DEBUG
	//tnt_read = 0;

	// If stdout is not a tty, don't highlight text
	istty = dt_isatty();

	// Print SMT2 preamble if output is smt2
	if ( DT_(clo_smt2) )
	{
		DT_(smt2_preamble)();
		DT_(clo_tainted_ins_only) = True;
		DT_(clo_critical_ins_only) = False;
	}
	DT_(clo_taint_begin) = False;
}
static void dt_fini(Int exitcode)
{
}

static void dt_pre_clo_init(void)
{
	VG_(details_name)            ("Datatrace");
	VG_(details_version)         (NULL);
	VG_(details_description)     ("Sensitive information leackage tracking");
	VG_(details_copyright_author)(
			"Copyright (C) 2002-2015, and GNU GPL'd, by Nicholas Nethercote.");
	VG_(details_bug_reports_to)  (VG_BUGS_TO);
	VG_(details_avg_translation_sizeB) ( 500 );

	//VG_(details_avg_translation_sizeB) ( 275 );
	VG_(basic_tool_funcs)					(dt_post_clo_init,
			DT_(instrument),
			dt_fini);
	//VG_(needs_superblock_discards)(dt_discard_superblock_info);
	VG_(needs_syscall_wrapper)		(dt_pre_syscall, 
			dt_post_syscall);

	VG_(needs_var_info)						();

	init_shadow_memory();
	init_soaap_data();

	VG_(needs_libc_freeres)				();
	VG_(needs_malloc_replacement)	(DT_(malloc),
			DT_(__builtin_new),
			DT_(__builtin_vec_new),     
			DT_(memalign),
			DT_(calloc),
			DT_(free),
			DT_(__builtin_delete),
			DT_(__builtin_vec_delete),
			DT_(realloc),
			DT_(malloc_usable_size), 
			DT_MALLOC_REDZONE_SZB ); 

	VG_(needs_client_requests) (DT_(handle_client_requests));
	DT_(malloc_list) = VG_(HT_construct)( "DT_(malloc_list)" );
	VG_(needs_command_line_options)(dt_process_cmd_line_options,
			dt_print_usage,
			dt_print_debug_usage);


#if 0
	VG_(track_new_mem_startup)		 ( dt_new_mem_startup );
	VG_(track_new_mem_mmap)				 ( dt_track_new_mem_mmap );
	VG_(track_die_mem_munmap)      ( dt_track_die_mem_munmap );
	VG_(track_copy_mem_remap)      ( dt_copy_address_range_state ); 

	VG_(track_die_mem_stack_signal)( dt_track_die_mem_stack_signal );
	VG_(track_die_mem_brk)				 ( dt_track_die_mem_brk );

	VG_(track_new_mem_stack)			 ( dt_new_mem_stack );
	VG_(track_die_mem_stack)       ( dt_die_mem_stack );
	VG_(track_ban_mem_stack)       ( dt_ban_mem_stack );

	VG_(track_pre_mem_read)				 ( dt_pre_mem_read );
	VG_(track_pre_mem_read_asciiz) ( dt_pre_mem_read_asciiz );
	VG_(track_pre_mem_write)			 ( dt_pre_mem_write );
	VG_(track_post_mem_write)			 ( dt_post_mem_write );

	VG_(track_post_reg_write)                  ( dt_post_reg_write );
	VG_(track_post_reg_write_clientcall_return)( dt_post_reg_write_clientcall );

	VG_(track_copy_mem_to_reg)		 ( dt_copy_mem_to_reg );
	VG_(track_copy_reg_to_mem)		 ( dt_copy_reg_to_mem );
#endif
}

VG_DETERMINE_INTERFACE_VERSION(dt_pre_clo_init)

	/*--------------------------------------------------------------------*/
	/*--- end                                                          ---*/
	/*--------------------------------------------------------------------*/
