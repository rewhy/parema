#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"    // tl_assert()
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_machine.h"       // VG_(fnptr_to_fnentry)
#include "pub_tool_libcbase.h"      // VG_(strcmp)
#include "pub_tool_options.h"

#include "pub_tool_guest.h"
#include "pub_tool_debuginfo.h"
#include "pub_core_threadstate.h"

#include "unistd-asm-arm.h"

#include "util.h"
#include "copy.h"
#include "fz_oatplus.h"
#include "fz_wrappers.h"
#include "fz_framework.h"
#include "fz_oatdexparse.h"

#include "shadow_memory.h"
#include "taint_analysis.h"
#include "symbolic_execution.h"
#include "fz_path_explorer.h"

#define FZ_DEBUG
#undef  FZ_DEBUG

#define FZ_LOG_ALL_MTH
//#undef  FZ_LOG_ALL_MTH

#define FZ_ONLY_JAVA_METHOD
//#undef  FZ_ONLY_JAVA_METHOD
// export VALGRIND_LIB=/home/fanatic/valgrind-3.8.1/inst/lib/valgrind/


/*----- For wrapping Java method -----*/

Addr test_ret = 0;

Addr string_equals_entry_addr = 0;
Addr string_equals_return_addr = 0;
Addr log_println_native_entry_addr = 0;
Addr log_println_native_return_addr = 0;
Addr lang_exception_init_addr = 0;
Addr native_poll_once_addr = 0;
Addr runtime_get_runtime_addr = 0;
static UInt lang_exception_init_index = 12692;
static ULong blocks1 = 0;
static ULong blocks2 = 0;
static UInt  fz_num = 0;
/*-----------  End  ----------------*/


static Char* clo_fnname = NULL;
int fd_to_taint = 0;

UInt fz_sink_method_index = 0;
HChar *fz_sink_method_name = NULL;
UInt fz_arg_taint_method_index = 0;
HChar *fz_arg_taint_method_name = NULL;
UInt fz_res_taint_method_index = 0;
HChar *fz_res_taint_method_name = NULL;

//static Bool fz_is_start = False;
static Bool fz_method_trace = False;
static UInt isExploring = 0;
static struct inMemInfo exeInfo;
//static UInt fz_tid = 1;

/*------------- Added for ART framework tracking ------------------*/
DebugInfo* di_art;

static Addr base_oatdata_addr = 0;
static UInt base_oatdata_size = 0;
static Addr base_oatexec_addr = 0;
static UInt base_oatexec_size = 0;

static Addr boot_oatdata_addr = 0;
static UInt boot_oatdata_size = 0;
static Addr boot_oatexec_addr = 0;
static UInt boot_oatexec_size = 0;

#define isExplore() \
	(isExploring == VG_(get_running_tid)())
/*
	 static INLINE
	 Bool isExplore() {
	 if(isExploring == 0)
	 return False;
	 if(isExploring == VG_(get_running_tid)())
	 return True;
	 return False;
	 }
	 */

static INLINE
Bool isBaseAddr(Addr addr) {
	if( (addr >= base_oatdata_addr) && (addr < (base_oatdata_addr + base_oatdata_size)) )
		return True; //BASE_OATDATA_ADDR;
	if( (addr >= base_oatexec_addr) && (addr < (base_oatexec_addr + base_oatexec_size)) )
		return True; //BASE_OATEXEC_ADDR;
	return False;//NOTART_ADDR;
}

static INLINE
Bool isBootAddr(Addr addr) {
	if( (addr >= boot_oatdata_addr) && (addr < (boot_oatdata_addr + boot_oatdata_size)) )
		return True; //BASE_OATDATA_ADDR;
	if( (addr >= boot_oatexec_addr) && (addr < (boot_oatexec_addr + boot_oatexec_size)) )
		return True; //BASE_OATEXEC_ADDR;
	return False;//NOTART_ADDR;
}

static INLINE
Bool isJavaCode(Addr addr) {
	return (isBootAddr(addr) || isBaseAddr(addr));
}

static INLINE
UInt isBaseMethod(MthNode *mNode) {
	VG_(printf)("%s\n", mNode->method);
	return (mNode->type & TYPE_BASE);
}

static INLINE
UInt isBootMethod(MthNode *mNode) {
	return (mNode->type & TYPE_BOOT);
}

void parseOatFile() {
	HChar *soname = NULL;
	Addr avma, oatdata, oatexec;
	SizeT size, oatdataSize, oatexecSize;

	DebugInfo* di = VG_(next_DebugInfo) (NULL);
	while(di) {
		soname = VG_(DebugInfo_get_soname)(di);
		if(VG_(DebugInfo_is_oat)(di)) {
			MY_LOGI("Meet oat file: %s\n", soname);
			if(VG_(get_symbol_range_SLOW)(di, "oatdata", &oatdata, &oatdataSize)) {
				MY_LOGI("oatdata: 0x%08x - 0x%08x\n", oatdata, oatdata+oatdataSize);
				if(VG_(get_symbol_range_SLOW)(di, "oatexec", &oatexec, &oatexecSize)) {
					MY_LOGI("oatexec: 0x%08x - 0x%08x\n", oatexec, oatexec+oatexecSize);
					if( (VG_(strcmp)("base.odex", soname) == 0) ) {
						oatDexParse(oatdata, oatdataSize, oatexec, oatexecSize, False);
						base_oatdata_addr = oatdata;
						base_oatdata_size = oatdataSize;
						base_oatexec_addr = oatexec;
						base_oatexec_size = oatexecSize;

					} else if (VG_(strcmp)("system@framework@boot.oat", soname) == 0) {
						oatDexParse(oatdata, oatdataSize, oatexec, oatexecSize, True);
						boot_oatdata_addr = oatdata;
						boot_oatdata_size = oatdataSize;
						boot_oatexec_addr = oatexec;
						boot_oatexec_size = oatexecSize;

					}
				}
			}
		}
		di = VG_(next_DebugInfo)(di);
	}
}

static void fz_set_instrumentate(const HChar *reason, Bool state) {

	fz_method_trace = state; // Represent the instrumentation state

	VG_(discard_translations_safely)( (Addr)0x1000, ~(SizeT)0x7fff, "datatrace");

	if (state)
		parseOatFile();
	//	initFilterlist();
	//else
	//	releaseFilterlist();
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
Bool fz_handle_client_requests( ThreadId tid, UWord *arg, UWord *ret) {
	switch (arg[0]) {
		case VG_USERREQ__WRAPPER_ART_OPENMEMORY_PRE:
			{
				struct StdString	 *location		= (struct StdString*)arg[1];
				struct MemMapPlus	 *pMemMapObj	= (struct MemMapPlus*)arg[2];
				MY_LOGI("[1]LIBART(%d):OpenMemory() pMemMapObj=0x%08x, location=%s\n",
						tid, (Addr)pMemMapObj, location->data);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENMEMORY:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct StdString	 *location		= (struct StdString*)arg[2];
				struct MemMapPlus	 *pMemMapObj	= (struct MemMapPlus*)arg[3];
				MY_LOGI("[1]LIBART(%d):OpenMemory() pMemMapObj=0x%08x, location=%s, pDexFileObj=0x%08x\n",
						tid, (Addr)pMemMapObj, location->data, (Addr)pDexFileObj);
				if(location->data) {
					if(is_base_apk(location->data)) {
						fz_set_instrumentate("start instrumentation", True);
					}
				}
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

//
//  CONCOLIC EXECUTION HELPERS
//

static VG_REGPARM(4) void helper_instrument_Put(UInt offset, IRTemp data, Int value, UInt size)
{
	if (!isExplore())
		return;

	if (get_reg_from_offset(offset) == guest_INVALID)
	{
		tl_assert(!IRTemp_is_tainted(data));
		return;
	}

	// Do taint propagation from tmporary to register
	if (register_is_tainted(offset) != IRTemp_is_tainted(data))
	{
#ifdef FZ_LOG_IR
		if(data == IRTemp_INVALID) {
			ST_LOGI("PUT(%d) <- 0x%x:I%d\n", offset, value, size);
		} else {
			ST_LOGI("PUT(%d) <- t%d:I%d | (0x%x)\n", offset, data, size, value);
		}
#endif
		flip_register(offset, IRTemp_is_tainted(data));
	}

	// Do symbolic execution
	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(data)
#else
			True
#endif
		 ) {

		char dep[DEP_MAX_LEN] = {0};
#ifdef FZ_EXE_TAINT
		char *dep_rhs = get_temporary_dep(data);
#else
		char *dep_rhs = NULL;
		char dep_tmp[DEP_MAX_LEN] = {0};
		if( data == IRTemp_INVALID )
		{
			VG_(snprintf)(dep_tmp, DEP_MAX_LEN, "FIX:%d(%u)", size, value);
			dep_rhs = dep_tmp;
		} else {
			dep_rhs = get_temporary_dep(data);
		}
#endif

		if(dep_rhs) {
			//VG_(snprintf)(dep, DEP_MAX_LEN, "PUT(%s)", dep_rhs);
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", dep_rhs);
			update_register_dep(offset, size, dep);
		} else {
			free_register_dep(offset);
		}
	} else {
		free_register_dep(offset);
	}
}

static VG_REGPARM(4) void helper_instrument_PutI(UInt base, UInt ix, UInt bias, UInt nElems)
{
	if (!isExplore())
		return;

	VG_(printf)("PutI()\n");
	UInt index = base+((ix+bias)%nElems);

	tl_assert(get_reg_from_offset(index) == guest_INVALID);
}

static VG_REGPARM(4) void helper_instrument_WrTmp_Get(IRTemp tmp, UInt offset, UInt value, UInt size)
{
	if (!isExplore())
		return;
	// Do taint propagation
	if (temporary_is_tainted(tmp) != register_is_tainted(offset))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- GET:I%d(%u) | 0x%x\n", tmp, size, offset, value);
#endif
		flip_temporary(tmp);
	}

	// Do symbolic execution
	if (
#ifdef FZ_EXE_TAINT
			register_is_tainted(offset)
#else
			True
#endif 
		 ) {
		char dep[DEP_MAX_LEN] = {0};
		char *tmp_rhs = NULL;
		tmp_rhs = get_register_dep(offset);
		if(tmp_rhs) {
			//VG_(snprintf)(dep, DEP_MAX_LEN, "GET(%s)", tmp_rhs);
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", tmp_rhs);
			update_temporary_dep(tmp, dep, size);
		} else {
			free_temporary_dep(tmp);
		}
	} else {
		free_temporary_dep(tmp);
	}
}
static VG_REGPARM(4) void helper_instrument_WrTmp_GetI(UInt base, UInt ix, UInt bias, UInt nElems)
{
	if (!isExplore())
		return;

	VG_(printf)("GetI()\n");
	UInt index = base+((ix+bias)%nElems);

	tl_assert(get_reg_from_offset(index) == guest_INVALID);
}

	static VG_REGPARM(3) 
void helper_instrument_WrTmp_RdTmp(IRTemp tmp_lhs, IRTemp tmp_rhs, UInt size)
{
	if (!isExplore())
		return;

	if (temporary_is_tainted(tmp_lhs) != temporary_is_tainted(tmp_rhs))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- t%d:I%d\n", tmp_lhs, tmp_rhs, size);
#endif
		flip_temporary(tmp_lhs);
	}

	if (
#ifdef FZ_EXE_TAINT
			temporary_is_tainted(tmp_rhs)
#else
			True
#endif 
		 ) {
		char dep[DEP_MAX_LEN] = {0};
		char *dep_rhs = NULL;
		dep_rhs = get_temporary_dep(tmp_rhs);
		if(dep_rhs) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "RdTmp(%s)", dep_rhs);
			update_temporary_dep(tmp_lhs, dep, size);
		} else {
			free_temporary_dep(tmp_lhs);
		}
	}
	else
	{
		free_temporary_dep(tmp_lhs);
	}
}

	static VG_REGPARM(4) 
void helper_instrument_WrTmp_Triop_SetElem(IRStmt *clone, UInt size, UInt arg1_value, UInt arg3_value)
{
	if (!isExplore())
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
	char str[32] = {0},  dep[DEP_MAX_LEN] = {0};
	IROp_to_str(op, str);

	if ((temporary_is_tainted(tmp) != temporary_is_tainted(arg1)) 
			|| (temporary_is_tainted(tmp) != temporary_is_tainted(arg3)))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- %s(t%d, 0x%x:I8, t%d) | (0x%x, 0x%x, 0x%x)\n",
				tmp, str, arg1, arg2_value, arg3, arg1_value, arg2_value, arg3_value);
#endif
		flip_temporary(tmp);
	}

	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg3)
#else
			True
#endif
		 )	{
		char *tmp_rhs1 = NULL, *tmp_rhs3 = NULL;
		//VG_(printf)("WrTmp_Binop: t%d=%s(t%d, t%d)\n", tmp, str, arg1, arg2);
		if (
#ifdef FZ_EXE_TAINT
				!IRTemp_is_tainted(arg1)
#else
				arg1 == IRTemp_INVALID
#endif
			 )	{
			tmp_rhs3 = get_temporary_dep(arg3);
			if(tmp_rhs3) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "%s(FIX:%d(%u),%u,%s)", 
						str, size1, arg1_value, arg2_value, tmp_rhs3);
				update_temporary_dep(tmp, dep, size0);
			} else {
				free_temporary_dep(tmp);
			}
			return;
		}
		if (
#ifdef FZ_EXE_TAINT
				!IRTemp_is_tainted(arg3)
#else
				arg3 == IRTemp_INVALID
#endif
			 ) {
			tmp_rhs1 = get_temporary_dep(arg1);
			if(tmp_rhs1) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%u,FIX:%d(%u))", 
						str, tmp_rhs1, arg2_value, size3, arg3_value);
				update_temporary_dep(tmp, dep, size0);
			} else {
				free_temporary_dep(tmp);
			}
			return;
		} 

		tmp_rhs1 = get_temporary_dep(arg1);
		tmp_rhs3 = get_temporary_dep(arg3);
		if(tmp_rhs1 && tmp_rhs3) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%u,%s)", 
					str, tmp_rhs1, arg2_value, tmp_rhs3);
			update_temporary_dep(tmp, dep, size0);
		} else {
			free_temporary_dep(tmp);
		}
		return;
	}
	free_temporary_dep(tmp);
	return;
}
static VG_REGPARM(4) void helper_instrument_WrTmp_Binop(IRStmt *clone, UInt size, UInt arg1_value, UInt arg2_value)
{
	if (!isExplore())
		return;

	IRExpr *e1 = NULL, *e2 = NULL;
	char str[32] = {0}, dep[DEP_MAX_LEN] = {0};

	tl_assert(clone);

	e1 = clone->Ist.WrTmp.data->Iex.Binop.arg1;
	e2 = clone->Ist.WrTmp.data->Iex.Binop.arg2;
	IROp	 op		= clone->Ist.WrTmp.data->Iex.Binop.op;
	IRTemp tmp  = clone->Ist.WrTmp.tmp;
	IRTemp arg1 = (e1->tag == Iex_RdTmp) ? e1->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp arg2 = (e2->tag == Iex_RdTmp) ? e2->Iex.RdTmp.tmp : IRTemp_INVALID;
	Int size0 = size & 0xff, size1 = (size >> 8) & 0xff, size2 = (size >> 16) & 0xff;

	IROp_to_str(op, str);

	/* if(op == Iop_GetElem8x8) {
		 ppIRStmt(clone);
		 VG_(printf)("(0x%x = GetElem8x8(0x%x, %d))\n", arg1_value, arg2_value);
		 }*/
	//VG_(printf)("t%d=%s(t%d, t%d)\n", tmp, str, arg1, arg2);
	if ((temporary_is_tainted(tmp) != IRTemp_is_tainted(arg1)) 
			|| (temporary_is_tainted(tmp) != IRTemp_is_tainted(arg2))) {
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- %s(t%d, t%d) | (0x%x 0x%x)\n", tmp, str, arg1, arg2, arg1_value, arg2_value);
#endif
		flip_temporary(tmp);
	}

	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg2)
#else
			True
#endif
		 )	{
		char *tmp_rhs1 = NULL, *tmp_rhs2 = NULL;
		//VG_(printf)("WrTmp_Binop: t%d=%s(t%d, t%d)\n", tmp, str, arg1, arg2);
		if (
#ifdef FZ_EXE_TAINT
				!IRTemp_is_tainted(arg1)
#else
				arg1 == IRTemp_INVALID
#endif
			 )	{
			tmp_rhs2 = get_temporary_dep(arg2);
			if(tmp_rhs2) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "%s(FIX:%d(%u),%s)", str, size1, arg1_value, tmp_rhs2);
				update_temporary_dep(tmp, dep, size0);
			} else {
				free_temporary_dep(tmp);
			}
			return;
		}

		if (
#ifdef FZ_EXE_TAINT
				!IRTemp_is_tainted(arg2)
#else
				arg2 == IRTemp_INVALID
#endif
			 ) {
			tmp_rhs1 = get_temporary_dep(arg1);
			if(tmp_rhs1) {
				if(op == Iop_GetElem8x8 || op == Iop_GetElem16x4 || op == Iop_GetElem32x2) {
					VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%u)", str, tmp_rhs1, size2, arg2_value);
				} else {
					VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,FIX:%d(%u))", str, tmp_rhs1, size2, arg2_value);
				}
				update_temporary_dep(tmp, dep, size0);
			} else {
				free_temporary_dep(tmp);
			}
			return;
		} 

		tmp_rhs1 = get_temporary_dep(arg1);
		tmp_rhs2 = get_temporary_dep(arg2);
#if 0
		char const_rhs1[DEP_MAX_LEN], const_rhs2[DEP_MAX_LEN];
		if( arg1 == IRTemp_INVALID) {
			VG_(snprintf)(const_rhs1, DEP_MAX_LEN, "FIX:%d(%u)", size1, arg1_value);
			tmp_rhs1 = const_rhs1;
		} else {
			tmp_rhs1 = get_temporary_dep(arg1);
		}
		if( arg2 == IRTemp_INVALID) {
			VG_(snprintf)(const_rhs2, DEP_MAX_LEN, "FIX:%d(%u)", size2, arg2_value);
			tmp_rhs2 = const_rhs2;
		} else {
			tmp_rhs2 = get_temporary_dep(arg2);
		}
#endif
		if(tmp_rhs1 && tmp_rhs2) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%s)", str, tmp_rhs1, tmp_rhs2);
			update_temporary_dep(tmp, dep, size0);
		} else {
			free_temporary_dep(tmp);
		}
		return;
		//VG_(printf)("tmp=%d %s size=%d\n", tmp, dep, size);
	}
	//VG_(printf)("%s(_%d, _%d)\n", str, arg1, arg2);
	free_temporary_dep(tmp);
	return;
}

#if 0
static VG_REGPARM(0) void helper_instrument_WrTmp_Binop(IRTemp tmp, IRTemp arg1, IRTemp arg2, UInt op, UInt size, UInt arg1_value, UInt arg2_value)
{
	if (fz_is_start == False)
		return;
	char str[32] = {0};
	char dep[DEP_MAX_LEN] = {0};
	IROp_to_str(op, str);
	if (temporary_is_tainted(tmp) != (IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg2)))
	{
		flip_temporary(tmp);
	}

	if (IRTemp_is_tainted(arg1) || IRTemp_is_tainted(arg2))
	{
		if (!IRTemp_is_tainted(arg1))
		{
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%u,%s)", str, arg1_value, get_temporary_dep(arg2));
		}
		else if (!IRTemp_is_tainted(arg2))
		{
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%u)", str, get_temporary_dep(arg1), arg2_value);
		}
		else
		{
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s,%s)", str, get_temporary_dep(arg1), get_temporary_dep(arg2));
		}

		update_temporary_dep(tmp, dep, size);
	}
	else
	{
		//VG_(printf)("%s(_%d, _%d)\n", str, arg1, arg2);
		free_temporary_dep(tmp);
	}
}
#endif
static VG_REGPARM(4) void helper_instrument_WrTmp_Unop(IRTemp tmp, IRTemp arg, UInt op, UInt size)
{
	if (!isExplore())
		return;

	char str[32] = {0};
	char dep[DEP_MAX_LEN] = {0};

	IROp_to_str(op, str);

	if (temporary_is_tainted(tmp) != IRTemp_is_tainted(arg))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d = %s(t%d)\n", tmp, str, arg);
#endif
		flip_temporary(tmp);
	}

	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(arg)
#else
			True
#endif 
		 )	{
		char *tmp_rhs = NULL; //get_temporary_dep(arg);
		tmp_rhs = get_temporary_dep(arg);
		if(tmp_rhs) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s)", str, tmp_rhs);
			update_temporary_dep(tmp, dep, size);
		} else {
			free_temporary_dep(tmp);
		}
	}
	else
	{
		free_temporary_dep(tmp);
	}
}
//static VG_REGPARM(4) void helper_instrument_WrTmp_Load(IRTemp tmp, UInt addr, UInt size, UInt load_value)
static VG_REGPARM(3) void helper_instrument_WrTmp_Load(IRTemp tmp, UInt addr, UInt size)
{
	if (!isExplore())
		return;

	/* Do taint propagation */
	if (temporary_is_tainted(tmp) != memory_is_tainted(addr, size))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- 0x%08x:I%d\n", tmp, addr, size);
#endif
		flip_temporary(tmp);
	}

	/* Do symbolic execution */
	if (
#ifdef FZ_EXE_TAINT
			memory_is_tainted(addr, size)
#else
			True
#endif 
		 ) {
		char dep[DEP_MAX_LEN] = {0};
		char dep_rhs[DEP_MAX_LEN] = {0};
		get_memory_dep(addr, size, dep_rhs, 0);
		if(VG_(strlen)(dep_rhs) > 0) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", dep_rhs);
			update_temporary_dep(tmp, dep, size);
		} else {
			free_temporary_dep(tmp);
		}
	}
	else /* Free the symbolic execution for the tmp */
	{
		free_temporary_dep(tmp);
	}
}
static VG_REGPARM(2) void helper_instrument_WrTmp_Const(IRTemp tmp, UInt value)
{
	if (!isExplore())
		return;
	if (
#ifdef FZ_EXE_TAINT
			temporary_is_tainted(tmp)
#else
			True
#endif 
		 ) {
#ifdef FZ_LOG_IR
		ST_LOGI("t%d = %d", tmp, value);
#endif
		flip_temporary(tmp);
		free_temporary_dep(tmp);
	}
}

static VG_REGPARM(4) void helper_instrument_WrTmp_CCall_armg_calculate_condition(IRStmt* clone, UInt cc_arg1_value, UInt cc_arg2_value, UInt cc_n_op_value)
{
	if (!isExplore())
		return;

	IRExpr** args = clone->Ist.WrTmp.data->Iex.CCall.args;

	Int cond = cc_n_op_value >> 4;
	Int cc_op = cc_n_op_value & 0xF;

	IRTemp tmp = clone->Ist.WrTmp.tmp;
	IRTemp cc_n_op = (args[0]->tag == Iex_RdTmp) ? args[0]->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp cc_arg1 = (args[1]->tag == Iex_RdTmp) ? args[1]->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp cc_arg2 = (args[2]->tag == Iex_RdTmp) ? args[2]->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp cc_arg3 = (args[3]->tag == Iex_RdTmp) ? args[3]->Iex.RdTmp.tmp : IRTemp_INVALID;

	char cc_n_op_dep[DEP_MAX_LEN]={0}, cc_arg1_dep[DEP_MAX_LEN]={0};
	char cc_arg2_dep[DEP_MAX_LEN]={0}, cc_arg3_dep[DEP_MAX_LEN]={0};


	if (temporary_is_tainted(tmp) != IRTemp_is_tainted(cc_arg1)
			|| temporary_is_tainted(tmp) != IRTemp_is_tainted(cc_arg2))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- armg_calculate_condition(t%d,t%d,t%d,t%d) | (%d, %d, %d, %d, 0)\n", 
				tmp, cc_n_op, cc_arg1, cc_arg2, cc_arg3, cc_n_op_value, cc_arg1_value, cc_arg2_value);
#endif
		flip_temporary(tmp);
	}

	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(cc_arg1) || IRTemp_is_tainted(cc_arg2) || IRTemp_is_tainted(cc_arg2)
#else
			True
#endif
		 )	{
		char dep[DEP_MAX_LEN] = {0};
		char *tmp_rhs = NULL;

		if(IRTemp_is_tainted(cc_arg1)) {
			tmp_rhs = get_temporary_dep(cc_arg1);
			if(tmp_rhs)
				VG_(sprintf)(cc_arg1_dep, "%s", tmp_rhs);
			else
				VG_(strcpy)(cc_arg1_dep, "unknown");
		} else {
			VG_(sprintf)(cc_arg1_dep, "FIX:32(%u)", cc_arg1_value);
		}

		if(IRTemp_is_tainted(cc_arg2)) {
			tmp_rhs = get_temporary_dep(cc_arg2);
			if(tmp_rhs)
				VG_(sprintf)(cc_arg2_dep, "%s", tmp_rhs);
			else
				VG_(strcpy)(cc_arg2_dep, "unknown");
		} else {
			VG_(sprintf)(cc_arg2_dep, "FIX:32(%u)", cc_arg2_value);
		}
#if 0	
		if(IRTemp_is_tainted(cc_arg3)) {
			tmp_rhs = get_temporary_dep(cc_arg3);
			if(tmp_rhs)
				VG_(sprintf)(cc_arg3_dep, "%s", tmp_rhs);
			else
				VG_(strcpy)(cc_arg3_dep, "unknown");
		} else {
			VG_(sprintf)(cc_arg3_dep, "%u", 0);
		}
#endif

		// VG_(snprintf)(dep, DEP_MAX_LEN, "armg_calculate_condition(%u, %s, %s, %s)", 
		//		cc_n_op_value, cc_arg1_dep, cc_arg2_dep, cc_arg3_dep);
		VG_(snprintf)(dep, DEP_MAX_LEN, "armg_calculate_condition(%u,%s,%s)", 
				cc_n_op_value, cc_arg1_dep, cc_arg2_dep);
		update_temporary_dep(tmp, dep, 32); // 1 because armg_calculate_condition returns UInt

#if 0
		if (
#ifdef FZ_EXE_TAINT
				!IRTemp_is_tainted(cc_arg1)
#else
				cc_arg1 == IRTemp_INVALID
#endif
			 )	{
			tmp_rhs2 = get_temporary_dep(cc_arg2);
			if(tmp_rhs2) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "armg_calculate_condition(%u, %u, %u, %s)", 
						cond, cc_op_value, cc_arg1_value, tmp_rhs2);
				update_temporary_dep(tmp, dep, 32); // 1 because armg_calculate_condition returns UInt
			} else {
				free_temporary_dep(tmp);
			}
		} else if (
#ifdef FZ_EXE_TAINT
				!IRTemp_is_tainted(cc_arg2)
#else
				cc_arg2 == IRTemp_INVALID
#endif
				)	{
			tmp_rhs1 = get_temporary_dep(cc_arg1);
			if(tmp_rhs1) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "armg_calculate_condition(%u, %u, %s, %u)", 
						cond, cc_op_value, tmp_rhs1, cc_arg2_value);
				update_temporary_dep(tmp, dep, 32); // 1 because armg_calculate_condition returns UInt
			} else {
				free_temporary_dep(tmp);
			}
		} else {
			tmp_rhs1 = get_temporary_dep(cc_arg1);
			tmp_rhs2 = get_temporary_dep(cc_arg2);
			if( tmp_rhs1 && tmp_rhs2) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "armg_calculate_condition(%u, %u, %s, %s)", 
						cond, cc_op_value, tmp_rhs1, tmp_rhs2);
				update_temporary_dep(tmp, dep, 32); // 1 because armg_calculate_condition returns UInt
			} else {
				free_temporary_dep(tmp);
			}
		}
#endif
	} else {
		free_temporary_dep(tmp);
	}
}

#if 0
static VG_REGPARM(0) void helper_instrument_WrTmp_CCall_x86g_calculate_condition(IRTemp tmp, IRTemp cc_dep1, IRTemp cc_dep2, UInt cond, UInt cc_op_value, UInt cc_dep1_value, UInt cc_dep2_value)
{
	if (fz_is_start == False)
		return;
	if (temporary_is_tainted(tmp) != (IRTemp_is_tainted(cc_dep1) || IRTemp_is_tainted(cc_dep2)))
	{
		flip_temporary(tmp);
	}

	if (IRTemp_is_tainted(cc_dep1) || IRTemp_is_tainted(cc_dep2))
	{
		char dep[DEP_MAX_LEN] = {0};

		if (!IRTemp_is_tainted(cc_dep1))
		{
			VG_(snprintf)(dep, DEP_MAX_LEN, "x86g_calculate_condition(%u, %u, %u, %s)", cond, cc_op_value, cc_dep1_value, get_temporary_dep(cc_dep2));
		}
		else if (!IRTemp_is_tainted(cc_dep2))
		{
			VG_(snprintf)(dep, DEP_MAX_LEN, "x86g_calculate_condition(%u, %u, %s, %u)", cond, cc_op_value, get_temporary_dep(cc_dep1), cc_dep2_value);
		}
		else
		{
			VG_(snprintf)(dep, DEP_MAX_LEN, "x86g_calculate_condition(%u, %u, %s, %s)", cond, cc_op_value, get_temporary_dep(cc_dep1), get_temporary_dep(cc_dep2));
		}

		update_temporary_dep(tmp, dep, 32); // 1 because x86g_calculate_condition returns UInt
	}
	else
	{
		free_temporary_dep(tmp);
	}
}
#endif
static VG_REGPARM(0) void helper_instrument_WrTmp_CCall_else()
{
	if (!isExplore())
		return;
	// VG_(printf)("helper_instrument_WrTmp_CCall_else\n");
}

static VG_REGPARM(3) void helper_instrument_WrTmp_ITE(IRStmt *clone, UInt cond_value, UInt size)
{
	if (!isExplore())
		return;
	IRTemp	tmp		= clone->Ist.WrTmp.tmp;
	IRExpr* data	= clone->Ist.WrTmp.data;
	IRExpr* econd  = data->Iex.ITE.cond;
	IRExpr* eexpr0	= data->Iex.ITE.iftrue;
	IRExpr* eexprX	= data->Iex.ITE.iffalse;
	IRTemp  cond    = (econd->tag == Iex_RdTmp) ? econd->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  expr0   = (eexpr0->tag == Iex_RdTmp) ? eexpr0->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  exprX   = (eexprX->tag == Iex_RdTmp) ? eexprX->Iex.RdTmp.tmp : IRTemp_INVALID;
	//VG_(printf)("t%d = ITE(%d, t%d, t%d)\n", cond, tmp, expr0, exprX);
	char expr_is_tainted = (cond_value == 0) ? IRTemp_is_tainted(exprX) : IRTemp_is_tainted(expr0);

#ifdef FZ_LOG_IR
	if(IRTemp_is_tainted(exprX) || IRTemp_is_tainted(expr0))
		ST_LOGI("t%d = ITE(t%d, t%d, t%d) | (%c)\n", tmp, cond, expr0, exprX, cond_value == 0 ? 'F' : 'T' );
#endif
	if (temporary_is_tainted(tmp) != expr_is_tainted)
	{
		flip_temporary(tmp);
	}

	if (
#ifdef FZ_EXE_TAINT
			expr_is_tainted
#else
			True
#endif 
		 )	{
		char dep[DEP_MAX_LEN] = {0}, const_rhs[DEP_MAX_LEN] = {0};
		char *tmp_rhs = NULL;
		if(cond_value == 0) {
			if(exprX == IRTemp_INVALID) {
				VG_(snprintf)(const_rhs, DEP_MAX_LEN, "FIX:%d(%u)", size, valueOfConst(eexprX));
				tmp_rhs = const_rhs;
			} else {
				tmp_rhs = get_temporary_dep(exprX);
			}
		} else {
			if(expr0 == IRTemp_INVALID) {
				VG_(snprintf)(const_rhs, DEP_MAX_LEN, "FIX:%d(%u)", size, valueOfConst(eexpr0));
				tmp_rhs = const_rhs;
			} else {
				tmp_rhs = get_temporary_dep(expr0);
			}
		}

		if(tmp_rhs) {
			//VG_(snprintf)(dep, DEP_MAX_LEN, "ITE(%s)", tmp_rhs);
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", tmp_rhs);
			update_temporary_dep(tmp, dep, size);
		} else {
			free_temporary_dep(tmp);
		}
	}
	else
	{
		free_temporary_dep(tmp);
	}
}

#if 0
static VG_REGPARM(0) void helper_instrument_WrTmp_ITE(IRTemp tmp, UInt cond, IRTemp expr0, IRTemp exprX, UInt size)
{
	if (fz_is_start == False)
		return;
	char expr_is_tainted = (cond == 0) ? IRTemp_is_tainted(expr0) : IRTemp_is_tainted(exprX);

	if (temporary_is_tainted(tmp) != expr_is_tainted)
	{
		flip_temporary(tmp);
	}

	if (expr_is_tainted)
	{
		char dep[DEP_MAX_LEN] = {0};

		VG_(snprintf)(dep, DEP_MAX_LEN, "Mux0X(%s)", (cond == 0 ? get_temporary_dep(expr0) : get_temporary_dep(exprX)));

		update_temporary_dep(tmp, dep, size);
	}
	else
	{
		free_temporary_dep(tmp);
	}
}
#endif

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
static VG_REGPARM(4) void helper_instrument_LoadG(IRStmt *clone, UInt addr_value, UInt size, UInt guard_value)
{
	if (!isExplore())
		return;

	char str[32] = {'\0'};
	IRLoadG* lg		= clone->Ist.LoadG.details;
	IRLoadGOp cvt = lg->cvt;
	IRTemp dst		= lg->dst;
	IRTemp addr		= (lg->addr->tag == Iex_RdTmp)  ? lg->addr->Iex.RdTmp.tmp  : IRTemp_INVALID;
	IRTemp guard	= (lg->guard->tag == Iex_RdTmp) ? lg->guard->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp alt		= (lg->alt->tag == Iex_RdTmp)   ? lg->alt->Iex.RdTmp.tmp   : IRTemp_INVALID;
	//if(size == 8)
	//	VG_(printf)("Load from 0x%08x %c\n", addr_value, *((Char*)addr_value));

	//UChar expr_is_tainted = (guard_value == 0) ? IRTemp_is_tainted(alt) : (memory_is_tainted(addr_value, size) | IRTemp_is_tainted(addr));
	UChar expr_is_tainted = (guard_value == 0) ? IRTemp_is_tainted(alt) : memory_is_tainted(addr_value, size);

	//if( guard_value != 0) 
	//	VG_(printf)("t%d <- t%d ? 0x%08x:I%d : t%d | (%c)\n", dst, guard, addr_value, size, alt, guard_value == 0 ? 'F' : 'T');
	IRLoadGOp_to_str(cvt, str);
	if (temporary_is_tainted(dst) != expr_is_tainted)
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- t%d ? %s(LDle:%d(t%d) : t%d | (0x%08x, %c)\n", 
				dst, guard, str, size, addr, alt, addr_value, guard_value == 0 ? 'F' : 'T');
#endif
		flip_temporary(dst);
	}

	if (
#ifdef FZ_EXE_TAINT
			expr_is_tainted
#else
			True
#endif
		 )	{
		HChar dep[DEP_MAX_LEN] = {0};
		HChar dep_rhs[DEP_MAX_LEN] = {0};
		if(guard_value != 0) {
			ppIRStmt(clone); VG_(printf)("\n");
			get_memory_dep(addr_value, size, dep_rhs, 0);
			if(VG_(strlen)(dep_rhs) > 0) {
				//VG_(snprintf)(dep, DEP_MAX_LEN, "%s(LDle-Cond:%d(%s))", str, size, dep_rhs);
				//VG_(snprintf)(dep, DEP_MAX_LEN, "%s(LDle:%d(%s))", str, size, dep_rhs);
				VG_(snprintf)(dep, DEP_MAX_LEN, "%s(%s)", str, dep_rhs);
				update_temporary_dep(dst, dep, size);
			} else {
				free_temporary_dep(dst);
			}
		} else {
			char *tmp_rhs = get_temporary_dep(alt);
			if(tmp_rhs) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "RdTmp(%s)", tmp_rhs);
				update_temporary_dep(dst, dep, size);
			} else {
				free_temporary_dep(dst);
			}
		}
	}
	else
	{
		free_temporary_dep(dst);
	}
}
static VG_REGPARM(3) void helper_instrument_Store(IRStmt *stclone, UInt addr, IRTemp data, UInt size)
{
	if (!isExplore())
		return;
	if (memory_is_tainted(addr, size) != IRTemp_is_tainted(data))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("0x%08x:I%d <- t%d\n", addr, size, data);
#endif
		flip_memory(addr, size, IRTemp_is_tainted(data));
	}

	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(data)
#else
			True
#endif
		 ) {
		char dep[DEP_MAX_LEN] = {0};
		char *tmp_rhs = NULL;
#ifdef FZ_EXE_TAINT
		tmp_rhs = get_temporary_dep(data);
#else
		char const_rhs[DEP_MAX_LEN] = {0};
		if( data != IRTemp_INVALID) {
			tmp_rhs = get_temporary_dep(data);
		}	else {
			VG_(snprintf)(dep, DEP_MAX_LEN, "FIX:%d(%u)", size, valueOfConst(stclone->Ist.Store.data));
			tmp_rhs = const_rhs;
		}
#endif
		if(tmp_rhs) {
			//VG_(snprintf)(dep, DEP_MAX_LEN, "STle:%d(%s)", size, tmp_rhs);
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", tmp_rhs);
			update_memory_dep(addr, dep, size);
		} else {
			free_memory_dep(addr, size);
		}
	}
	else
	{
		free_memory_dep(addr, size);
	}
}
//static VG_REGPARM(0) void helper_instrument_StoreG(UInt addr, IRTemp data, UInt size, UInt guard)
static VG_REGPARM(4) void helper_instrument_StoreG(IRStmt *clone, UInt addr, UInt size, UInt guard_value)
{
	if (!isExplore())
		return;

	IRStoreG* sg = clone->Ist.StoreG.details;
	//IRExpr* addr = sg->addr;
	IRTemp  data  = (sg->data->tag == Iex_RdTmp)  ? sg->data->Iex.RdTmp.tmp  : IRTemp_INVALID;
	IRTemp  guard = (sg->guard->tag == Iex_RdTmp) ? sg->guard->Iex.RdTmp.tmp : IRTemp_INVALID;

	if(guard_value == 0)
		return;
	if (memory_is_tainted(addr, size) != IRTemp_is_tainted(data))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("if(t%d) 0x%08x:I%d <- t%d | (%c)\n", guard, addr, size, data, guard_value == 0 ? 'F' : 'T');
#endif
		flip_memory(addr, size, IRTemp_is_tainted(data));
	}

	if (
#ifdef FZ_EXE_TAINT
			IRTemp_is_tainted(data)
#else
			True
#endif
		 )	{
		char dep[DEP_MAX_LEN] = {0};
		char *tmp_rhs = get_temporary_dep(data);
		if(tmp_rhs) {
			//VG_(snprintf)(dep, DEP_MAX_LEN, "STle(%s)", get_temporary_dep(data));
			//VG_(snprintf)(dep, DEP_MAX_LEN, "STle-Cond:%d(%s)", size, tmp_rhs);
			//VG_(snprintf)(dep, DEP_MAX_LEN, "STle:%d(%s)", size, tmp_rhs);
			VG_(snprintf)(dep, DEP_MAX_LEN, "%s", tmp_rhs);
			update_memory_dep(addr, dep, size);
		} else {
			free_memory_dep(addr, size);
		}
	}
	else
	{
		free_memory_dep(addr, size);
	}
}

static VG_REGPARM(4) void helper_instrument_CAS_single_element(UInt addr, IRTemp dataLo, UInt size, UInt cas_succeeded)
{
	if (!isExplore())
		return;
	// Never met	
	tl_assert(0);

	if (cas_succeeded)
	{
		if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
		{
#ifdef FZ_LOG_IR
			ST_LOGI("0x%08x:I%d <- CASle(t%d)\n", addr, size, dataLo);
#endif
			flip_memory(addr, size, IRTemp_is_tainted(dataLo));
		}

		if (
#ifdef FZ_EXE_TAINT
				IRTemp_is_tainted(dataLo)
#else
				True
#endif 
			 )	{
			char dep[DEP_MAX_LEN] = {0};
			char *tmp_rhs = NULL;
			tmp_rhs = get_temporary_dep(dataLo);
			if(tmp_rhs) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", tmp_rhs);
				update_memory_dep(addr, dep, size);
			} else {
				free_memory_dep(addr, size);
			}
		}
		else
		{
			free_memory_dep(addr, size);
		}
	}
}

static VG_REGPARM(4) void helper_instrument_CAS_double_element(IRStmt* clone, UInt addr, UInt size, UInt cas_succeeded)
{
	if (!isExplore())
		return;
	char dep[DEP_MAX_LEN] = {0};
	char *tmp_rhs = NULL;
	IRCAS*  cas = clone->Ist.CAS.details;
	IRTemp  dataLo = (cas->expdLo->tag == Iex_RdTmp) ? cas->expdLo->Iex.RdTmp.tmp : IRTemp_INVALID;
	IRTemp  dataHi = (cas->expdHi->tag == Iex_RdTmp) ? cas->expdHi->Iex.RdTmp.tmp : IRTemp_INVALID;
	// Never met	
	tl_assert(0);
	if (cas_succeeded)
	{
		if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
		{
#ifdef FZ_LOG_IR
			ST_LOGI("0x%08x:I%d <- CASle(t%d, t%d)\n", addr+size, size, dataHi, dataLo);
#endif
			//ST_LOGI("0x%08x:I%d <- CASle(t%d, t%d)\n", addr, size, dataHi, dataLo);
			flip_memory(addr, size, IRTemp_is_tainted(dataLo));
		}

		if (memory_is_tainted(addr+size, size) != IRTemp_is_tainted(dataHi))
		{
#ifdef FZ_LOG_IR
			ST_LOGI("0x%08x:I%d <- CASle(t%d, t%d)\n", addr+size, size, dataHi, dataLo);
#endif
			flip_memory(addr+size, size, IRTemp_is_tainted(dataHi));
		}

		if (
#ifdef FZ_EXE_TAINT
				IRTemp_is_tainted(dataLo)
#else
				True
#endif
			 )	{
			tmp_rhs = get_temporary_dep(dataLo);
			if(tmp_rhs) { 
				VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", tmp_rhs);
				update_memory_dep(addr, dep, size);
			} else {
				free_memory_dep(addr, size);
			}
		}
		else
		{
			free_memory_dep(addr, size);
		}

		if (
#ifdef FZ_EXE_TAINT
				IRTemp_is_tainted(dataHi)
#else
				True
#endif
			 )	{
			tmp_rhs = get_temporary_dep(dataHi);
			if(tmp_rhs) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", tmp_rhs);
				update_memory_dep(addr+size, dep, size);
			} else {
				free_memory_dep(addr, size);
			}
		}
		else
		{
			free_memory_dep(addr+size, size);
		}
	}
}

#if 0
static VG_REGPARM(0) void helper_instrument_CAS_double_element(UInt addr, IRTemp dataLo, IRTemp dataHi, UInt size, UInt oldLo_succeeded, UInt oldHi_succeeded)
{
	if (fz_is_start == False)
		return;
	char cas_succeeded = oldLo_succeeded && oldHi_succeeded;

	if (cas_succeeded)
	{
		if (memory_is_tainted(addr, size) != IRTemp_is_tainted(dataLo))
		{
			flip_memory(addr, size, IRTemp_is_tainted(dataLo));
		}

		if (memory_is_tainted(addr+size, size) != IRTemp_is_tainted(dataHi))
		{
			flip_memory(addr+size, size, IRTemp_is_tainted(dataHi));
		}

		if (IRTemp_is_tainted(dataLo))
		{
			char dep[DEP_MAX_LEN] = {0};

			VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", get_temporary_dep(dataLo));

			update_memory_dep(addr, dep, size);
		}
		else
		{
			free_memory_dep(addr, size);
		}

		if (IRTemp_is_tainted(dataHi))
		{
			char dep[DEP_MAX_LEN] = {0};

			VG_(snprintf)(dep, DEP_MAX_LEN, "CASle(%s)", get_temporary_dep(dataHi));

			update_memory_dep(addr+size, dep, size);
		}
		else
		{
			free_memory_dep(addr+size, size);
		}
	}
}
#endif
//static VG_REGPARM(4) void helper_instrument_LLSC_Load_Linked(IRTemp result, UInt addr, UInt size, UInt load_value)
static VG_REGPARM(4) void helper_instrument_LLSC_Load_Linked(IRTemp result, UInt addr, UInt size)
{
	if (!isExplore())
		return;
	if (temporary_is_tainted(result) != memory_is_tainted(addr, size))
	{
#ifdef FZ_LOG_IR
		ST_LOGI("t%d <- LDle-Linked(0x%08x:I%d)\n", result, addr, size);
#endif
		flip_temporary(result);
	}

	if (
#ifdef FZ_EXE_TAINT
			memory_is_tainted(addr, size)
#else
			True
#endif
		 )	{
		char dep[DEP_MAX_LEN] = {0};
		char dep_rhs[DEP_MAX_LEN] = {0};
		//VG_(printf)("Debug 3 0x%08x:I%d\n", addr, size);
		get_memory_dep(addr, size, dep_rhs, 0);
		if(VG_(strlen)(dep_rhs) > 0) {
			VG_(snprintf)(dep, DEP_MAX_LEN, "LDle-Linked(%s)", dep_rhs);
			update_temporary_dep(result, dep, size);
		} else {
			free_temporary_dep(result);
		}
	}
	else
	{
		free_temporary_dep(result);
	}
}
static VG_REGPARM(4) void helper_instrument_LLSC_Store_Conditional(UInt addr, IRTemp storedata, UInt size, UInt store_succeeded)
{
	if (!isExplore())
		return;
	//if(store_succeeded)
	//VG_(printf)("0x%08x:I%d <- STle-Cond(t%d) | (%c)\n", addr, size, storedata, store_succeeded == 0 ? 'F' : 'T');
	if (store_succeeded)
	{
		if (memory_is_tainted(addr, size) != IRTemp_is_tainted(storedata))
		{
#ifdef FZ_LOG_IR
			ST_LOGI("0x%08x:I%d <- STle-Cond(t%d) | (%c)\n", addr, size, storedata, store_succeeded == 0 ? 'F' : 'T');
#endif
			flip_memory(addr, size, IRTemp_is_tainted(storedata));
		}

		if (
#ifdef FZ_EXE_TAINT
				IRTemp_is_tainted(storedata)
#else
				True
#endif
			 ) {
			char dep[DEP_MAX_LEN] = {0};
			char *dep_rhs = NULL;
			dep_rhs = get_temporary_dep(storedata);
			if(dep_rhs) {
				VG_(snprintf)(dep, DEP_MAX_LEN, "%s", dep_rhs);
				update_memory_dep(addr, dep, size);
			} else {
				free_memory_dep(addr, size);
			}
		}
		else
		{
			free_memory_dep(addr, size);
		}
	}
}
static VG_REGPARM(2) UInt helper_instrument_Exit(IRStmt *clone, UInt guard_value)
{
	if (!isExplore())
		return guard_value;

	IRTemp guard	= (clone->Ist.Exit.guard->tag == Iex_RdTmp) ? clone->Ist.Exit.guard->Iex.RdTmp.tmp : IRTemp_INVALID;
	Int offsIP = clone->Ist.Exit.offsIP;
	Addr dst   = clone->Ist.Exit.dst->Ico.U32;
	Int size = sizeofIRType_bits(typeOfIRConst(clone->Ist.Exit.dst));

	if (guard_value)
	{
		if (register_is_tainted(offsIP))
		{
			flip_register(offsIP, 0);
			free_register_dep(offsIP);
		}
	}

	UInt  pc = VG_(get_IP)( VG_(get_running_tid)() );
	if (
#ifdef FZ_EXE_TAINT
			temporary_is_tainted(guard)
#else
			True
#endif
		 )	{
#ifdef FZ_LOG_IR
		if(isBaseAddr(pc))
			ST_LOGI("if(t%d) goto 0x%08x | (%c)\n", guard, dst, guard_value == 0 ? 'F' : 'T');
#endif
		char* dep = NULL;
		dep = get_temporary_dep(guard);
		if( /*fz_is_mem_range(pc, 4)*/ True ) {
			if (guard_value) {
				EXP_LOGI("branch: TAKEN(%s)\n", dep);
				outputConstraint(dep, True);
			} else {
				EXP_LOGI("branch: NOT_TAKEN(%s)\n", dep);
				outputConstraint(dep, False);
			}
		}
	} 
	else {
		if( fz_is_mem_range(pc, 4) ) {
			VG_(printf)("Untainted branch pc = 0x%08X offsIP = 0x%x, dst = 0x%x, guard = t%d (%d)\n", 
					pc, offsIP, dst, guard, guard_value);
		}
	}
	return guard_value;
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

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_Put",
			VG_(fnptr_to_fnentry)(helper_instrument_Put),
			mkIRExprVec_4(mkIRExpr_HWord(offset),
				mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
				(offset < 140) ? mkIRExpr_HWord(data_value) : assignNew_HWord(sb_out, data),
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
			mkIRExprVec_3(mkIRExpr_HWord(tmp_lhs),
				mkIRExpr_HWord(tmp_rhs),
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

#if defined(VGPV_arm_linux_android)
	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Binop",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Binop),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				mkIRExpr_HWord(size | (size1 << 8) | (size2 << 16)),
				(arg1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg1) : mkIRExpr_HWord(arg1_value),
				(arg2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg2) : mkIRExpr_HWord(arg2_value))
			);

#else
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Binop",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Binop),
			mkIRExprVec_7(mkIRExpr_HWord(tmp),
				mkIRExpr_HWord((arg1->tag == Iex_RdTmp) ? arg1->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord((arg2->tag == Iex_RdTmp) ? arg2->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord(op),
				mkIRExpr_HWord(size),
				(arg1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg1) : mkIRExpr_HWord(arg1_value),
				(arg2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, arg2) : mkIRExpr_HWord(arg2_value))
			);
#endif
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

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Unop",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Unop),
			mkIRExprVec_4(mkIRExpr_HWord(tmp),
				mkIRExpr_HWord((arg->tag == Iex_RdTmp) ? arg->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord(op),
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

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_Load",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_Load),
			mkIRExprVec_3(mkIRExpr_HWord(tmp),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord(size))
			//assignNew_HWord(sb_out, IRExpr_RdTmp(tmp)))
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
	}

#if 0
	if (VG_(strcmp)(cee->name, "x86g_calculate_condition") == 0)
	{
		IRExpr* cond = args[0];
		IRExpr* cc_op = args[1];
		IRExpr* cc_dep1 = args[2];
		IRExpr* cc_dep2 = args[3];

		tl_assert(cond->tag == Iex_Const && cond->Iex.Const.con->tag == Ico_U32);
		tl_assert(isIRAtom(cc_op));
		tl_assert(isIRAtom(cc_dep1));
		tl_assert(isIRAtom(cc_dep2));
		if (cc_op->tag == Iex_Const) tl_assert(cc_op->Iex.Const.con->tag == Ico_U32);
		if (cc_dep1->tag == Iex_Const) tl_assert(cc_dep1->Iex.Const.con->tag == Ico_U32);
		if (cc_dep2->tag == Iex_Const) tl_assert(cc_dep2->Iex.Const.con->tag == Ico_U32);
		// typeOf(x86g_calculate_condition) == typeOf(tmp) == I32
		di = unsafeIRDirty_0_N(0,
				"helper_instrument_WrTmp_CCall_x86g_calculate_condition",
				VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_CCall_x86g_calculate_condition),
				mkIRExprVec_7(mkIRExpr_HWord(tmp),
					mkIRExpr_HWord((cc_dep1->tag == Iex_RdTmp) ? cc_dep1->Iex.RdTmp.tmp : IRTemp_INVALID),
					mkIRExpr_HWord((cc_dep2->tag == Iex_RdTmp) ? cc_dep2->Iex.RdTmp.tmp : IRTemp_INVALID),
					mkIRExpr_HWord(cond->Iex.Const.con->Ico.U32),
					(cc_op->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_op) : mkIRExpr_HWord(cc_op->Iex.Const.con->Ico.U32),
					(cc_dep1->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep1) : mkIRExpr_HWord(cc_dep1->Iex.Const.con->Ico.U32),
					(cc_dep2->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, cc_dep2) : mkIRExpr_HWord(cc_dep2->Iex.Const.con->Ico.U32))
				);
		addStmtToIRSB(sb_out, IRStmt_Dirty(di));
	}
#endif
	else {
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

#if defined(VGPV_arm_linux_android)
	IRStmt* stclone = deepMallocIRStmt(st);
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_ITE",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_ITE),
			mkIRExprVec_3(mkIRExpr_HWord((HWord)stclone),
				assignNew_HWord(sb_out, cond),
				mkIRExpr_HWord(size))
			);
#else // VGA_arm
	di = unsafeIRDirty_0_N(0,
			"helper_instrument_WrTmp_ITE",
			VG_(fnptr_to_fnentry)(helper_instrument_WrTmp_ITE),
			mkIRExprVec_5(mkIRExpr_HWord(tmp),
				assignNew_HWord(sb_out, cond),
				mkIRExpr_HWord((expr0->tag == Iex_RdTmp) ? expr0->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord((exprX->tag == Iex_RdTmp) ? exprX->Iex.RdTmp.tmp : IRTemp_INVALID),
				mkIRExpr_HWord(size))
			);
#endif // defined(VGA_arm)
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
			instrument_WrTmp_Get(st, sb_out);
			break;
		case Iex_GetI:
			instrument_WrTmp_GetI(st, sb_out);
			break;
		case Iex_RdTmp:
			instrument_WrTmp_RdTmp(st, sb_out);
			break;
		case Iex_Unop:
			instrument_WrTmp_Unop(st, sb_out);
			break;
		case Iex_Binop:
			instrument_WrTmp_Binop(st, sb_out);
			break;
		case Iex_Triop:
			instrument_WrTmp_Triop(st, sb_out);
			break;
		case Iex_Load:
			instrument_WrTmp_Load(st, sb_out);
			break;
		case Iex_Const:
			instrument_WrTmp_Const(st, sb_out);
			break;
		case Iex_CCall:
			instrument_WrTmp_CCall(st, sb_out);
			break;
#if 0
		case Iex_Mux0X:
			instrument_WrTmp_Mux0X(st, sb_out);
			break;
#endif
		case Iex_ITE:
			instrument_WrTmp_ITE(st, sb_out);
			break;
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
			mkIRExprVec_4(mkIRExpr_HWord(stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
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

	IRStmt* stclone = deepMallocIRStmt(st);

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_StoreG",
			VG_(fnptr_to_fnentry)(helper_instrument_StoreG),
			mkIRExprVec_4(mkIRExpr_HWord(stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				//mkIRExpr_HWord((data->tag == Iex_RdTmp) ? data->Iex.RdTmp.tmp : IRTemp_INVALID),
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
	Int size = 0;
	IRDirty* di;

	IROp vwiden = Iop_INVALID;
	IRType loadedTy = Ity_INVALID;

	tl_assert(isIRAtom(addr));
	tl_assert(isIRAtom(alt));
	tl_assert(isIRAtom(guard));

	switch (lg->cvt) {
		case ILGop_Ident32: loadedTy = Ity_I32; vwiden = Iop_INVALID; size = 32; break;
		case ILGop_16Uto32: loadedTy = Ity_I16; vwiden = Iop_16Uto32; size = 16; break;
		case ILGop_16Sto32: loadedTy = Ity_I16; vwiden = Iop_16Sto32; size = 16; break;
		case ILGop_8Uto32:  loadedTy = Ity_I8;  vwiden = Iop_8Uto32;  size = 8; break;
		case ILGop_8Sto32:  loadedTy = Ity_I8;  vwiden = Iop_8Sto32;  size = 8; break;
		default: VG_(tool_panic)("instrument_LoadG()");
	}

	IRStmt* stclone = deepMallocIRStmt(st);

	di = unsafeIRDirty_0_N(0,
			"helper_instrument_LoadG",
			VG_(fnptr_to_fnentry)(helper_instrument_LoadG),
			mkIRExprVec_4(mkIRExpr_HWord((HWord)stclone),
				(addr->tag == Iex_RdTmp) ? assignNew_HWord(sb_out, addr) : mkIRExpr_HWord(addr->Iex.Const.con->Ico.U32),
				mkIRExpr_HWord(size),
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
void instrument_Exit(IRStmt* st, IRSB* sb_out)
{
	IRExpr* guard = st->Ist.Exit.guard;
	// Int offsIP = st->Ist.Exit.offsIP;
	// Int size = sizeofIRType_bits(typeOfIRConst(st->Ist.Exit.dst));
	IRDirty* di = NULL;

	tl_assert(guard->tag == Iex_RdTmp);

	IRTemp newGuard32 = newIRTemp(sb_out->tyenv, Ity_I32);
	IRTemp newGuard = newIRTemp(sb_out->tyenv, Ity_I1);
	IRStmt* stclone = deepMallocIRStmt(st);

	di = unsafeIRDirty_1_N(newGuard32,
			2,
			"helper_instrument_Exit",
			VG_(fnptr_to_fnentry)(helper_instrument_Exit),
			//mkIRExprVec_4(assignNew_HWord(sb_out, guard),
		 mkIRExprVec_2(mkIRExpr_HWord((Addr)stclone),
				 // mkIRExpr_HWord(offsIP),
				 // mkIRExpr_HWord(size),
				 assignNew_HWord(sb_out, guard))
			 //mkIRExpr_HWord(guard->Iex.RdTmp.tmp))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));
	addStmtToIRSB(sb_out, IRStmt_WrTmp(newGuard, IRExpr_Unop(Iop_32to1, IRExpr_RdTmp(newGuard32))));
	addStmtToIRSB(sb_out, 
			IRStmt_Exit(IRExpr_RdTmp(newGuard), 
				st->Ist.Exit.jk,
				st->Ist.Exit.dst,
				st->Ist.Exit.offsIP));
	//IRExpr_Unop(Iop_32to1, IRExpr_RdTmp(dst))));
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

#define MAX_PATH    256
static void resolve_fd(Int fd, Char *path, Int max) {
	Char src[MAX_PATH]; // be lazy and use their max
	Int len = 0;
	// TODO: Cache resolved fds by also catching open()s and close()s
	VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), fd);
	len = VG_(readlink)(src, path, max);
	// Just give emptiness on error.
	if (len == -1) {
		len = 0;
	}
	path[len] = '\0';
}

void handle_sys_open(ThreadId tid, UWord *args, UInt nArgs, SysRes res)
{
	UChar pathname[MAX_PATH];
	Int fd = sr_Res(res);
	if (fd > -1)
	{
		resolve_fd(fd, pathname, MAX_PATH-1);
		if (VG_(strcmp)(pathname, clo_fnname) == 0)
		{
			VG_(printf)("open(\"%s\", ..) = %lu\n", pathname, fd);
			fd_to_taint = fd;
			//fz_is_start = True;
		}
	}
}

static void pre_syscall(ThreadId tId, UInt syscall_number, UWord* args, UInt nArgs)
{
}

static void post_syscall(ThreadId tId, UInt syscall_number, UWord* args, UInt nArgs, SysRes res)
{
	switch (syscall_number)
	{
		case __NR_open:
#ifdef __NR_openat
		case __NR_openat:
#endif
			//handle_sys_open(tId, args, nArgs, res);
			break;
		case __NR_read:
			//handle_sys_read(tId, args, nArgs,  res);
			break;
		default:
			break;
	}
}

//
//  BASIC TOOL FUNCTIONS
//
static Bool fz_process_cmd_line_option(Char* arg)
{
	if VG_STR_CLO(arg, "--fname", clo_fnname) {}
	else if VG_INT_CLO(arg, "--sink-index", fz_sink_method_index){}
	else if VG_STR_CLO(arg, "--sink-method", fz_sink_method_name){}
	else if VG_INT_CLO(arg, "--taint-res-index", fz_res_taint_method_index){ VG_(printf)("taint_res_index = %d\n", fz_res_taint_method_index);}
	else if VG_STR_CLO(arg, "--taint-res-name", fz_res_taint_method_name){ VG_(printf)("taint_res_name = %s\n", fz_res_taint_method_name);}
	else if VG_INT_CLO(arg, "--taint-arg-index", fz_arg_taint_method_index){}
	else if VG_STR_CLO(arg, "--taint-arg-name", fz_arg_taint_method_name){}
	else 
		return VG_(replacement_malloc_process_cmd_line_option)(arg);

	// tl_assert(clo_fnname);
	// tl_assert(clo_fnname[0]);
	return True;
}

static void fz_print_usage(void)
{
	VG_(printf)(
			"    --fnname=<filename>								file to taint\n"
			"    --sink-index=<Method_index>				the mthod index for terminate the symoblic execution\n"
			"    --sink-method=<Method_name>				the mthod name for terminate the symoblic execution\n"
			"    --taint-arg-index=<Method_index>		the arguments of the method for tainting\n"
			"    --taint-arg-name=<Method_name>	  	the arguments of the method for tainting\n"
			"    --taint-res-index=<Method_index>		the result of the method for tainting\n"
			"    --taint-res-name=<Method_name>	  	the arguments of the method for tainting\n"
			);
}

static void fz_print_debug_usage(void)
{
	VG_(printf)(
			"    (none)\n"
			);
}

static void fz_post_clo_init(void)
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

static 
INLINE Int mth_stack_size(ThreadId tid) {
	return mthStack[tid].size;
}

static
INLINE Int mth_push_stack(ThreadId tid, Addr lr, Addr sp, MthNode *mth, UChar taintTag) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if (ms->size > 10)
			return -1;
		if(ms->size < MAX_STACK_SIZE) {
			ms->lr[ms->size] = lr;
			ms->sp[ms->size] = sp;
			ms->mth[ms->size]  = (Addr)mth;
			ms->taintTag[ms->size] = taintTag;
			ms->size++;
		} else {
			MY_LOGI("Method stack overflow!!!\n");
			//mth_stack_print(tid);
			tl_assert(0);
		}
		return ms->size;
	}
	return -1;
}

static
INLINE Int mth_pop_stack1(ThreadId tid, Int num) {
	MthStack *ms = NULL;
	tl_assert(num > 0);
	if(num > 1) {
		VG_(printf)("Pop %d methods form call stack.\n", num);
	}
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > num) {
			ms->size -= num;
		} else {
			ms->size = 0;
		}
		//if(is_mth_stack_full)
		//	is_mth_stack_full = False;
		return ms->size;
	} 
	return -1;
}   

static 
INLINE Bool mth_top_stack1(ThreadId tid, Addr *addr,
		MthNode **mth,
		UChar *taintTag,
		Int index) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size >= index) {
			*addr = ms->lr[ms->size - index];
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
INLINE Int mth_pop_stack(ThreadId tid) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > 0) {
			ms->size--;
		}
		return ms->size;
	}
	return -1;
}

static 
INLINE Int mth_top_stack(ThreadId tid, Addr *addr, MthNode **mth, UChar *taintTag) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > 0) {
			if(addr)
				*addr = ms->lr[ms->size - 1];
			if(mth) {
				if(mth)
					*mth = (MthNode*)ms->mth[ms->size - 1];
				if(taintTag)
					*taintTag = ms->taintTag[ms->size - 1];
			}
			return ms->size;
		}
	}
	return 0;
}

static INLINE
UInt get_top_base_ret_addr(ThreadId tid, MthNode **mth, Addr *sp) {
	MthStack *ms = NULL;
	MthNode  *mn = NULL;
	UInt i = 0,	ret = 0;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		i = ms->size - 1;
		while(i > 0) {
			mn = (MthNode*)ms->mth[i];
			*mth = mn;
			*sp  = ms->sp[i];
			if(isBaseMethod(mn)) {
				return ms->lr[i];
			}
			return ms->lr[i];
			i--;
		}
		return ms->lr[1];
	}
	return -1;
}

static
INLINE MthNode* mth_lookup_stack(ThreadId tid, Addr a) {
	MthStack *ms = NULL;
	Addr addr;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		for(Int i = ms->size; i > 0; i--){
			addr = ms->lr[i - 1];
			if(a & ~0x1 == addr & ~0x1) {
				return (MthNode*)ms->mth[i - 1];
			}
		}
	}
	return NULL;
}

static
//void invoke_superblock(MthList *mList, VexGuestLayout *layout) {
void invoke_superblock(Addr irst_addr, MthList *mList) {
	ThreadId tid			= VG_(get_running_tid)();
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState	*arch_state = &tst->arch.vex;
	UWord r0, r1, r2, r3, r4, sp, lr, pc;
	Int tt = 0, i = 0;
	Addr last_lr;
	Bool isSource = False;
	UChar taintTag = 0;
#if defined(VGPV_arm_linux_android)
	r0 = arch_state->guest_R0;
	r1 = arch_state->guest_R1;
	r2 = arch_state->guest_R2;
	r3 = arch_state->guest_R3;
	r4 = arch_state->guest_R4;
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
	Int stackSize = mth_stack_size(tid) + 1;
	/* ART_INVOKE("%d 0x%08x %05d 0x%08x pc=0x%08x lr=0x%08x last_lr=0x%08x %s %s() %s stack =%d sp=0x%08x isStatic=%s\n",
		 tid, (Addr)mNode, mNode->mthKey, mNode->codeAddr, pc, lr, last_lr, mNode->clazz, mNode->method,
		 mNode->shorty, tt, sp, isStatic ? "True" : "False"); */
	/*if(mNode->mthKey == fz_arg_taint_method_index) {
		if((VG_(strcmp)(mNode->method, fz_arg_taint_method_name) == 0) && (isExploring == False)) {
		isSource = True;
		EXP_LOGI("Start fuzzing (Invoke)..\n");
		}
		}*/
#ifndef FZ_LOG_ALL_MTH
	if(isExploring == tid) {
#endif
		ART_INVOKE("%d %05d %s %s() %s flag=%d codeAddr=0x%08x codeSize=%d isStatic:%c(Debug: sp=0x%08x lr=0x%08x pc=0x%08x(0x%08x))\n",
				tid, mNode->mthKey, mNode->clazz, mNode->method, mNode->shorty, pAMth->access_flags_,
				mNode->codeAddr, mNode->codeSize, isStatic ? 'T' : 'F',
				sp, lr, pc, irst_addr);
		taintTag = check_mth_invoke(mNode, tid, isSource);
#ifndef FZ_LOG_ALL_MTH
	}
#endif
	tt = mth_push_stack(tid, lr, sp, mNode, taintTag);
}

static
//void return_superblock(Addr a, VexGuestLayout *layout) {
void return_superblock(Addr a) {
	ThreadId tid = VG_(get_running_tid)();
	ThreadState *tst = VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	Addr addr;
	MthNode *mNode = NULL, *rNode = NULL;
	UWord lsp, sp, pc, lr;
	UChar taintTag = 0;
#if defined(VGPV_arm_linux_android)
	sp = arch_state->guest_R13;
	lr = arch_state->guest_R14;
	pc = arch_state->guest_R15T;
#endif
	Bool isStatic = False;
	Int  index = 0;
	Int stackSize = 0; //mth_top_stack(tid, &addr, &mNode, &taintTag);
	//if(stackSize > 0)
	while(mth_top_stack1(tid, &addr, &mNode, &taintTag, ++index)) 
	{
		if(addr == a) {
			mth_pop_stack1(tid, index);
			index = 0;
			isStatic = (mNode->accessFlags & ACC_STATIC) ? True : False;
#ifndef FZ_LOG_ALL_MTH
			if(isExploring == tid) {
#endif
				stackSize = mth_stack_size(tid) + 1;
				ART_RETURN("%d %05d %s %s() %s isSource=%s (debug: pc=0x%08x lr= 0x%08x sp=0x%08x dst=0x%08x blocks=%llu(%llu))\n",
						tid, mNode->mthKey, mNode->clazz, mNode->method,
						mNode->shorty,
						mNode->type & TYPE_SOURCE ? "True" : "Flase",
						pc,
						lr,
						sp,
						a,
						blocks1,
						blocks2
						);
				check_mth_return(mNode, tid, taintTag);	
#ifndef FZ_LOG_ALL_MTH
			}
#endif
			if((mNode->mthKey == fz_res_taint_method_index) && (VG_(strcmp)(mNode->method, fz_res_taint_method_name) == 0)) {
				if(fz_num == 0) {
					fz_num++;
				}
				if((isExploring == 0)) {
					EXP_LOGI("Try to fuzzing tid=%d, addr=0x%08x\n", tid, addr);
					addr = get_top_base_ret_addr(tid, &rNode, &lsp);
					if(addr > 0) {
						VG_(memset)((Addr)&exeInfo, 0, sizeof(exeInfo));
						initPathExploring(exeInfo.pathIndex);
						UInt src_size = do_taint_source(mNode, tid, exeInfo.inputBuf);
						exeInfo.begAddr = a;
						exeInfo.mNode = mNode;
						exeInfo.retAddr = addr;
						test_ret = addr;
						exeInfo.stackTop = lsp;
						exeInfo.stackBottom = sp;
						exeInfo.inputSize = src_size;
						exeInfo.codeAddr = rNode->codeAddr;
						exeInfo.codeEnd  = rNode->codeAddr + rNode->codeSize - 1;
						exeInfo.tid = tid;
						isExploring = tid;
						exeInfo.mthStackSize = mth_stack_size(tid);
						saveState(&exeInfo);
						EXP_LOGI("Start fuzzing (return 0x%08x 0f %s.%s isE=%d blocks=%llu(%llu))\n", 
								addr, rNode->clazz, rNode->method, isExploring, blocks1, blocks2);
						blocks1 = 0;
						//blocks2 = 0;
					} else {
						MY_LOGW("Cannot get return address!!!!!\n");
					}
				}
			}
			/* Process Exception */
			if(mNode->mthKey == lang_exception_init_index) {
				stackSize = mth_stack_size(tid);
				while(stackSize > 0) {
					mth_top_stack(tid, &addr, &mNode, &taintTag);
					if (VG_(strstr)(mNode->clazz, "Exception;")) {
						VG_(printf)("[Exppop %3d]: %d %05d %s %s()\n", stackSize, tid, mNode->mthKey, mNode->clazz, mNode->method);
						stackSize = mth_pop_stack(tid);
						continue;
					}
					VG_(printf)("[Exppop %3d]: %d %s %s()\n", stackSize, tid, mNode->clazz, mNode->method);
					mth_pop_stack(tid);
					break;
				}
			}
		}
	}
}

	static 
VG_REGPARM(2) void helper_instrument_superblock( Addr irst_addr, Addr mListAddr)
{
	blocks2++;
	if (isExplore()) {
		blocks1++;
		for (UInt i = 0; i < MAX_TEMPORARIES; i++)
		{
			if (
#ifdef FZ_EXE_TAINT
					temporary_is_tainted(i)
#else
					True
#endif
				 ) {
#ifdef FZ_EXE_TAINT
				//ST_LOGI("t%d is tainted and cleared.\n", i);
#endif
				flip_temporary(i);
				free_temporary_dep(i);
			}
		}
		ThreadId tid = VG_(get_running_tid)();
		UInt  pc = VG_(get_IP)( tid );
		/*---- Path explorer ----*
		 * 1) Save register info
		 * 2) Save stack info
		 * 3) Save input info
		 */
		/*---- Path iterative execution ----
		 * 1) Recover register info
		 * 2) Recover stack info
		 * 3) Modify input
		 */
		if (exeInfo.begAddr == pc) { // The beginning of the path exploring routine
			EXP_LOGI("Take the %d iterative fuzzing (blocks=%llu(%llu)).\n", 
					exeInfo.pathIndex, blocks1, blocks2);
			if(exeInfo.pathIndex == 0) { // Start exploring
				//saveState(&exeInfo);
			} else { // Iterative exploring
				//recoverState(&exeInfo);
				//set_taint_source_value(exeInfo.mNode, tid, exeInfo.inputBuf, exeInfo.inputSize);
				//do_taint_source(exeInfo.mNode, tid);
			}
		}
	}
	/*---- for method tracing ----*/
	if(fz_method_trace && mListAddr > 0) {
		MthList *mList = (MthList *)mListAddr;
		invoke_superblock(irst_addr, mList);
	}
}

static INLINE
UInt hook_method(Addr d) {
	if(d == test_ret) {
		EXP_LOGI("Return from target subroutine to 0x%08x\n", d);
	}
	if(exeInfo.tid != VG_(get_running_tid)())
		return d;
	if(d == string_equals_entry_addr)
	{
		ThreadId tid = VG_(get_running_tid)();
		string_equals_return_addr = hook_string_equals(tid, d);
		return string_equals_return_addr;
	}

	if(!isExplore()) {
#ifndef FZ_ONLY_JAVA_METHOD
		if( d == log_println_native_return_addr ) {
			log_println_native_return_addr = 0;
			isExploring = exeInfo.tid;
			EXP_LOGI("Exit excluding method...(ret=0x%08x isE=%d)\n",
					log_println_native_return_addr, isExploring);
		}
#endif
		return d;
	}
#ifndef FZ_ONLY_JAVA_METHOD
	if(d == log_println_native_entry_addr){
		ThreadId tid			= VG_(get_running_tid)();
		ThreadState *tst	= VG_(get_ThreadState) ( tid );
		VexGuestArchState	*arch_state = &tst->arch.vex;
#if defined(VGPV_arm_linux_android)
		log_println_native_return_addr = arch_state->guest_R14;
#endif
		isExploring = 0;
		EXP_LOGI("Enter excluding method(ret=0x%08x isE=%d)...\n", 
				log_println_native_return_addr, isExploring);
	}
#endif //not FZ_ONLY_JAVA_METHOD
	return d;
}

	static INLINE
UInt init_stack_next_explore(Addr d) 
{
	Addr dst = d;
	finiPathExploring();
	EXP_LOGI("Finish the %d iterative fuzzing (blocks=%llu(%llu)).\n", 
			exeInfo.pathIndex, blocks1, blocks2);
	VG_(memset)((Addr)exeInfo.inputBuf, 0, MAX_INPUT_SIZE);
	exeInfo.pathIndex++;
	if(getInput(exeInfo.inputBuf, MAX_INPUT_SIZE, exeInfo.pathIndex)) {
		ThreadId tid			= VG_(get_running_tid)();
		dst = exeInfo.begAddr;
		EXP_LOGI("Return to 0x%08x for %d iterative execution (orig: 0x%08x)\n", dst, exeInfo.pathIndex, d);
		recoverState(&exeInfo);
		set_taint_source_value(exeInfo.mNode, tid, exeInfo.inputBuf, exeInfo.inputSize);
		do_taint_source(exeInfo.mNode, tid, exeInfo.inputBuf);
		initPathExploring(exeInfo.pathIndex);
		while(mth_stack_size(tid) > exeInfo.mthStackSize) {
			mth_pop_stack(tid);
		}
		return dst;
	}
	isExploring = 0;
	EXP_LOGI("Return to 0x%08x(orig: 0x%08x, retAddr: 0x%08x)\n", dst, d, exeInfo.retAddr);
	EXP_LOGI("Complete fuzzing (%d paths are explored blocks=%llu(%llu) isE=%d).\n", 
			exeInfo.pathIndex, blocks1, blocks2, isExploring);
	VG_(memset)((Addr)&exeInfo, 0, sizeof(exeInfo));
	return dst;
}

	static 
VG_REGPARM(1) UInt helper_instrument_tmp_next(Addr d)
{
	Addr dst = d;
	dst = hook_method(d);
	if(dst != d)
		return dst;
	if(isExplore()) {
		if( (dst == exeInfo.retAddr) || (dst == runtime_get_runtime_addr)) {
#if 0
			|| (dst == lang_exception_init_addr) 
				|| (dst == native_poll_once_addr) || (dst == runtime_get_runtime_addr) ) 
#endif
			dst = init_stack_next_explore(d);
			if(dst != d)
				return dst;
		}
	}
	if(fz_method_trace) {
		return_superblock(dst);
	}
	//ST_LOGI("return to 0x%08x\n", dst);
	return dst;
}
	static 
VG_REGPARM(1) UInt helper_instrument_const_next(Addr d)
{
	Addr dst = d;
	dst = hook_method(d);
	if(dst != d)
		return dst;
#if 0
	if(isExplore()) {
		if( (dst == lang_exception_init_addr) || (dst == native_poll_once_addr) ) {
			dst = init_stack_next_explore(d);
		}
	}
#endif
	return dst;
}

	static 
IRSB* fz_instrument ( VgCallbackClosure* closure,
		IRSB* sb_in,
		const VexGuestLayout* layout,
		const VexGuestExtents* vge,
		const VexArchInfo* archinfo_host,
		IRType gWordTy, IRType hWordTy )
{

	if((fz_method_trace == False))
		return sb_in;
	Int i;
	IRSB* sb_out;
	IRDirty* di;
	MthList *mList = NULL;
	MthNode *mNode = NULL;
	Bool		isEntry = False;
	Bool		is_debug = False;
	Bool    is_java = isJavaCode(vge->base[0]);
#ifdef FZ_DEBUG
	if(isExploring) {
		if( isBaseAddr(vge->base[0]) > 0 ) {
			VG_(printf)("Input 0x%08x: ", vge->base[0]);
			ppIRSB(sb_in);
		}
	}
	if(((vge->base[0] >> 16) == 0x4a7) ||
			((vge->base[0] >> 16) == 0x6f1) ||
			((vge->base[0] >> 16) == 0x7362) ||
			((vge->base[0] >> 16) == 0x1efb)) {
		VG_(printf)("Input (0x%08x): ", vge->base[0]);
		ppIRSB(sb_in);
		is_debug = True;
	}
#endif

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
	if(fz_method_trace) {
		if (is_framework_bb(vge->base[0])) {
			mList = query_method_list(vge->base[0]);
		}
	}

	/*----------------- End -----------------*/

	di = unsafeIRDirty_0_N(2,
			"helper_instrument_superblock",
			VG_(fnptr_to_fnentry)(helper_instrument_superblock),
			mkIRExprVec_2(mkIRExpr_HWord((Addr)vge->base[0]),
				mkIRExpr_HWord((Addr)mList))
			);
	addStmtToIRSB(sb_out, IRStmt_Dirty(di));

	for (/*use current i*/; i < sb_in->stmts_used; i++)
	{
		IRStmt* st = sb_in->stmts[i];
		if (!st)
			continue;
#ifdef FZ_ONLY_JAVA_METHOD
		if(is_java == False) {
			addStmtToIRSB(sb_out, st);
			continue;
		}
#endif

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
				instrument_WrTmp(st, sb_out);
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_Put:
				instrument_Put(st, sb_out);
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_PutI:
				instrument_PutI(st, sb_out);
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_Store:
				instrument_Store(st, sb_out);
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_StoreG:
				addStmtToIRSB(sb_out, st);
				// if (<guard>) ST<end>(<addr>) = <data>
				instrument_StoreG(st, sb_out);
				break;
			case Ist_LoadG: 
				// t<tmp> = if (<guard>) <cvt>(LD<end>(<addr>)) else <alt>
				instrument_LoadG(st, sb_out);
				addStmtToIRSB(sb_out, st);
				break;
			case Ist_CAS:
				addStmtToIRSB(sb_out, st); // dirty helpers use temporaries (oldHi, oldLo) defined in the instruction
				instrument_CAS(st, sb_out);
				break;
			case Ist_LLSC:
				addStmtToIRSB(sb_out, st);
				instrument_LLSC(st, sb_out);
				break;
			case Ist_Exit:
				instrument_Exit(st, sb_out);
				//addStmtToIRSB(sb_out, st);
				break;
			default:
				MY_LOGI("fz_main.c: fz_instrument(), Unhandled IRStmt.\n");
				ppIRStmt(st);
				VG_(printf)("\n");
				tl_assert(0);
		}
	}

	//if((sb_in->jumpkind == Ijk_Ret) || (sb_in->jumpkind == Ijk_Call)) 
	if(True) {
		IRExpr *next = sb_in->next;
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
	if(isExploring) {
		if( isBaseAddr(vge->base[0]) > 0 ) {
			VG_(printf)("Output 0x%08x: ", vge->base[0]);
			ppIRSB(sb_out);
		}
	}
	ppIRSB(sb_out);
	if(isExploring || is_debug) {
		VG_(printf)("Debug output (0x%08x, %d) ", vge->base[0], vge->len[0]);
		ppIRSB(sb_out);
	}
#endif
	return sb_out;
}

static void fz_fini(Int exitcode)
{
	destroy_shadow_memory();
	isExploring = 0;
	EXP_LOGI("Executed blocks: %llu %llu\n", blocks1, blocks2);
}

static void fz_pre_clo_init(void)
{
	VG_(details_name)            ("Fuzzer");
	VG_(details_version)         ("0.1.1");
	VG_(details_description)     ("A concolic fuzzer for Android apps");
	VG_(details_copyright_author)("Copyright (C) 2016, Rewhy.");
	VG_(details_bug_reports_to)  (VG_BUGS_TO);

	VG_(details_avg_translation_sizeB) ( 275 );

	VG_(needs_libc_freeres)				();
	VG_(needs_malloc_replacement)	(
			fz_malloc,
			fz_builtin_new,
			fz_builtin_vec_new,
			fz_memalign,
			fz_calloc,
			fz_free,
			fz_builtin_delete,
			fz_builtin_vec_delete,
			fz_realloc,
			fz_malloc_usable_size,
			0 );

	fz_malloc_list = VG_(HT_construct)( "fz_malloc_list" );

	VG_(basic_tool_funcs)        (fz_post_clo_init,
			fz_instrument,
			fz_fini);

	VG_(needs_command_line_options)(fz_process_cmd_line_option,
			fz_print_usage,
			fz_print_debug_usage);

	VG_(needs_syscall_wrapper) (pre_syscall, post_syscall);
	VG_(needs_client_requests) (fz_handle_client_requests);
	/* No needs, no core events to track */
}
VG_DETERMINE_INTERFACE_VERSION(fz_pre_clo_init)
