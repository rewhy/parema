#ifndef _DT_TAINT_H
#define _DT_TAINT_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

#define DT_(str)		VGAPPEND(vgDatatrace_,str)

//#include "dt_structs.h"
extern Bool trace_obj_taint;
extern Bool trace_ins_taint;
extern Bool trace_art_method;

#define DT_WHITE_LIST		1
//Stack of strings---------------------------------------
#define MAX_LEN 256
#define STACK_SIZE 102400

struct myStringArray{
   char m[STACK_SIZE][MAX_LEN];
   int size;
};

struct FunList {
	char name[MAX_LEN];
	struct FunList *next;
};
struct LibList {
	char name[MAX_LEN];
	struct Funlist *flist;
	struct LibList *next;
};

struct FilterList {
	Addr			text_avma;
	Addr      text_end;
	SizeT			text_size;
	struct FilterList* next;
};

#if 1
Bool addFilterFun(const HChar* soname, const HChar* fnname);
//Int myStringArray_getIndex( struct myStringArray *a, const HChar* string );
//Int myStringArray_push( struct myStringArray *a, const HChar* string );
//Int myStringArray_rmIndex( struct myStringArray *a, const Int index );
#endif

/*------------------------------------------------------------*/
/*--- Fast-case knobs                                      ---*/
/*------------------------------------------------------------*/
// Comment these out to disable the fast cases (don't just set them to zero).
#define PERF_FAST_LOADV    1
#define PERF_FAST_STOREV   1
#define PERF_FAST_SARP     1

/* --------------- Basic configuration --------------- */ 

/* N_PRIMARY_MAP must be a power of 2 */
#if VG_WORDSIZE ==				4
#define N_PRIMARY_BITS		16
#else
#define N_PRIMARY_BITS		19
#endif
/* 0x10000 */
#define N_PRIMARY_MAP			( ((UWord)1) << N_PRIMARY_BITS)
/* 0x10000 * 0xffff = 0xffff0000 */
#define MAX_PRIMARY_ADDRESS (Addr)((((Addr)0x10000) * N_PRIMARY_MAP)-1)

/* Size for each socend map, because memchek/taintgrind represents
 * each byte (8 bits) under 32-bit platform with 2 VA_bits, so each 
 * SecMap can represent 0x10000 bytes space. 
 * */
#define SM_CHUNKS					0x4000
#define SM_OFF(aaa)				(((aaa) & 0xffff) >> 2)
#define SM_OFF_16(aaa)		(((aaa) & 0xffff) >> 3)

/*----------------------------------------------------------*/
/*---  V and A bits (Victor & Albert ?)                  ---*/
/*----------------------------------------------------------*/

#define	SM_SIZE							0x10000
#define SM_MASK							(SM_SIZE - 1)

#define V_BIT_UNTAINTED			0
#define V_BIT_TAINTED				1

#define V_BITS8_UNTAINTED		0
#define V_BITS8_TAINTED			0xFF

#define V_BITS16_UNTAINTED	0
#define V_BITS16_TAINTED		0xFFFF

#define V_BITS32_UNTAINTED	0
#define V_BITS32_TAINTED		0xFFFFFFFF

#define V_BITS64_UNTAINTED  0
#define V_BITS64_TAINTED		0xFFFFFFFFFFFFFFFFUL
// Taintgrind: UNDEFINED -> TAINTED, DEFINED -> UNTAINTED,
//             PARTDEFINED -> PARTUNTAINTED
// These represent eight bits of memory.
#define VA_BITS2_NOACCESS      0x0      // 00b
#define VA_BITS2_TAINTED       0x1      // 01b
#define VA_BITS2_UNTAINTED     0x2      // 10b
#define VA_BITS2_PARTUNTAINTED 0x3      // 11b

// These represent 16 bits of memory.
#define VA_BITS4_NOACCESS     0x0      // 00_00b
#define VA_BITS4_TAINTED      0x5      // 01_01b
#define VA_BITS4_UNTAINTED    0xa      // 10_10b

// These represent 32 bits of memory.
#define VA_BITS8_NOACCESS     0x00     // 00_00_00_00b
#define VA_BITS8_TAINTED      0x55     // 01_01_01_01b
#define VA_BITS8_UNTAINTED    0xaa     // 10_10_10_10b

// These represent 64 bits of memory.
#define VA_BITS16_NOACCESS    0x0000   // 00_00_00_00b x 2
#define VA_BITS16_TAINTED     0x5555   // 01_01_01_01b x 2
#define VA_BITS16_UNTAINTED   0xaaaa   // 10_10_10_10b x 2

#define INLINE						inline __attribute__((always_inline))

static INLINE Addr start_of_this_sm ( Addr a ) {
  return (a & (~SM_MASK));
}
static INLINE Bool is_start_of_sm ( Addr a ) {
  return (start_of_this_sm(a) == a);
}

typedef struct {
  UChar vabits8[SM_CHUNKS];
} SecMap;

/* SMT2 functions */
#define TI_MAX 2100 
#define RI_MAX 740 
// Tmp variable indices; the MSB indicates whether it's tainted (1) or not (0)
extern UInt  ti[TI_MAX];
// Tmp variable values
extern ULong tv[TI_MAX];
// Reg variable indices
extern UInt  ri[RI_MAX];
// Tmp variable Types/Widths
extern UInt  tt[TI_MAX];

extern struct   myStringArray lvar_s;
extern int      lvar_i[STACK_SIZE];

extern Int	istty;

/*--- instrumentation (dt_taint.c) ---*/
/* Functions/vars defined in dt_taint.c */ 
UChar get_vabits2( Addr a ); // Taintgrind: needed by DT_(instrument)
void DT_(make_reg_tainted) (Int r, ThreadId tid);
void DT_(make_reg_untainted) (Int r, ThreadId tid);
Bool DT_(check_reg_tainted) (Int r, ThreadId tid);
void DT_(make_mem_noaccess)( Addr a, SizeT len );
void DT_(make_mem_tainted)( Addr a, SizeT len );
Bool DT_(check_mem_tainted)( Addr a, SizeT len );
void DT_(make_mem_tainted_named)( Addr a, SizeT len, const HChar *varname );
void DT_(make_mem_untainted)( Addr a, SizeT len );
void DT_(clear_mem_tainted) ();
void DT_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );

VG_REGPARM(3) void DT_(h32_exit_t)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_exit_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_next_t)   ( IRExpr *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_next_c)   ( IRExpr *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_store_tt) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_store_tc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_store_ct) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_load_t)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_load_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_get)      ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_geti)     ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_put_t)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_put_c)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_puti)     ( UInt, UInt, UInt, UInt );
VG_REGPARM(3) void DT_(h32_wrtmp_c)  ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_unop_t)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_unop_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_binop_tc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_binop_ct) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_binop_tt) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_binop_cc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_triop)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_qop)      ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_rdtmp)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_ite_tc)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_ite_ct)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_ite_tt)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_ite_cc)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_ccall)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_x86g_calculate_condition)    ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void DT_(h32_none)     ( HChar *, UInt, UInt );

VG_REGPARM(3) void DT_(h64_exit_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_exit_c)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_next_t)   ( IRExpr *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_next_c)   ( IRExpr *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_store_tt) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_store_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_store_ct) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_load_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_load_c)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_get)      ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_geti)     ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_put_t)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_put_c)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_puti)     ( ULong, ULong, ULong, ULong );
VG_REGPARM(3) void DT_(h64_wrtmp_c)  ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_unop_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_unop_c)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_binop_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_binop_ct) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_binop_tt) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_binop_cc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_triop)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_qop)      ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_rdtmp)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_ite_tc)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_ite_ct)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_ite_tt)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_ite_cc)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_ccall)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_amd64g_calculate_condition)    ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void DT_(h64_none)     ( HChar *, ULong, ULong );

#if 0
/* Strings used by dt_translate, printed by dt_main */
extern const char *IRType_string[];
extern const char *IREndness_string[];
extern const char *IRConst_string[];
extern const char *IRExpr_string[];
extern const char *IRStmt_string[];
extern const char *IRJumpKind_string[];
#endif

/* Functions defined in tnt_translate, used by tnt_main */
extern Int extract_IRConst( IRConst* con );
extern ULong extract_IRConst64( IRConst* con );

/* V-bits load/store helpers */
VG_REGPARM(1) void DT_(helperc_STOREV64be) ( Addr, ULong );
VG_REGPARM(1) void DT_(helperc_STOREV64le) ( Addr, ULong );
VG_REGPARM(2) void DT_(helperc_STOREV32be) ( Addr, UWord );
VG_REGPARM(2) void DT_(helperc_STOREV32le) ( Addr, UWord );
VG_REGPARM(2) void DT_(helperc_STOREV16be) ( Addr, UWord );
VG_REGPARM(2) void DT_(helperc_STOREV16le) ( Addr, UWord );
VG_REGPARM(2) void DT_(helperc_STOREV8)    ( Addr, UWord );

VG_REGPARM(2) void  DT_(helperc_LOADV256be) ( /*OUT*/V256*, Addr );
VG_REGPARM(2) void  DT_(helperc_LOADV256le) ( /*OUT*/V256*, Addr );
VG_REGPARM(2) void  DT_(helperc_LOADV128be) ( /*OUT*/V128*, Addr );
VG_REGPARM(2) void  DT_(helperc_LOADV128le) ( /*OUT*/V128*, Addr );
VG_REGPARM(1) ULong DT_(helperc_LOADV64be)  ( Addr );
VG_REGPARM(1) ULong DT_(helperc_LOADV64le)  ( Addr );
VG_REGPARM(1) UWord DT_(helperc_LOADV32be)  ( Addr );
VG_REGPARM(1) UWord DT_(helperc_LOADV32le)  ( Addr );
VG_REGPARM(1) UWord DT_(helperc_LOADV16be)  ( Addr );
VG_REGPARM(1) UWord DT_(helperc_LOADV16le)  ( Addr );
VG_REGPARM(1) UWord DT_(helperc_LOADV8)     ( Addr );

void DT_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len, Addr nia );

/* Taint args */
#define MAX_PATH 256
extern HChar  DT_(clo_file_filter)[MAX_PATH];
extern Int    DT_(clo_taint_start);
extern Int    DT_(clo_taint_len);
extern Bool   DT_(clo_taint_all);
extern Int    DT_(clo_after_kbb);
extern Int    DT_(clo_before_kbb);
extern Bool   DT_(clo_tainted_ins_only);
extern Bool   DT_(clo_critical_ins_only);
extern Int    DT_(do_print);
extern Bool   DT_(clo_smt2);
//extern Char* DT_(clo_allowed_syscalls);
//extern Bool  DT_(read_syscalls_file);
extern Bool		DT_(clo_taint_begin);

#define _ti(ltmp) ti[ltmp] & 0x7fffffff
#define is_tainted(ltmp) (ti[ltmp] >> 31)

extern void DT_(smt2_preamble) (void);
extern void DT_(smt2_exit)     ( IRStmt * );
extern void DT_(smt2_load_c_32)   ( IRStmt *, UInt, UInt );
extern void DT_(smt2_load_t_32)   ( IRStmt *, UInt, UInt );
extern void DT_(smt2_load_c_64)   ( IRStmt *, ULong, ULong );
extern void DT_(smt2_load_t_64)   ( IRStmt *, ULong, ULong );
extern void DT_(smt2_store_ct) ( IRStmt * );
extern void DT_(smt2_store_tc) ( IRStmt * );
extern void DT_(smt2_store_tt) ( IRStmt * );
extern void DT_(smt2_unop_t)   ( IRStmt * );
extern void DT_(smt2_binop_tc) ( IRStmt * );
extern void DT_(smt2_binop_ct) ( IRStmt * );
extern void DT_(smt2_binop_tt) ( IRStmt * );
extern void DT_(smt2_rdtmp)    ( IRStmt * );
extern void DT_(smt2_get)      ( IRStmt * );
extern void DT_(smt2_put_t_32) ( IRStmt * );
extern void DT_(smt2_put_t_64) ( IRStmt * );
extern void DT_(smt2_x86g_calculate_condition)    ( IRStmt * );
extern void DT_(smt2_amd64g_calculate_condition)  ( IRStmt * );
extern void DT_(smt2_ite_tt)   ( IRStmt * );

void init_shadow_memory( void );
void init_soapp_data();
void DT_(copy_address_range_state) (Addr src, Addr dst, SizeT len);
/* dt_translate.c, for filter instrumentation BB */
void initFilterlist();
void releaseFilterlist();
#endif // _DT_TAINT_H
