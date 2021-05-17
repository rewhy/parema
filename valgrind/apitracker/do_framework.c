// dt_framework.c
//
#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_guest.h"
#include "pub_core_threadstate.h"

//#include "dt_debug.h"
//#include "dt_taint.h"
#include "do_oatdexparse.h"
#include "do_oatplus.h"
#include "do_framework.h"
#include "taint_analysis.h"


#define FUNC_STRING_EQUALS_INDEX	13334
static UChar taint_index = 0;

#define UNKNOWN_CLASS_NAME		"???"
#define TMP_STR_SIZE		1024

#define	T	"\e[31mY"
#define	F	"N"

HChar tmp_string_str[TMP_STR_SIZE];
HChar tmp_class_name[TMP_STR_SIZE];

extern UInt do_method_index;
extern UInt do_arg_taint_method_index;
extern HChar *do_arg_taint_method_name;
//extern UInt do_res_taint_method_index;
//extern HChar *do_res_taint_method_index;

static Bool check_reg_tainted(UInt reg, UInt tid) {
	if(register_is_tainted(reg * 4 + 8) == 1)
		return True;
	return False;
}
static Bool check_mem_tainted(Addr addr, UInt bytes) {
	if(memory_is_tainted(addr, bytes * 8) == 1)
		return True;
	return False;
}

int enc_unicode_to_utf8_one(ULong unic, UChar *pOutput, Int outSize)  
{  
	tl_assert(pOutput != NULL);  
	//tl_assert(outSize >= 6);  

	if ( unic <= 0x0000007F )  
	{  
		// * U-00000000 - U-0000007F:  0xxxxxxx  
		*pOutput     = (unic & 0x7F);  
		return 1;  
	}  
	else if ( unic >= 0x00000080 && unic <= 0x000007FF )  
	{  
		// * U-00000080 - U-000007FF:  110xxxxx 10xxxxxx  
		*(pOutput+1) = (unic & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 6) & 0x1F) | 0xC0;  
		return 2;  
	}  
	else if ( unic >= 0x00000800 && unic <= 0x0000FFFF )  
	{  
		// * U-00000800 - U-0000FFFF:  1110xxxx 10xxxxxx 10xxxxxx  
		*(pOutput+2) = (unic & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >>  6) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 12) & 0x0F) | 0xE0;  
		return 3;  
	}  
	else if ( unic >= 0x00010000 && unic <= 0x001FFFFF )  
	{  
		// * U-00010000 - U-001FFFFF:  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(pOutput+3) = (unic & 0x3F) | 0x80;  
		*(pOutput+2) = ((unic >>  6) & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >> 12) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 18) & 0x07) | 0xF0;  
		return 4;  
	}  
	else if ( unic >= 0x00200000 && unic <= 0x03FFFFFF )  
	{  
		// * U-00200000 - U-03FFFFFF:  111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(pOutput+4) = (unic & 0x3F) | 0x80;  
		*(pOutput+3) = ((unic >>  6) & 0x3F) | 0x80;  
		*(pOutput+2) = ((unic >> 12) & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >> 18) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 24) & 0x03) | 0xF8;  
		return 5;  
	}  
	else if ( unic >= 0x04000000 && unic <= 0x7FFFFFFF )  
	{  
		// * U-04000000 - U-7FFFFFFF:  1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(pOutput+5) = (unic & 0x3F) | 0x80;  
		*(pOutput+4) = ((unic >>  6) & 0x3F) | 0x80;  
		*(pOutput+3) = ((unic >> 12) & 0x3F) | 0x80;  
		*(pOutput+2) = ((unic >> 18) & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >> 24) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 30) & 0x01) | 0xFC;  
		return 6;  
	}  

	return 0;  
}

HChar *get_classobject_name(ClassMirror *clazz) {
	if(!clazz) {
		VG_(printf)("Object@0x%08x NULL.\n", (Addr)clazz);
		return UNKNOWN_CLASS_NAME;
	}
#if DBG_PARAMETER_PARSE
	VG_(printf)("Object@0x%08x type index: %d ClassDef index: %d\n",
			(Addr)clazz, clazz->dex_type_idx_, clazz->dex_class_def_idx_);
#endif
	StringMirror *strMi = clazz->name_;
	if(!strMi) {
		return UNKNOWN_CLASS_NAME;
	}
	Int size = 0, i = 0;
	UShort *value = NULL;
#if DBG_PARAMETER_PARSE
	VG_(printf)("Object@0x%08x flags: 0x%08x len=%d\n", (Addr)clazz, clazz->access_flags_ >> 16, strMi->count_);
#endif
	if(strMi->count_ > 0) {
		size = TMP_STR_SIZE-1 < strMi->count_ ? TMP_STR_SIZE-1 : strMi->count_;
		value = strMi->value_;
		for(i=0; i < size; i++) {
			tmp_class_name[i] = (UChar)value[i];
		}
		tmp_class_name[i] = '\0';
		return tmp_class_name;
	}
	return UNKNOWN_CLASS_NAME;
}
	static
HChar* get_stringobj_str(Addr addr)
{
	StringMirror *strObj = (StringMirror *)addr;
	Int size = 0, i = 0, j = 0;
	UShort *value = NULL;
	ClassMirror *clazz = strObj->object_.klass_;
	HChar *t = get_classobject_name(clazz);
	if(strObj && strObj->count_ > 0) {
		size = TMP_STR_SIZE-1 < strObj->count_ ? TMP_STR_SIZE-1 : strObj->count_;
		value = strObj->value_;
		//TNT_LOGI("%s@%08x content@0x%08x\n", t, (Addr)clazz, (Addr)value);
		for(i=0; i < size; i++) {
			//tmp_string_str[i] = (UChar)value[i];
			j += enc_unicode_to_utf8_one(value[i], tmp_string_str+j, TMP_STR_SIZE-j);
		}
		tmp_string_str[i] = '\0';
		return tmp_string_str;
	}
	return NULL;
}
UShort* get_string_content(Addr addr)
{
	StringMirror *strObj = (StringMirror *)addr;
	if(strObj && strObj->count_ > 0) {
		return strObj->value_;
	}
	return NULL;
}
/*
 * From: art/compiler/dex/quick/arm/arm_lir.h
 * Runtime register usage conventions.
 *
 * r0-r3: Argument registers in both Dalvik and C/C++ conventions.
 *        However, for Dalvik->Dalvik calls we'll pass the target's Method*
 *        pointer in r0 as a hidden arg0. Otherwise used as codegen scratch
 *        registers.
 * r0-r1: As in C/C++ r0 is 32-bit return register and r0/r1 is 64-bit
 * r4   : If ARM_R4_SUSPEND_FLAG is set then reserved as a suspend check/debugger
 *        assist flag, otherwise a callee save promotion target.
 * r5   : Callee save (promotion target)
 * r6   : Callee save (promotion target)
 * r7   : Callee save (promotion target)
 * r8   : Callee save (promotion target)
 * r9   : (rARM_SELF) is reserved (pointer to thread-local storage)
 * r10  : Callee save (promotion target)
 * r11  : Callee save (promotion target)
 * r12  : Scratch, may be trashed by linkage stubs
 * r13  : (sp) is reserved
 * r14  : (lr) is reserved
 * r15  : (pc) is reserved
 *
 * 5 core temps that codegen can use (r0, r1, r2, r3, r12)
 * 7 core registers that can be used for promotion
 *
 * Floating pointer registers
 * s0-s31
 * d0-d15, where d0={s0,s1}, d1={s2,s3}, ... , d15={s30,s31}
 *
 * s16-s31 (d8-d15) preserved across C calls
 * s0-s15 (d0-d7) trashed across C calls
 *
 * s0-s15/d0-d7 used as codegen temp/scratch
 * s16-s31/d8-d31 can be used for promotion.
 *
 * Calling convention
 *     o On a call to a Dalvik method, pass target's Method* in r0
 *     o r1-r3 will be used for up to the first 3 words of arguments
 *     o Arguments past the first 3 words will be placed in appropriate
 *       out slots by the caller.
 *     o If a 64-bit argument would span the register/memory argument
 *       boundary, it will instead be fully passed in the frame.
 *     o Maintain a 16-byte stack alignment
 *
 *  Stack frame diagram (stack grows down, higher addresses at top):
 *
 * +------------------------+
 * | IN[ins-1]              |  {Note: resides in caller's frame}
 * |       .                |
 * | IN[0]                  |
 * | caller's Method*       |
 * +========================+  {Note: start of callee's frame}
 * | spill region           |  {variable sized - will include lr if non-leaf.}
 * +------------------------+
 * | ...filler word...      |  {Note: used as 2nd word of V[locals-1] if long]
 * +------------------------+
 * | V[locals-1]            |
 * | V[locals-2]            |
 * |      .                 |
 * |      .                 |
 * | V[1]                   |
 * | V[0]                   |
 * +------------------------+
 * |  0 to 3 words padding  |
 * +------------------------+
 * | OUT[outs-1]            |
 * | OUT[outs-2]            |
 * |       .                |
 * | OUT[0]                 |
 * | cur_method*            | <<== sp w/ 16-byte alignment
* +========================+
*/

/*--------------------- For taint source ----------------------------*/
	static
Bool check_string_tainted(StringMirror *strObj)
{
	UShort *value = NULL;
	UInt	 len = 0, i = 0;
	Bool	 isTaint = False;
	if(strObj && strObj->count_ > 0){
		len = strObj->count_ * sizeof(Short) * 8;
		isTaint = check_mem_tainted((Addr)strObj->value_, len);
		isTaint = memory_is_tainted((Addr)strObj->value_, len);
	}
	return isTaint;
}

	static
Int make_string_tainted(StringMirror *strObj) 
{
	UShort *value = NULL;
	UInt	 len = 0, i = 0;
	char dep[DEP_MAX_LEN] = {0};
	if(strObj && strObj->count_ > 0){
		value = strObj->value_;
		VG_(printf)("taint: 0x%08x %d %s\n", strObj->value_, strObj->count_, (HChar*)strObj->value_);
		for(i = 0; i < /*strObj->count_*/2; i++) {
			if (!memory_is_tainted((UInt)&value[i], 16))
			{
				flip_memory((UInt)&value[i], 16, 1);
			}
			VG_(snprintf)(dep, DEP_MAX_LEN, "INPUT:16(%lu)", i);
			update_memory_dep((UInt)&value[i], dep, 16);
		}
		VG_(printf)("\n");
		//len = sizeof(StringMirror) + strObj->count_ * sizeof(UShort);
		len = strObj->count_ * sizeof(Short);
		//DT_(make_mem_tainted)((Addr)strObj->value_, len);
		return strObj->count_;
	}	else {
		VG_(printf)("NULL\n");
	}
	return 0;
}

	static
Int make_string_untainted(StringMirror *strObj) 
{
	UShort *value = NULL;
	UInt	 len = 0, i = 0;
	if(strObj && strObj->count_ > 0){
#ifdef	DBG_FRAMEWORK
		value = strObj->value_;
		FRM_LOGI("untaint: 0x%08x %d\n", r0, strObj->count_, (HChar*)strObj->value_);
		for(i = 0; i < strObj->count_; i++) {
			FRM_LOGI(" 0x%04x(%c)", value[i], (HChar)value[i]);
		}
		FRM_LOGI("\n");
#endif
		len = sizeof(StringMirror) + strObj->count_ * sizeof(UShort);
		//DT_(make_mem_untainted)((Addr)strObj, len);
		return strObj->count_;
	}	else {
		VG_(printf)("NULL\n");
	}
	return 0;
}
/*
 * L:		jobject
 * V:		void
 * Z:		bool
 * B:		Byte
 * C:		Char
 * D:		Double
 * F:		Float
 * I:		Int
 * J:		Long
 * S:		Shorty
 */

static 
UInt process_array_arg(HChar *clazz, Addr addr) {
	tl_assert(clazz[0] == '[');
	ArrayMirror *array = (ArrayMirror *)addr;
	UInt j = 0, size = 0;
	HChar *cv = NULL;
	Int		*iv = NULL;
	Long	*jv = NULL;
	Int len = array->length_ > 2 ? 2 : array->length_;
	switch(clazz[1]) {
		case 'B':
		case 'C':
			cv = (HChar*)array->first_element_;
			size = 1;
			VG_(printf)("\t%s: ", clazz);
			for( j = 0; j < len; j++)
				VG_(printf)("%02x ", cv[j]);
			VG_(printf)("\n");
			break;
		case 'Z':
			size = 1;
			break;
		case 'S':
			size = 2;
			break;
		case 'I':
			iv = (Int*)array->first_element_;
			size = 4;
			VG_(printf)("\t%s: ", clazz);
			for( j = 0; j < len; j++)
				VG_(printf)("%d ", iv[j]);
			VG_(printf)("\n");
			break;
		case 'J':
			jv = (Long*)array->first_element_;
			size = 8;
			VG_(printf)("\t%s: ", clazz);
			for( j = 0; j < len; j++)
				VG_(printf)("%lld ", jv[j]);
			VG_(printf)("\n");
			break;
		case 'L':
			size = 4;
			break;
		case 'F':
			size = 4;
			break;
		case 'D':
			size = 8;
			break;
		case 'V':
		default:
			break;
	}
	return array->length_ * size;
}
UInt get_declaring_class_flags(Addr c)
{
	if(c==NULL)
		return 0;
	ClassMirror *pclazz = (ClassMirror*)c;
	return pclazz->access_flags_;

}
void do_taint_source(MthNode *mNode, ThreadId tid)
{
	if(mNode->shorty == NULL) {
		TNT_LOGI("%s shorty is NULL!!!!\n", mNode->method);
		return;
	}
	if(mNode->shorty[0] == 'V') {
		TNT_LOGI("%s has has no return value!!!!\n", mNode->method);
		return;
	}
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	UWord r0, r1; Int tt;
	UWord *r;
	ClassMirror *clazz = NULL;
	UInt	objSize = 0, clazzSize = 0;
	Addr clazz_addr1, clazz_addr2;
	HChar		*tmp = NULL;
	HChar		*content = NULL;
	Bool		bres;
	HChar		cres;
	Short		sres;
	Int			ires;
	Long		jres;
	Float		fres;
	Double	dres;
	HChar dep[32];
# if defined(VGPV_arm_linux_android)
	r  = (UWord*)&arch_state->guest_R0;
	r0 = arch_state->guest_R0;
	r1 = arch_state->guest_R1;
#endif 
	switch(mNode->shorty[0]) {
		case 'L':
			clazz = (ClassMirror *)r[0];
			clazz_addr1 = r[0];
			if((Addr)clazz) {
				clazz = clazz->object_.klass_;
			} else {
				clazz = NULL;
			}
			if(clazz) {
				tmp =  get_classobject_name(clazz);
				clazzSize = clazz->class_size_;
				objSize = clazz->object_size_;
			} else {
				tmp = "????";
			}
			clazz_addr2 = (Addr) clazz;
			//DT_(make_reg_tainted)(0, tid);
			if(tmp[0] == '[') {
				process_array_arg(tmp, (Addr)r[0]);
			} else if(VG_(strcmp)("java.lang.String", tmp) == 0) {
				content = get_stringobj_str((StringMirror *)r[0]);
				make_string_tainted((StringMirror*)r[0]);
			}
			TNT_LOGI("%s return \'class\' %s@0x%08x(0x%08x) %d(%d)tainted", 
					mNode->method, tmp, clazz_addr1, clazz_addr2, clazzSize, objSize);
			if(content)
				VG_(printf)(" (c:%s).\n", content);
			else 
				VG_(printf)(" (c:NULL).\n", content);
			break;
		case 'Z':	// Bool
			bres = (Bool)r[0];
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			TNT_LOGI("%s return \'Bool\' value %s tainted.\n", mNode->method, bres ? T : F);
			//DT_(make_reg_tainted)(0, tid);
			break;
		case 'C': // Char
			cres = (HChar)r[0];
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			TNT_LOGI("%s return \'Char\' value %c tainted.\n", mNode->method, cres);
			//DT_(make_reg_tainted)(0, tid);
			break;
		case 'S': // Short
			sres = (Short)r[0];
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			TNT_LOGI("%s return \'Short\' value %d tainted.\n", mNode->method, sres);
			//DT_(make_reg_tainted)(0, tid);
			break;
		case 'I': // Int
			ires = (Int)r[0];
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			TNT_LOGI("%s return \'Int\' value %d tainted.\n", mNode->method, ires);
			//DT_(make_reg_tainted)(0, tid);
			break;
		case 'J': // Long
			jres = (Long)r[0] << 32;
			jres |= r1;
			TNT_LOGI("%s return \'Long\' value %lld tainted.\n", mNode->method, jres);
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			flip_register(12, 1);
			VG_(sprintf)(dep, "INPUT:32(1)");
			update_register_dep(8, 32, dep);
			//DT_(make_reg_tainted)(0, tid);
			//DT_(make_reg_tainted)(1, tid);
			break;
		case 'F': // Float
			fres = *((Float*)r);
			TNT_LOGI("%s return \'Float\' value %f tainted.\n", mNode->method, fres);
			//DT_(make_reg_tainted)(0, tid);
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			break;
		case 'D': // Double
			dres = *((Double*)r);
			TNT_LOGI("%s return \'Double\' value %f tainted.\n", mNode->method, dres);
			flip_register(8, 1);
			VG_(sprintf)(dep, "INPUT:32(0)");
			update_register_dep(8, 32, dep);
			flip_register(12, 1);
			VG_(sprintf)(dep, "INPUT:32(1)");
			update_register_dep(8, 32, dep);
			//DT_(make_reg_tainted)(0, tid);
			//DT_(make_reg_tainted)(1, tid);
			break;
		case 'V': // Void
		default:
			break;
	}
}
/*----------------- For check parameters --------------*/

UChar check_mth_invoke(MthNode *mNode, ThreadId tid, Bool is_source)
{
	if(mNode == NULL || mNode->shorty == NULL) {
		TNT_LOGI("%s shorty is NULL!!!!\n", mNode->method);
		return 0;
	}
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	struct ArtMethodPlus *pAMth = NULL;
	ClassMirror		*clazz = NULL;
	UInt	objSize = 0, clazzSize = 0;
	Addr	objAddr = 0;
	UChar isNeedTaint = 0;
	Bool isTaint = False; 
	HChar *tmp = UNKNOWN_CLASS_NAME;//, *tmp1 = NULL;
	HChar type = '\0';
	Word *r;
	Float	*s;
	HChar *content, constrainSrc[256], constrainDst[256];
	Int tt, i = 0, j = 0, f = 0, len = 0;
	UInt    *psp;
	Addr		sp;
	Bool		bres;
	HChar		cres;
	Short		sres;
	Int			ires;
	Long		jres;
	Float		fres, fres1;
	Double	dres, dres1;
# if defined(VGPV_arm_linux_android)
	r = (Word*)&arch_state->guest_R0;
	s = (Float*)&arch_state->guest_D0;
	sp		= r[13]+16;
	psp   = (UInt*)(r[13]);
#endif
#if DBG_PARAMETER_PARSE
	VG_(printf)("r0=%08x r1=%08x r2=%08x r3=%08x sp=%08x lr=%08x pc=%08x\n",
			r[0], r[1], r[2], r[3], r[13], r[14], r[15]);
	VG_(printf)("s0=%f s1=%f s2=%f s3=%f\n",
			s[0], s[1], s[2], s[3]);
	VG_(printf)("0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
			psp[0], psp[1], psp[2], psp[3], psp[4], psp[5], psp[6], psp[7], psp[8], psp[9], psp[10]);
#endif 
	/* Check parameters */
	i = 1;
	if(mNode->accessFlags & ACC_STATIC) { // Static method
		j = 1;
	} else {
		j = 2;
		clazz = (ClassMirror*)r[1];
		if(clazz) {
			clazz = clazz->object_.klass_;
			if(clazz) 
				tmp = get_classobject_name(clazz);
			else
				tmp = "???";
		}
		isTaint = check_reg_tainted(1, tid);
		content = NULL;
		if(VG_(strcmp)("java.lang.String", tmp) == 0) {
			if(is_source) {
				make_string_tainted((StringMirror*)r[1]);
			}
			isTaint = check_string_tainted((StringMirror *)r[1]);
			content = get_stringobj_str((StringMirror *)r[1]);
			if(mNode->mthKey == FUNC_STRING_EQUALS_INDEX) {
				VG_(snprintf)(constrainSrc, 256, "%s", content);
			}
		}
		TNT_LOGI("[00] \'class\' %s@0x%08x tainted=%s ", 
				tmp, r[1], isTaint ? T : F);
		if(content)
			VG_(printf)("(c:%s)\n", content);
		else
			VG_(printf)("\n");
	}
#if DBG_PARAMETER_PARSE
	pAMth = (struct ArtMethodPlus *)r[0];
	VG_(printf)("key=%d flags=0x%08x (0x%08x) dex_method_index=%d method_index=%d\n", mNode->mthKey,
			pAMth->access_flags_, mNode->accessFlags, pAMth->dex_method_index_, pAMth->method_index_);
#endif
	isNeedTaint = isTaint ? 1 : 0;
	while(i < VG_(strlen)(mNode->shorty)) {
		type = mNode->shorty[i];
		isTaint = False;
		switch(type) {
			case 'L':
				clazzSize = 0;
				objSize   = 0;
				if(j < 4) {
					if(r[j] > 0)
						clazz = (ClassMirror *)(r[j]);
					else
						clazz = NULL;
					isTaint = check_reg_tainted(j, tid);
					j += 1;
				}	else {
					isTaint = check_mem_tainted((Addr)sp, 4);
					clazz = (ClassMirror*)(*((Addr*)sp));
					sp += sizeof(Addr);
				}
				objAddr = (Addr)clazz;
				if((Addr)clazz & (0xffff << 16))
					clazz = clazz->object_.klass_;
				else 
					clazz = NULL;
				if(clazz) {
					tmp = get_classobject_name(clazz);
					clazzSize = clazz->class_size_;
					objSize		= clazz->object_size_;;
				}	else {
					tmp = "???";
				}
				content = NULL;
				if(tmp[0] == '[') {
					len = process_array_arg(tmp, objAddr);
					isTaint = check_mem_tainted(objAddr + sizeof(ObjectMirror) + sizeof(UInt), len);
				} else if(VG_(strcmp)("java.lang.String", tmp) == 0) {
					if(is_source) {
						make_string_tainted((StringMirror*)objAddr);
					}
					content = get_stringobj_str((StringMirror *)objAddr);
					isTaint = check_string_tainted((StringMirror *)objAddr);
					if(mNode->mthKey == FUNC_STRING_EQUALS_INDEX) {
						VG_(snprintf)(constrainDst, 256, "%s",  content);
					}
				}
				TNT_LOGI("[%02d] \'class\' %s@0x%08x %d(%d) tainted=%s ", 
						i, tmp, objAddr, clazzSize, objSize, isTaint ? T : F);
				if(content)
					VG_(printf)("(c:%s)\n", content);
				else
					VG_(printf)("\n");
				break;
			case 'Z': // Bool
				if( j < 4) {
					bres = (Bool)r[j];
					isTaint = check_reg_tainted(j, tid);
					j += 1;
				} else {
					bres = (Bool)(*(Int*)sp);
					sp += sizeof(Int);
					isTaint = check_mem_tainted(sp, 4);
				}
				TNT_LOGI("[%02d] \'Bool\' %d tainted=%s.\n", 
						i, bres, isTaint ? T : F);
				break;
			case 'C':
				if( j < 4) {
					cres = (HChar)r[j];
					isTaint = check_reg_tainted(j, tid);
					j += 1;
				} else {
					cres = (HChar)(*(Int*)sp);
					sp += sizeof(Int);
					isTaint = check_mem_tainted(sp, 4);
				}
				TNT_LOGI("[%02d] \'char\' %c tainted=%s.\n", 
						i, cres, isTaint ? T : F);
				break;
			case 'S':
				if( j < 4) {
					sres = (Short)r[j];
					isTaint = check_reg_tainted(j, tid);
					j += 1;
				} else {
					sres = (Short)(*(Int*)sp);
					sp += sizeof(Int);
					isTaint = check_mem_tainted(sp, 4);
				}
				TNT_LOGI("[%02d] \'Short\' %d tainted=%s.\n", 
						i, sres, isTaint ? T : F);
				break;
			case 'I':
				if( j < 4) {
					ires = (Int)r[j];
					isTaint = check_reg_tainted(j, tid);
					j += 1;
				} else {
					ires = *(Int*)sp;
					sp += sizeof(Int);
					isTaint = check_mem_tainted(sp, 4);
				}
				TNT_LOGI("[%02d] \'Int\' 0x%x tainted=%s.\n", 
						i, ires, isTaint ? T : F);
				break;
			case 'J':
				if( j < 3) {
					jres = (Long)r[j+1] << 32;
					jres |= r[j];
					isTaint = check_reg_tainted(j, tid);
					isTaint |= check_reg_tainted(j+1, tid);
					j += 2;
				} else {
					jres = *(Long*)sp;
					sp += sizeof(Long);
					isTaint = check_mem_tainted(sp, 8);
				}
				TNT_LOGI("[%02d] \'Long\' 0x%llx tainted=%s.\n", 
						i, jres, isTaint ? T : F);
				break;
			case 'F':
#if 0
				if( j < 4) {
					fres = *((Float*)&r[j]);
					isTaint = check_reg_tainted(j, tid);
					j += 1;
				} else {
					sp += sizeof(Float);
					fres = *(Float*)sp;
					isTaint = check_mem_tainted(sp, 4);
				}
#else
				fres = s[f];
				f += 1;
				if( j >= 4 ) {
					fres1 = *((Float*)sp);
					sp += sizeof(Float);
				}
#endif
				TNT_LOGI("[%02d] \'Float\' %f (%f) tainted=%s.\n", 
						i, fres, fres1, isTaint ? T : F);
				break;
			case 'D':
#if 0
				if( j < 3) {
					dres = *((Double*)&r[j]);
					isTaint = check_reg_tainted(j, tid);
					isTaint |= check_reg_tainted(j+1, tid);
					j += 2;
				} else {
					jres = (*(Long*)sp);
					sp += sizeof(Double);
					dres = (Double)jres;
					isTaint = check_mem_tainted(sp, 8);
				}
#else
				dres = *((Double*)&s[f]);
				f += 2;
				if( j >= 4 ) {
					dres1 = *((Double*)sp);
					sp += sizeof(Double);
				}
#endif
				TNT_LOGI("[%02d] \'Double\' %f (%f) tainted=%s.\n", 
						i, dres, dres1, isTaint ? T : F);
				break;
			case 'V':
				tl_assert(0);
				break;
			default:
				TNT_LOGI("[%02d] unknown type \'%c\'\n", i, type);
				break;
		}
		i++;
		isNeedTaint = isTaint ? 1 : isNeedTaint;
	};
	if(mNode->mthKey == FUNC_STRING_EQUALS_INDEX) {
		if(isNeedTaint > 0) {
			VG_(printf)("RESULT:32(%u): %s == %s ?\n", ++taint_index, constrainSrc, constrainDst);
			isNeedTaint = taint_index % 256;
		}
	}
	return isNeedTaint;
}

UChar check_mth_return(MthNode *mNode, ThreadId tid, UChar taintTag)
{
	if(mNode == NULL || mNode->shorty == NULL) {
		TNT_LOGI("%s shorty is NULL!!!!\n", mNode->method);
		return;
	}
	if(mNode->shorty[0] == 'V') {
		return;
	}
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	Bool isTaint = False;
	HChar type = '\0';
	UWord *r;
	Float *s;
	Addr		sp;
	UInt	len = 0;
	ClassMirror		*clazz = NULL;
	HChar *tmp = NULL, *content = NULL;
	Bool		bres;
	HChar		cres;
	Short		sres;
	Int			ires;
	Long		jres;
	Float		fres, fres1;
	Double	dres, dres1;
# if defined(VGPV_arm_linux_android)
	r	= (UWord*)&arch_state->guest_R0;
	s = (Float*)&arch_state->guest_D0;
	sp		= r[13];
#endif
#if DBG_PARAMETER_PARSE
	TNT_LOGI("r0=0x%08x r1=0x%08x s0=%f s1=%f sp=0x%08x\n", 
			r[0], r[1], s[0], s[1], sp);
#endif
	/* Check parameters */
	type = mNode->shorty[0];
	switch(type) {
		case 'L':
			clazz = (ClassMirror *)r[0];
			if((Addr)clazz) {
				clazz = clazz->object_.klass_;
			} else {
				clazz = NULL;
			}
			if(clazz) {
				tmp =  get_classobject_name(clazz);	
			} else {
				tmp = "????";
			}
			isTaint = check_reg_tainted(0, tid);
			if(tmp[0] == '[') {
				len = process_array_arg(tmp, r[0]);
#if 0
				isTaint = check_mem_tainted(r[0] + sizeof(ObjectMirror) + sizeof(UInt), len);
				if(isTaint)
					DT_(make_reg_tainted)(0, tid);
				else
					DT_(make_reg_untainted)(0, tid);
#endif
			} else if(VG_(strcmp)("java.lang.String", tmp) == 0) {
				/*if(is_source) {
					make_string_tainted((StringMirror*)objAddr);
				}*/
				content = get_stringobj_str((StringMirror *)r[0]);
#if 0
				isTaint = check_string_tainted((StringMirror *)r[0]);
				if(isTaint)
					DT_(make_reg_tainted)(0, tid);
				else
					DT_(make_reg_untainted)(0, tid);
#endif
			}
			TNT_LOGI("[99] \'class\' %s@0x%08x tainted=%s ", 
					tmp, r[0], isTaint ? T : F);
			if(content)
				VG_(printf)("(c:%s)\n", content);
			else
				VG_(printf)("\n");
			break;
		case 'Z': // Bool
			bres = (Bool)r[0];
			isTaint = check_reg_tainted(0, tid);
			TNT_LOGI("[99] \'Bool\' %d tainted=%s.\n", 
					bres, isTaint ? T : F);
			if(mNode->mthKey == FUNC_STRING_EQUALS_INDEX && taintTag > 0) {
				flip_register(8, 1);
				HChar dep[32];
				VG_(sprintf)(dep, "RESULT:32(%u)", taintTag);
				update_register_dep(8, 32, dep);
				if(bres == 0) {
					r[0] = 1;
					VG_(printf)("Result is modified from \'False\' to \'True\'.\n");
				}
			}
			break;
		case 'C':
			cres = (HChar)r[0];
			isTaint = check_reg_tainted(0, tid);
			TNT_LOGI("[99] \'char\' %c tainted=%s.\n", 
					cres, isTaint ? T : F);
			break;
		case 'S':
			sres = (Short)r[0];
			isTaint = check_reg_tainted(0, tid);
			TNT_LOGI("[99] \'Short\' %d tainted=%s.\n", 
					sres, isTaint ? T : F);
			break;
		case 'I':
			ires = (Int)r[0];
			isTaint = check_reg_tainted(0, tid);
			TNT_LOGI("[99] \'Int\' 0x%x tainted=%s.\n", 
					ires, isTaint ? T : F);
			break;
		case 'J':
			jres = (Long)r[1] << 32;
			jres |= r[0];
			isTaint = check_reg_tainted(0, tid);
			isTaint |= check_reg_tainted(1, tid);
			TNT_LOGI("[99] \'Long\' 0x%llx tainted=%s.\n", 
					jres, isTaint ? T : F);
			break;
		case 'F':
			fres = *(Float*)r;
			fres1= *(Float*)s;
			isTaint = check_reg_tainted(0, tid);
			TNT_LOGI("[99] \'Float\' %f (%f) tainted=%s.\n", 
					fres1, fres, isTaint ? T : F);
			break;
		case 'D':
			dres = *(Double*)r;
			dres1= *(Double*)s;
			isTaint = check_reg_tainted(0, tid);
			isTaint |= check_reg_tainted(1, tid);
			TNT_LOGI("[99] \'Double\' %f (%f) tainted=%s.\n", 
					dres1, dres, isTaint ? T : F);
			break;
		case 'V':
		default:
			break;
	}
	return 0;
}
