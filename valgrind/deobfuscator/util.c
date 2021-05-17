#include "util.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"    // tl_assert()

Bool dumpBinary(UChar* buf, UInt size) {
	if (buf == NULL) {
		VG_(printf)("Error in dumpBinary: buf 0x%08x size: %d\n", (Addr)buf, size);
		return False;
	}
	Int fout;
	HChar fpath[255];
	VG_(sprintf)(fpath, "/data/local/tmp/fuzz/0x%08x-0x%08x.bin", (Addr)buf, (Addr)buf + size - 1);
	fout = VG_(fd_open)(fpath, VKI_O_WRONLY|VKI_O_TRUNC, 0);
	if (fout <= 0) {
		fout = VG_(fd_open)(fpath, VKI_O_CREAT|VKI_O_WRONLY, VKI_S_IRUSR|VKI_S_IWUSR);
		if( fout <= 0 ) {
			VG_(printf)("Create bin file error.\n");
			return False;
		}
	} 
	VG_(printf)("Try to dump bin file %s\n", fpath);
	VG_(write)(fout, buf, size);
	VG_(close)(fout);
	return True;
}

HChar *inet_ntoa(struct in_addr in)
{ 
	static HChar b[18];
	register UChar *p = (UChar*)&in;
	VG_(snprintf)(b, sizeof(b), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return b;	
}

Int inet_aton(UChar *cp, struct in_addr *ap)
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




int IRLoadGOp_to_str(IRLoadGOp lop, char* buffer)
{
	buffer[0] = '\0';
	int size = 0;
	switch(lop) {
		case  ILGop_INVALID:
			tl_assert(0);
			break;
		case ILGop_IdentV128: /* 128 bit vector, no conversion */
			size = 128;
			break;
		case ILGop_Ident64:   /* 64 bit, no conversion */
			size = 64;
			break;
		case ILGop_Ident32:   /* 32 bit, no conversion */
			size = 32;
			break;
		case ILGop_16Uto32:   /* 16 bit load, Z-widen to 32 */
			size = 16;
			VG_(strcpy)(buffer, "16Uto32");
			break;
		case ILGop_16Sto32:   /* 16 bit load, S-widen to 32 */
			size = 16;
			VG_(strcpy)(buffer, "16Sto32");
			break;
		case ILGop_8Uto32:    /* 8 bit load, Z-widen to 32 */
			size = 8;
			VG_(strcpy)(buffer, "8Uto32");
			break;
		case ILGop_8Sto32:     /* 8 bit load, S-widen to 32 */
			size = 8;
			VG_(strcpy)(buffer, "8Sto32");
			break;
		default:
			tl_assert(0);
	}
	return size;
}

void IROp_to_str(IROp op, char* buffer)
{
   HChar* str = NULL;
   IROp base;

   switch (op)
   {
      case Iop_Add8 ... Iop_Add64:
         str = "Add"; base = Iop_Add8; break;
      case Iop_Sub8 ... Iop_Sub64:
         str = "Sub"; base = Iop_Sub8; break;
      case Iop_Mul8 ... Iop_Mul64:
         str = "Mul"; base = Iop_Mul8; break;
      case Iop_Or8 ... Iop_Or64:
         str = "Or"; base = Iop_Or8; break;
      case Iop_And8 ... Iop_And64:
         str = "And"; base = Iop_And8; break;
      case Iop_Xor8 ... Iop_Xor64:
         str = "Xor"; base = Iop_Xor8; break;
      case Iop_Shl8 ... Iop_Shl64:
         str = "Shl"; base = Iop_Shl8; break;
      case Iop_Shr8 ... Iop_Shr64:
         str = "Shr"; base = Iop_Shr8; break;
      case Iop_Sar8 ... Iop_Sar64:
         str = "Sar"; base = Iop_Sar8; break;
      case Iop_CmpEQ8 ... Iop_CmpEQ64:
         str = "CmpEQ"; base = Iop_CmpEQ8; break;
      case Iop_CmpNE8 ... Iop_CmpNE64:
         str = "CmpNE"; base = Iop_CmpNE8; break;
      case Iop_CasCmpEQ8 ... Iop_CasCmpEQ64:
         str = "CasCmpEQ"; base = Iop_CasCmpEQ8; break;
      case Iop_CasCmpNE8 ... Iop_CasCmpNE64:
         str = "CasCmpNE"; base = Iop_CasCmpNE8; break;
      case Iop_Not8 ... Iop_Not64:
         str = "Not"; base = Iop_Not8; break;
      /* other cases must explicitly "return;" */
      case Iop_8Uto16:   VG_(strcpy)(buffer, "8Uto16");  return;
      case Iop_8Uto32:   VG_(strcpy)(buffer, "8Uto32");  return;
      case Iop_16Uto32:  VG_(strcpy)(buffer, "16Uto32"); return;
      case Iop_8Sto16:   VG_(strcpy)(buffer, "8Sto16");  return;
      case Iop_8Sto32:   VG_(strcpy)(buffer, "8Sto32");  return;
      case Iop_16Sto32:  VG_(strcpy)(buffer, "16Sto32"); return;
      case Iop_32Sto64:  VG_(strcpy)(buffer, "32Sto64"); return;
      case Iop_32Uto64:  VG_(strcpy)(buffer, "32Uto64"); return;
      case Iop_32to8:    VG_(strcpy)(buffer, "32to8");   return;
      case Iop_16Uto64:  VG_(strcpy)(buffer, "16Uto64"); return;
      case Iop_16Sto64:  VG_(strcpy)(buffer, "16Sto64"); return;
      case Iop_8Uto64:   VG_(strcpy)(buffer, "8Uto64"); return;
      case Iop_8Sto64:   VG_(strcpy)(buffer, "8Sto64"); return;
      case Iop_64to16:   VG_(strcpy)(buffer, "64to16"); return;
      case Iop_64to8:    VG_(strcpy)(buffer, "64to8");  return;

      case Iop_Not1:     VG_(strcpy)(buffer, "Not1");    return;
      case Iop_32to1:    VG_(strcpy)(buffer, "32to1");   return;
      case Iop_64to1:    VG_(strcpy)(buffer, "64to1");   return;
      case Iop_1Uto8:    VG_(strcpy)(buffer, "1Uto8");   return;
      case Iop_1Uto32:   VG_(strcpy)(buffer, "1Uto32");  return;
      case Iop_1Uto64:   VG_(strcpy)(buffer, "1Uto64");  return;
      case Iop_1Sto8:    VG_(strcpy)(buffer, "1Sto8");  return;
      case Iop_1Sto16:   VG_(strcpy)(buffer, "1Sto16");  return;
      case Iop_1Sto32:   VG_(strcpy)(buffer, "1Sto32");  return;
      case Iop_1Sto64:   VG_(strcpy)(buffer, "1Sto64");  return;

      case Iop_MullS8:   VG_(strcpy)(buffer, "MullS8");  return;
      case Iop_MullS16:  VG_(strcpy)(buffer, "MullS16"); return;
      case Iop_MullS32:  VG_(strcpy)(buffer, "MullS32"); return;
      case Iop_MullS64:  VG_(strcpy)(buffer, "MullS64"); return;
      case Iop_MullU8:   VG_(strcpy)(buffer, "MullU8");  return;
      case Iop_MullU16:  VG_(strcpy)(buffer, "MullU16"); return;
      case Iop_MullU32:  VG_(strcpy)(buffer, "MullU32"); return;
      case Iop_MullU64:  VG_(strcpy)(buffer, "MullU64"); return;

      case Iop_Clz64:    VG_(strcpy)(buffer, "Clz64"); return;
      case Iop_Clz32:    VG_(strcpy)(buffer, "Clz32"); return;
      case Iop_Ctz64:    VG_(strcpy)(buffer, "Ctz64"); return;
      case Iop_Ctz32:    VG_(strcpy)(buffer, "Ctz32"); return;

      case Iop_CmpLT32S: VG_(strcpy)(buffer, "CmpLT32S"); return;
      case Iop_CmpLE32S: VG_(strcpy)(buffer, "CmpLE32S"); return;
      case Iop_CmpLT32U: VG_(strcpy)(buffer, "CmpLT32U"); return;
      case Iop_CmpLE32U: VG_(strcpy)(buffer, "CmpLE32U"); return;

      case Iop_CmpLT64S: VG_(strcpy)(buffer, "CmpLT64S"); return;
      case Iop_CmpLE64S: VG_(strcpy)(buffer, "CmpLE64S"); return;
      case Iop_CmpLT64U: VG_(strcpy)(buffer, "CmpLT64U"); return;
      case Iop_CmpLE64U: VG_(strcpy)(buffer, "CmpLE64U"); return;

      case Iop_CmpNEZ8:  VG_(strcpy)(buffer, "CmpNEZ8"); return;
      case Iop_CmpNEZ16: VG_(strcpy)(buffer, "CmpNEZ16"); return;
      case Iop_CmpNEZ32: VG_(strcpy)(buffer, "CmpNEZ32"); return;
      case Iop_CmpNEZ64: VG_(strcpy)(buffer, "CmpNEZ64"); return;

      case Iop_CmpwNEZ32: VG_(strcpy)(buffer, "CmpwNEZ32"); return;
      case Iop_CmpwNEZ64: VG_(strcpy)(buffer, "CmpwNEZ64"); return;

      case Iop_Left8:  VG_(strcpy)(buffer, "Left8"); return;
      case Iop_Left16: VG_(strcpy)(buffer, "Left16"); return;
      case Iop_Left32: VG_(strcpy)(buffer, "Left32"); return;
      case Iop_Left64: VG_(strcpy)(buffer, "Left64"); return;
      case Iop_Max32U: VG_(strcpy)(buffer, "Max32U"); return;

      case Iop_CmpORD32U: VG_(strcpy)(buffer, "CmpORD32U"); return;
      case Iop_CmpORD32S: VG_(strcpy)(buffer, "CmpORD32S"); return;

      case Iop_CmpORD64U: VG_(strcpy)(buffer, "CmpORD64U"); return;
      case Iop_CmpORD64S: VG_(strcpy)(buffer, "CmpORD64S"); return;

      case Iop_DivU32: VG_(strcpy)(buffer, "DivU32"); return;
      case Iop_DivS32: VG_(strcpy)(buffer, "DivS32"); return;
      case Iop_DivU64: VG_(strcpy)(buffer, "DivU64"); return;
      case Iop_DivS64: VG_(strcpy)(buffer, "DivS64"); return;
      case Iop_DivU64E: VG_(strcpy)(buffer, "DivU64E"); return;
      case Iop_DivS64E: VG_(strcpy)(buffer, "DivS64E"); return;
      case Iop_DivU32E: VG_(strcpy)(buffer, "DivU32E"); return;
      case Iop_DivS32E: VG_(strcpy)(buffer, "DivS32E"); return;

      case Iop_DivModU64to32: VG_(strcpy)(buffer, "DivModU64to32"); return;
      case Iop_DivModS64to32: VG_(strcpy)(buffer, "DivModS64to32"); return;

      case Iop_DivModU128to64: VG_(strcpy)(buffer, "DivModU128to64"); return;
      case Iop_DivModS128to64: VG_(strcpy)(buffer, "DivModS128to64"); return;

      case Iop_DivModS64to64: VG_(strcpy)(buffer, "DivModS64to64"); return;

      case Iop_16HIto8:  VG_(strcpy)(buffer, "16HIto8"); return;
      case Iop_16to8:    VG_(strcpy)(buffer, "16to8");   return;
      case Iop_8HLto16:  VG_(strcpy)(buffer, "8HLto16"); return;

      case Iop_32HIto16: VG_(strcpy)(buffer, "32HIto16"); return;
      case Iop_32to16:   VG_(strcpy)(buffer, "32to16");   return;
      case Iop_16HLto32: VG_(strcpy)(buffer, "16HLto32"); return;

      case Iop_64HIto32: VG_(strcpy)(buffer, "64HIto32"); return;
      case Iop_64to32:   VG_(strcpy)(buffer, "64to32");   return;
      case Iop_32HLto64: VG_(strcpy)(buffer, "32HLto64"); return;

      case Iop_128HIto64: VG_(strcpy)(buffer, "128HIto64"); return;
      case Iop_128to64:   VG_(strcpy)(buffer, "128to64");   return;
      case Iop_64HLto128: VG_(strcpy)(buffer, "64HLto128"); return;

      case Iop_CmpF32:    VG_(strcpy)(buffer, "CmpF32");    return;
#ifdef T380
      case Iop_F32toI16S: VG_(strcpy)(buffer, "F32toI16S");  return;
#endif
      case Iop_F32toI32S: VG_(strcpy)(buffer, "F32toI32S");  return;
      case Iop_F32toI64S: VG_(strcpy)(buffer, "F32toI64S");  return;
#ifdef T380
      case Iop_I16StoF32: VG_(strcpy)(buffer, "I16StoF32");  return;
#endif
      case Iop_I32StoF32: VG_(strcpy)(buffer, "I32StoF32");  return;
      case Iop_I64StoF32: VG_(strcpy)(buffer, "I64StoF32");  return;

      case Iop_AddF64:    VG_(strcpy)(buffer, "AddF64"); return;
      case Iop_SubF64:    VG_(strcpy)(buffer, "SubF64"); return;
      case Iop_MulF64:    VG_(strcpy)(buffer, "MulF64"); return;
      case Iop_DivF64:    VG_(strcpy)(buffer, "DivF64"); return;
      case Iop_AddF64r32: VG_(strcpy)(buffer, "AddF64r32"); return;
      case Iop_SubF64r32: VG_(strcpy)(buffer, "SubF64r32"); return;
      case Iop_MulF64r32: VG_(strcpy)(buffer, "MulF64r32"); return;
      case Iop_DivF64r32: VG_(strcpy)(buffer, "DivF64r32"); return;
      case Iop_AddF32:    VG_(strcpy)(buffer, "AddF32"); return;
      case Iop_SubF32:    VG_(strcpy)(buffer, "SubF32"); return;
      case Iop_MulF32:    VG_(strcpy)(buffer, "MulF32"); return;
      case Iop_DivF32:    VG_(strcpy)(buffer, "DivF32"); return;

        /* 128 bit floating point */
      case Iop_AddF128:   VG_(strcpy)(buffer, "AddF128");  return;
      case Iop_SubF128:   VG_(strcpy)(buffer, "SubF128");  return;
      case Iop_MulF128:   VG_(strcpy)(buffer, "MulF128");  return;
      case Iop_DivF128:   VG_(strcpy)(buffer, "DivF128");  return;
      case Iop_AbsF128:   VG_(strcpy)(buffer, "AbsF128");  return;
      case Iop_NegF128:   VG_(strcpy)(buffer, "NegF128");  return;
      case Iop_SqrtF128:  VG_(strcpy)(buffer, "SqrtF128"); return;
      case Iop_CmpF128:   VG_(strcpy)(buffer, "CmpF128");  return;

      case Iop_F64HLtoF128: VG_(strcpy)(buffer, "F64HLtoF128"); return;
      case Iop_F128HItoF64: VG_(strcpy)(buffer, "F128HItoF64"); return;
      case Iop_F128LOtoF64: VG_(strcpy)(buffer, "F128LOtoF64"); return;
      case Iop_I32StoF128: VG_(strcpy)(buffer, "I32StoF128"); return;
      case Iop_I64StoF128: VG_(strcpy)(buffer, "I64StoF128"); return;
      case Iop_F128toI32S: VG_(strcpy)(buffer, "F128toI32S"); return;
      case Iop_F128toI64S: VG_(strcpy)(buffer, "F128toI64S"); return;
      case Iop_F32toF128:  VG_(strcpy)(buffer, "F32toF128");  return;
      case Iop_F64toF128:  VG_(strcpy)(buffer, "F64toF128");  return;
      case Iop_F128toF64:  VG_(strcpy)(buffer, "F128toF64");  return;
      case Iop_F128toF32:  VG_(strcpy)(buffer, "F128toF32");  return;

        /* s390 specific */
      case Iop_MAddF32:    VG_(strcpy)(buffer, "s390_MAddF32"); return;
      case Iop_MSubF32:    VG_(strcpy)(buffer, "s390_MSubF32"); return;

      case Iop_ScaleF64:      VG_(strcpy)(buffer, "ScaleF64"); return;
      case Iop_AtanF64:       VG_(strcpy)(buffer, "AtanF64"); return;
      case Iop_Yl2xF64:       VG_(strcpy)(buffer, "Yl2xF64"); return;
      case Iop_Yl2xp1F64:     VG_(strcpy)(buffer, "Yl2xp1F64"); return;
      case Iop_PRemF64:       VG_(strcpy)(buffer, "PRemF64"); return;
      case Iop_PRemC3210F64:  VG_(strcpy)(buffer, "PRemC3210F64"); return;
      case Iop_PRem1F64:      VG_(strcpy)(buffer, "PRem1F64"); return;
      case Iop_PRem1C3210F64: VG_(strcpy)(buffer, "PRem1C3210F64"); return;
      case Iop_NegF64:        VG_(strcpy)(buffer, "NegF64"); return;
      case Iop_AbsF64:        VG_(strcpy)(buffer, "AbsF64"); return;
      case Iop_NegF32:        VG_(strcpy)(buffer, "NegF32"); return;
      case Iop_AbsF32:        VG_(strcpy)(buffer, "AbsF32"); return;
      case Iop_SqrtF64:       VG_(strcpy)(buffer, "SqrtF64"); return;
      case Iop_SqrtF32:       VG_(strcpy)(buffer, "SqrtF32"); return;
      case Iop_SinF64:    VG_(strcpy)(buffer, "SinF64"); return;
      case Iop_CosF64:    VG_(strcpy)(buffer, "CosF64"); return;
      case Iop_TanF64:    VG_(strcpy)(buffer, "TanF64"); return;
      case Iop_2xm1F64:   VG_(strcpy)(buffer, "2xm1F64"); return;

      case Iop_MAddF64:    VG_(strcpy)(buffer, "MAddF64"); return;
      case Iop_MSubF64:    VG_(strcpy)(buffer, "MSubF64"); return;
      case Iop_MAddF64r32: VG_(strcpy)(buffer, "MAddF64r32"); return;
      case Iop_MSubF64r32: VG_(strcpy)(buffer, "MSubF64r32"); return;

#ifdef T380
      case Iop_Est5FRSqrt:						VG_(strcpy)(buffer, "Est5FRSqrt"); return;
#else
      case Iop_RSqrtEst5GoodF64:			VG_(strcpy)(buffer, "Est5FRSqrt"); return;
#endif
      case Iop_RoundF64toF64_NEAREST: VG_(strcpy)(buffer, "RoundF64toF64_NEAREST"); return;
      case Iop_RoundF64toF64_NegINF:	VG_(strcpy)(buffer, "RoundF64toF64_NegINF"); return;
      case Iop_RoundF64toF64_PosINF:	VG_(strcpy)(buffer, "RoundF64toF64_PosINF"); return;
      case Iop_RoundF64toF64_ZERO:		VG_(strcpy)(buffer, "RoundF64toF64_ZERO"); return;

      case Iop_TruncF64asF32: VG_(strcpy)(buffer, "TruncF64asF32"); return;
#ifdef T380
      case Iop_CalcFPRF:      VG_(strcpy)(buffer, "CalcFPRF"); return;
#endif

      case Iop_QAdd32S: VG_(strcpy)(buffer, "QAdd32S"); return;
      case Iop_QSub32S: VG_(strcpy)(buffer, "QSub32S"); return;
      case Iop_Add16x2:   VG_(strcpy)(buffer, "Add16x2"); return;
      case Iop_Sub16x2:   VG_(strcpy)(buffer, "Sub16x2"); return;
      case Iop_QAdd16Sx2: VG_(strcpy)(buffer, "QAdd16Sx2"); return;
      case Iop_QAdd16Ux2: VG_(strcpy)(buffer, "QAdd16Ux2"); return;
      case Iop_QSub16Sx2: VG_(strcpy)(buffer, "QSub16Sx2"); return;
      case Iop_QSub16Ux2: VG_(strcpy)(buffer, "QSub16Ux2"); return;
      case Iop_HAdd16Ux2: VG_(strcpy)(buffer, "HAdd16Ux2"); return;
      case Iop_HAdd16Sx2: VG_(strcpy)(buffer, "HAdd16Sx2"); return;
      case Iop_HSub16Ux2: VG_(strcpy)(buffer, "HSub16Ux2"); return;
      case Iop_HSub16Sx2: VG_(strcpy)(buffer, "HSub16Sx2"); return;

      case Iop_Add8x4:   VG_(strcpy)(buffer, "Add8x4"); return;
      case Iop_Sub8x4:   VG_(strcpy)(buffer, "Sub8x4"); return;
      case Iop_QAdd8Sx4: VG_(strcpy)(buffer, "QAdd8Sx4"); return;
      case Iop_QAdd8Ux4: VG_(strcpy)(buffer, "QAdd8Ux4"); return;
      case Iop_QSub8Sx4: VG_(strcpy)(buffer, "QSub8Sx4"); return;
      case Iop_QSub8Ux4: VG_(strcpy)(buffer, "QSub8Ux4"); return;
      case Iop_HAdd8Ux4: VG_(strcpy)(buffer, "HAdd8Ux4"); return;
      case Iop_HAdd8Sx4: VG_(strcpy)(buffer, "HAdd8Sx4"); return;
      case Iop_HSub8Ux4: VG_(strcpy)(buffer, "HSub8Ux4"); return;
      case Iop_HSub8Sx4: VG_(strcpy)(buffer, "HSub8Sx4"); return;
      case Iop_Sad8Ux4:  VG_(strcpy)(buffer, "Sad8Ux4"); return;

      case Iop_CmpNEZ16x2: VG_(strcpy)(buffer, "CmpNEZ16x2"); return;
      case Iop_CmpNEZ8x4:  VG_(strcpy)(buffer, "CmpNEZ8x4"); return;

      case Iop_CmpF64:    VG_(strcpy)(buffer, "CmpF64"); return;

      case Iop_F64toI16S: VG_(strcpy)(buffer, "F64toI16S"); return;
      case Iop_F64toI32S: VG_(strcpy)(buffer, "F64toI32S"); return;
      case Iop_F64toI64S: VG_(strcpy)(buffer, "F64toI64S"); return;
      case Iop_F64toI64U: VG_(strcpy)(buffer, "F64toI64U"); return;

      case Iop_F64toI32U: VG_(strcpy)(buffer, "F64toI32U"); return;

#ifdef T380
      case Iop_I16StoF64: VG_(strcpy)(buffer, "I16StoF64"); return;
#endif
      case Iop_I32StoF64: VG_(strcpy)(buffer, "I32StoF64"); return;
      case Iop_I64StoF64: VG_(strcpy)(buffer, "I64StoF64"); return;
      case Iop_I64UtoF64: VG_(strcpy)(buffer, "I64UtoF64"); return;
      case Iop_I64UtoF32: VG_(strcpy)(buffer, "I64UtoF32"); return;

      case Iop_I32UtoF64: VG_(strcpy)(buffer, "I32UtoF64"); return;

      case Iop_F32toF64: VG_(strcpy)(buffer, "F32toF64"); return;
      case Iop_F64toF32: VG_(strcpy)(buffer, "F64toF32"); return;

      case Iop_RoundF64toInt: VG_(strcpy)(buffer, "RoundF64toInt"); return;
      case Iop_RoundF32toInt: VG_(strcpy)(buffer, "RoundF32toInt"); return;
      case Iop_RoundF64toF32: VG_(strcpy)(buffer, "RoundF64toF32"); return;

      case Iop_ReinterpF64asI64: VG_(strcpy)(buffer, "ReinterpF64asI64"); return;
      case Iop_ReinterpI64asF64: VG_(strcpy)(buffer, "ReinterpI64asF64"); return;
      case Iop_ReinterpF32asI32: VG_(strcpy)(buffer, "ReinterpF32asI32"); return;
      case Iop_ReinterpI32asF32: VG_(strcpy)(buffer, "ReinterpI32asF32"); return;

      case Iop_I32UtoFx4: VG_(strcpy)(buffer, "I32UtoFx4"); return;
      case Iop_I32StoFx4: VG_(strcpy)(buffer, "I32StoFx4"); return;

      case Iop_F32toF16x4: VG_(strcpy)(buffer, "F32toF16x4"); return;
      case Iop_F16toF32x4: VG_(strcpy)(buffer, "F16toF32x4"); return;

#ifdef T380
      case Iop_Rsqrte32Fx4:	VG_(strcpy)(buffer, "VRsqrte32Fx4"); return;
      case Iop_Rsqrte32x4:  VG_(strcpy)(buffer, "VRsqrte32x4"); return;
      case Iop_Rsqrte32Fx2: VG_(strcpy)(buffer, "VRsqrte32Fx2"); return;
      case Iop_Rsqrte32x2:  VG_(strcpy)(buffer, "VRsqrte32x2"); return;
#else
      case Iop_RSqrtEst32Fx4: VG_(strcpy)(buffer, "VRsqrte32Fx4"); return;
      case Iop_RSqrtEst32Ux4: VG_(strcpy)(buffer, "VRsqrte32x4"); return;
      case Iop_RSqrtEst32Fx2: VG_(strcpy)(buffer, "VRsqrte32Fx2"); return;
      case Iop_RSqrtEst32Ux2: VG_(strcpy)(buffer, "VRsqrte32x2"); return;
#endif

      case Iop_QFtoI32Ux4_RZ: VG_(strcpy)(buffer, "QFtoI32Ux4_RZ"); return;
      case Iop_QFtoI32Sx4_RZ: VG_(strcpy)(buffer, "QFtoI32Sx4_RZ"); return;

      case Iop_FtoI32Ux4_RZ: VG_(strcpy)(buffer, "FtoI32Ux4_RZ"); return;
      case Iop_FtoI32Sx4_RZ: VG_(strcpy)(buffer, "FtoI32Sx4_RZ"); return;

      case Iop_I32UtoFx2: VG_(strcpy)(buffer, "I32UtoFx2"); return;
      case Iop_I32StoFx2: VG_(strcpy)(buffer, "I32StoFx2"); return;

      case Iop_FtoI32Ux2_RZ: VG_(strcpy)(buffer, "FtoI32Ux2_RZ"); return;
      case Iop_FtoI32Sx2_RZ: VG_(strcpy)(buffer, "FtoI32Sx2_RZ"); return;

      case Iop_RoundF32x4_RM: VG_(strcpy)(buffer, "RoundF32x4_RM"); return;
      case Iop_RoundF32x4_RP: VG_(strcpy)(buffer, "RoundF32x4_RP"); return;
      case Iop_RoundF32x4_RN: VG_(strcpy)(buffer, "RoundF32x4_RN"); return;
      case Iop_RoundF32x4_RZ: VG_(strcpy)(buffer, "RoundF32x4_RZ"); return;

      case Iop_Abs8x8: VG_(strcpy)(buffer, "Abs8x8"); return;
      case Iop_Abs16x4: VG_(strcpy)(buffer, "Abs16x4"); return;
      case Iop_Abs32x2: VG_(strcpy)(buffer, "Abs32x2"); return;
      case Iop_Add8x8: VG_(strcpy)(buffer, "Add8x8"); return;
      case Iop_Add16x4: VG_(strcpy)(buffer, "Add16x4"); return;
      case Iop_Add32x2: VG_(strcpy)(buffer, "Add32x2"); return;
      case Iop_QAdd8Ux8: VG_(strcpy)(buffer, "QAdd8Ux8"); return;
      case Iop_QAdd16Ux4: VG_(strcpy)(buffer, "QAdd16Ux4"); return;
      case Iop_QAdd32Ux2: VG_(strcpy)(buffer, "QAdd32Ux2"); return;
      case Iop_QAdd64Ux1: VG_(strcpy)(buffer, "QAdd64Ux1"); return;
      case Iop_QAdd8Sx8: VG_(strcpy)(buffer, "QAdd8Sx8"); return;
      case Iop_QAdd16Sx4: VG_(strcpy)(buffer, "QAdd16Sx4"); return;
      case Iop_QAdd32Sx2: VG_(strcpy)(buffer, "QAdd32Sx2"); return;
      case Iop_QAdd64Sx1: VG_(strcpy)(buffer, "QAdd64Sx1"); return;
      case Iop_PwAdd8x8: VG_(strcpy)(buffer, "PwAdd8x8"); return;
      case Iop_PwAdd16x4: VG_(strcpy)(buffer, "PwAdd16x4"); return;
      case Iop_PwAdd32x2: VG_(strcpy)(buffer, "PwAdd32x2"); return;
      case Iop_PwAdd32Fx2: VG_(strcpy)(buffer, "PwAdd32Fx2"); return;
      case Iop_PwAddL8Ux8: VG_(strcpy)(buffer, "PwAddL8Ux8"); return;
      case Iop_PwAddL16Ux4: VG_(strcpy)(buffer, "PwAddL16Ux4"); return;
      case Iop_PwAddL32Ux2: VG_(strcpy)(buffer, "PwAddL32Ux2"); return;
      case Iop_PwAddL8Sx8: VG_(strcpy)(buffer, "PwAddL8Sx8"); return;
      case Iop_PwAddL16Sx4: VG_(strcpy)(buffer, "PwAddL16Sx4"); return;
      case Iop_PwAddL32Sx2: VG_(strcpy)(buffer, "PwAddL32Sx2"); return;
      case Iop_Sub8x8: VG_(strcpy)(buffer, "Sub8x8"); return;
      case Iop_Sub16x4: VG_(strcpy)(buffer, "Sub16x4"); return;
      case Iop_Sub32x2: VG_(strcpy)(buffer, "Sub32x2"); return;
      case Iop_QSub8Ux8: VG_(strcpy)(buffer, "QSub8Ux8"); return;
      case Iop_QSub16Ux4: VG_(strcpy)(buffer, "QSub16Ux4"); return;
      case Iop_QSub32Ux2: VG_(strcpy)(buffer, "QSub32Ux2"); return;
      case Iop_QSub64Ux1: VG_(strcpy)(buffer, "QSub64Ux1"); return;
      case Iop_QSub8Sx8: VG_(strcpy)(buffer, "QSub8Sx8"); return;
      case Iop_QSub16Sx4: VG_(strcpy)(buffer, "QSub16Sx4"); return;
      case Iop_QSub32Sx2: VG_(strcpy)(buffer, "QSub32Sx2"); return;
      case Iop_QSub64Sx1: VG_(strcpy)(buffer, "QSub64Sx1"); return;
      case Iop_Mul8x8: VG_(strcpy)(buffer, "Mul8x8"); return;
      case Iop_Mul16x4: VG_(strcpy)(buffer, "Mul16x4"); return;
      case Iop_Mul32x2: VG_(strcpy)(buffer, "Mul32x2"); return;
      case Iop_Mul32Fx2: VG_(strcpy)(buffer, "Mul32Fx2"); return;
      case Iop_PolynomialMul8x8: VG_(strcpy)(buffer, "PolynomialMul8x8"); return;
      case Iop_MulHi16Ux4: VG_(strcpy)(buffer, "MulHi16Ux4"); return;
      case Iop_MulHi16Sx4: VG_(strcpy)(buffer, "MulHi16Sx4"); return;
      case Iop_QDMulHi16Sx4: VG_(strcpy)(buffer, "QDMulHi16Sx4"); return;
      case Iop_QDMulHi32Sx2: VG_(strcpy)(buffer, "QDMulHi32Sx2"); return;
      case Iop_QRDMulHi16Sx4: VG_(strcpy)(buffer, "QRDMulHi16Sx4"); return;
      case Iop_QRDMulHi32Sx2: VG_(strcpy)(buffer, "QRDMulHi32Sx2"); return;
#ifdef T380
      case Iop_QDMulLong16Sx4: VG_(strcpy)(buffer, "QDMulLong16Sx4"); return;
      case Iop_QDMulLong32Sx2: VG_(strcpy)(buffer, "QDMulLong32Sx2"); return;
#else
      case Iop_QDMull16Sx4: VG_(strcpy)(buffer, "QDMulLong16Sx4"); return;
      case Iop_QDMull32Sx2: VG_(strcpy)(buffer, "QDMulLong32Sx2"); return;
#endif
      case Iop_Avg8Ux8: VG_(strcpy)(buffer, "Avg8Ux8"); return;
      case Iop_Avg16Ux4: VG_(strcpy)(buffer, "Avg16Ux4"); return;
      case Iop_Max8Sx8: VG_(strcpy)(buffer, "Max8Sx8"); return;
      case Iop_Max16Sx4: VG_(strcpy)(buffer, "Max16Sx4"); return;
      case Iop_Max32Sx2: VG_(strcpy)(buffer, "Max32Sx2"); return;
      case Iop_Max8Ux8: VG_(strcpy)(buffer, "Max8Ux8"); return;
      case Iop_Max16Ux4: VG_(strcpy)(buffer, "Max16Ux4"); return;
      case Iop_Max32Ux2: VG_(strcpy)(buffer, "Max32Ux2"); return;
      case Iop_Min8Sx8: VG_(strcpy)(buffer, "Min8Sx8"); return;
      case Iop_Min16Sx4: VG_(strcpy)(buffer, "Min16Sx4"); return;
      case Iop_Min32Sx2: VG_(strcpy)(buffer, "Min32Sx2"); return;
      case Iop_Min8Ux8: VG_(strcpy)(buffer, "Min8Ux8"); return;
      case Iop_Min16Ux4: VG_(strcpy)(buffer, "Min16Ux4"); return;
      case Iop_Min32Ux2: VG_(strcpy)(buffer, "Min32Ux2"); return;
      case Iop_PwMax8Sx8: VG_(strcpy)(buffer, "PwMax8Sx8"); return;
      case Iop_PwMax16Sx4: VG_(strcpy)(buffer, "PwMax16Sx4"); return;
      case Iop_PwMax32Sx2: VG_(strcpy)(buffer, "PwMax32Sx2"); return;
      case Iop_PwMax8Ux8: VG_(strcpy)(buffer, "PwMax8Ux8"); return;
      case Iop_PwMax16Ux4: VG_(strcpy)(buffer, "PwMax16Ux4"); return;
      case Iop_PwMax32Ux2: VG_(strcpy)(buffer, "PwMax32Ux2"); return;
      case Iop_PwMin8Sx8: VG_(strcpy)(buffer, "PwMin8Sx8"); return;
      case Iop_PwMin16Sx4: VG_(strcpy)(buffer, "PwMin16Sx4"); return;
      case Iop_PwMin32Sx2: VG_(strcpy)(buffer, "PwMin32Sx2"); return;
      case Iop_PwMin8Ux8: VG_(strcpy)(buffer, "PwMin8Ux8"); return;
      case Iop_PwMin16Ux4: VG_(strcpy)(buffer, "PwMin16Ux4"); return;
      case Iop_PwMin32Ux2: VG_(strcpy)(buffer, "PwMin32Ux2"); return;
      case Iop_CmpEQ8x8: VG_(strcpy)(buffer, "CmpEQ8x8"); return;
      case Iop_CmpEQ16x4: VG_(strcpy)(buffer, "CmpEQ16x4"); return;
      case Iop_CmpEQ32x2: VG_(strcpy)(buffer, "CmpEQ32x2"); return;
      case Iop_CmpGT8Ux8: VG_(strcpy)(buffer, "CmpGT8Ux8"); return;
      case Iop_CmpGT16Ux4: VG_(strcpy)(buffer, "CmpGT16Ux4"); return;
      case Iop_CmpGT32Ux2: VG_(strcpy)(buffer, "CmpGT32Ux2"); return;
      case Iop_CmpGT8Sx8: VG_(strcpy)(buffer, "CmpGT8Sx8"); return;
      case Iop_CmpGT16Sx4: VG_(strcpy)(buffer, "CmpGT16Sx4"); return;
      case Iop_CmpGT32Sx2: VG_(strcpy)(buffer, "CmpGT32Sx2"); return;
      case Iop_Cnt8x8: VG_(strcpy)(buffer, "Cnt8x8"); return;
#ifdef T380
      case Iop_Clz8Sx8:	 VG_(strcpy)(buffer, "Clz8Sx8"); return;
      case Iop_Clz16Sx4: VG_(strcpy)(buffer, "Clz16Sx4"); return;
      case Iop_Clz32Sx2: VG_(strcpy)(buffer, "Clz32Sx2"); return;
			case Iop_Cls8Sx8:	 VG_(strcpy)(buffer, "Cls8Sx8"); return;
      case Iop_Cls16Sx4: VG_(strcpy)(buffer, "Cls16Sx4"); return;
      case Iop_Cls32Sx2: VG_(strcpy)(buffer, "Cls32Sx2"); return;
#else
      case Iop_Clz8x8:	VG_(strcpy)(buffer, "Clz8Sx8"); return;
      case Iop_Clz16x4: VG_(strcpy)(buffer, "Clz16Sx4"); return;
      case Iop_Clz32x2: VG_(strcpy)(buffer, "Clz32Sx2"); return;
      case Iop_Cls8x8:	VG_(strcpy)(buffer, "Cls8Sx8"); return;
      case Iop_Cls16x4: VG_(strcpy)(buffer, "Cls16Sx4"); return;
      case Iop_Cls32x2: VG_(strcpy)(buffer, "Cls32Sx2"); return;
#endif
      case Iop_ShlN8x8: VG_(strcpy)(buffer, "ShlN8x8"); return;
      case Iop_ShlN16x4: VG_(strcpy)(buffer, "ShlN16x4"); return;
      case Iop_ShlN32x2: VG_(strcpy)(buffer, "ShlN32x2"); return;
      case Iop_ShrN8x8: VG_(strcpy)(buffer, "ShrN8x8"); return;
      case Iop_ShrN16x4: VG_(strcpy)(buffer, "ShrN16x4"); return;
      case Iop_ShrN32x2: VG_(strcpy)(buffer, "ShrN32x2"); return;
      case Iop_SarN8x8: VG_(strcpy)(buffer, "SarN8x8"); return;
      case Iop_SarN16x4: VG_(strcpy)(buffer, "SarN16x4"); return;
      case Iop_SarN32x2: VG_(strcpy)(buffer, "SarN32x2"); return;
      case Iop_QNarrowBin16Sto8Ux8: VG_(strcpy)(buffer, "QNarrowBin16Sto8Ux8"); return;
      case Iop_QNarrowBin16Sto8Sx8: VG_(strcpy)(buffer, "QNarrowBin16Sto8Sx8"); return;
      case Iop_QNarrowBin32Sto16Sx4: VG_(strcpy)(buffer, "QNarrowBin32Sto16Sx4"); return;
      case Iop_NarrowBin16to8x8: VG_(strcpy)(buffer, "NarrowBin16to8x8"); return;
      case Iop_NarrowBin32to16x4: VG_(strcpy)(buffer, "NarrowBin32to16x4"); return;
      case Iop_InterleaveHI8x8: VG_(strcpy)(buffer, "InterleaveHI8x8"); return;
      case Iop_InterleaveHI16x4: VG_(strcpy)(buffer, "InterleaveHI16x4"); return;
      case Iop_InterleaveHI32x2: VG_(strcpy)(buffer, "InterleaveHI32x2"); return;
      case Iop_InterleaveLO8x8: VG_(strcpy)(buffer, "InterleaveLO8x8"); return;
      case Iop_InterleaveLO16x4: VG_(strcpy)(buffer, "InterleaveLO16x4"); return;
      case Iop_InterleaveLO32x2: VG_(strcpy)(buffer, "InterleaveLO32x2"); return;
      case Iop_CatOddLanes8x8: VG_(strcpy)(buffer, "CatOddLanes8x8"); return;
      case Iop_CatOddLanes16x4: VG_(strcpy)(buffer, "CatOddLanes16x4"); return;
      case Iop_CatEvenLanes8x8: VG_(strcpy)(buffer, "CatEvenLanes8x8"); return;
      case Iop_CatEvenLanes16x4: VG_(strcpy)(buffer, "CatEvenLanes16x4"); return;
      case Iop_InterleaveOddLanes8x8: VG_(strcpy)(buffer, "InterleaveOddLanes8x8"); return;
      case Iop_InterleaveOddLanes16x4: VG_(strcpy)(buffer, "InterleaveOddLanes16x4"); return;
      case Iop_InterleaveEvenLanes8x8: VG_(strcpy)(buffer, "InterleaveEvenLanes8x8"); return;
      case Iop_InterleaveEvenLanes16x4: VG_(strcpy)(buffer, "InterleaveEvenLanes16x4"); return;
      case Iop_Shl8x8: VG_(strcpy)(buffer, "Shl8x8"); return;
      case Iop_Shl16x4: VG_(strcpy)(buffer, "Shl16x4"); return;
      case Iop_Shl32x2: VG_(strcpy)(buffer, "Shl32x2"); return;
      case Iop_Shr8x8: VG_(strcpy)(buffer, "Shr8x8"); return;
      case Iop_Shr16x4: VG_(strcpy)(buffer, "Shr16x4"); return;
      case Iop_Shr32x2: VG_(strcpy)(buffer, "Shr32x2"); return;
      case Iop_QShl8x8: VG_(strcpy)(buffer, "QShl8x8"); return;
      case Iop_QShl16x4: VG_(strcpy)(buffer, "QShl16x4"); return;
      case Iop_QShl32x2: VG_(strcpy)(buffer, "QShl32x2"); return;
      case Iop_QShl64x1: VG_(strcpy)(buffer, "QShl64x1"); return;
      case Iop_QSal8x8: VG_(strcpy)(buffer, "QSal8x8"); return;
      case Iop_QSal16x4: VG_(strcpy)(buffer, "QSal16x4"); return;
      case Iop_QSal32x2: VG_(strcpy)(buffer, "QSal32x2"); return;
      case Iop_QSal64x1: VG_(strcpy)(buffer, "QSal64x1"); return;
#ifdef T380
      case Iop_QShlN8Sx8: VG_(strcpy)(buffer, "QShlN8Sx8"); return;
      case Iop_QShlN16Sx4: VG_(strcpy)(buffer, "QShlN16Sx4"); return;
      case Iop_QShlN32Sx2: VG_(strcpy)(buffer, "QShlN32Sx2"); return;
      case Iop_QShlN64Sx1: VG_(strcpy)(buffer, "QShlN64Sx1"); return;
      
			case Iop_QShlN8x8: VG_(strcpy)(buffer, "QShlN8x8"); return;
      case Iop_QShlN16x4: VG_(strcpy)(buffer, "QShlN16x4"); return;
      case Iop_QShlN32x2: VG_(strcpy)(buffer, "QShlN32x2"); return;
      case Iop_QShlN64x1: VG_(strcpy)(buffer, "QShlN64x1"); return;
      
			case Iop_QSalN8x8: VG_(strcpy)(buffer, "QSalN8x8"); return;
      case Iop_QSalN16x4: VG_(strcpy)(buffer, "QSalN16x4"); return;
      case Iop_QSalN32x2: VG_(strcpy)(buffer, "QSalN32x2"); return;
      case Iop_QSalN64x1: VG_(strcpy)(buffer, "QSalN64x1"); return;
#else
      case Iop_QShlNsatSU8x8:		VG_(strcpy)(buffer, "QShlN8Sx8"); return;
			case Iop_QShlNsatSU16x4:	VG_(strcpy)(buffer, "QShlN16Sx4"); return;
      case Iop_QShlNsatSU32x2:	VG_(strcpy)(buffer, "QShlN32Sx2"); return;
      case Iop_QShlNsatSU64x1:	VG_(strcpy)(buffer, "QShlN64Sx1"); return;
      
			case Iop_QShlNsatUU8x8:		VG_(strcpy)(buffer, "QShlN8x8"); return;
      case Iop_QShlNsatUU16x4:	VG_(strcpy)(buffer, "QShlN16x4"); return;
      case Iop_QShlNsatUU32x2:	VG_(strcpy)(buffer, "QShlN32x2"); return;
      case Iop_QShlNsatUU64x1:	VG_(strcpy)(buffer, "QShlN64x1"); return;
      
			case Iop_QShlNsatSS8x8:		VG_(strcpy)(buffer, "QSalN8x8"); return;
      case Iop_QShlNsatSS16x4:	VG_(strcpy)(buffer, "QSalN16x4"); return;
      case Iop_QShlNsatSS32x2:	VG_(strcpy)(buffer, "QSalN32x2"); return;
      case Iop_QShlNsatSS64x1:	VG_(strcpy)(buffer, "QSalN64x1"); return;
#endif
      case Iop_Sar8x8: VG_(strcpy)(buffer, "Sar8x8"); return;
      case Iop_Sar16x4: VG_(strcpy)(buffer, "Sar16x4"); return;
      case Iop_Sar32x2: VG_(strcpy)(buffer, "Sar32x2"); return;
      case Iop_Sal8x8: VG_(strcpy)(buffer, "Sal8x8"); return;
      case Iop_Sal16x4: VG_(strcpy)(buffer, "Sal16x4"); return;
      case Iop_Sal32x2: VG_(strcpy)(buffer, "Sal32x2"); return;
      case Iop_Sal64x1: VG_(strcpy)(buffer, "Sal64x1"); return;
      case Iop_Perm8x8: VG_(strcpy)(buffer, "Perm8x8"); return;
#ifdef T380
      case Iop_Reverse16_8x8: VG_(strcpy)(buffer, "Reverse16_8x8"); return;
      case Iop_Reverse32_8x8: VG_(strcpy)(buffer, "Reverse32_8x8"); return;
      case Iop_Reverse32_16x4: VG_(strcpy)(buffer, "Reverse32_16x4"); return;
      case Iop_Reverse64_8x8: VG_(strcpy)(buffer, "Reverse64_8x8"); return;
      case Iop_Reverse64_16x4: VG_(strcpy)(buffer, "Reverse64_16x4"); return;
      case Iop_Reverse64_32x2: VG_(strcpy)(buffer, "Reverse64_32x2"); return;
#else
      case Iop_Reverse8sIn16_x4:	VG_(strcpy)(buffer, "Reverse16_8x8"); return;
      case Iop_Reverse8sIn32_x2:	VG_(strcpy)(buffer, "Reverse32_8x8"); return;
      case Iop_Reverse16sIn32_x2: VG_(strcpy)(buffer, "Reverse32_16x4"); return;
      case Iop_Reverse8sIn64_x1:	VG_(strcpy)(buffer, "Reverse64_8x8"); return;
      case Iop_Reverse16sIn64_x1:	VG_(strcpy)(buffer, "Reverse64_16x4"); return;
      case Iop_Reverse32sIn64_x1:	VG_(strcpy)(buffer, "Reverse64_32x2"); return;
#endif
      case Iop_Abs32Fx2: VG_(strcpy)(buffer, "Abs32Fx2"); return;

      case Iop_CmpNEZ32x2: VG_(strcpy)(buffer, "CmpNEZ32x2"); return;
      case Iop_CmpNEZ16x4: VG_(strcpy)(buffer, "CmpNEZ16x4"); return;
      case Iop_CmpNEZ8x8:  VG_(strcpy)(buffer, "CmpNEZ8x8"); return;

      case Iop_Add32Fx4:  VG_(strcpy)(buffer, "Add32Fx4"); return;
      case Iop_Add32Fx2:  VG_(strcpy)(buffer, "Add32Fx2"); return;
      case Iop_Add32F0x4: VG_(strcpy)(buffer, "Add32F0x4"); return;
      case Iop_Add64Fx2:  VG_(strcpy)(buffer, "Add64Fx2"); return;
      case Iop_Add64F0x2: VG_(strcpy)(buffer, "Add64F0x2"); return;

      case Iop_Div32Fx4:  VG_(strcpy)(buffer, "Div32Fx4"); return;
      case Iop_Div32F0x4: VG_(strcpy)(buffer, "Div32F0x4"); return;
      case Iop_Div64Fx2:  VG_(strcpy)(buffer, "Div64Fx2"); return;
      case Iop_Div64F0x2: VG_(strcpy)(buffer, "Div64F0x2"); return;

      case Iop_Max32Fx8:  VG_(strcpy)(buffer, "Max32Fx8"); return;
      case Iop_Max32Fx4:  VG_(strcpy)(buffer, "Max32Fx4"); return;
      case Iop_Max32Fx2:  VG_(strcpy)(buffer, "Max32Fx2"); return;
      case Iop_PwMax32Fx4:  VG_(strcpy)(buffer, "PwMax32Fx4"); return;
      case Iop_PwMax32Fx2:  VG_(strcpy)(buffer, "PwMax32Fx2"); return;
      case Iop_Max32F0x4: VG_(strcpy)(buffer, "Max32F0x4"); return;
      case Iop_Max64Fx4:  VG_(strcpy)(buffer, "Max64Fx4"); return;
      case Iop_Max64Fx2:  VG_(strcpy)(buffer, "Max64Fx2"); return;
      case Iop_Max64F0x2: VG_(strcpy)(buffer, "Max64F0x2"); return;

      case Iop_Min32Fx8:  VG_(strcpy)(buffer, "Min32Fx8"); return;
      case Iop_Min32Fx4:  VG_(strcpy)(buffer, "Min32Fx4"); return;
      case Iop_Min32Fx2:  VG_(strcpy)(buffer, "Min32Fx2"); return;
      case Iop_PwMin32Fx4:  VG_(strcpy)(buffer, "PwMin32Fx4"); return;
      case Iop_PwMin32Fx2:  VG_(strcpy)(buffer, "PwMin32Fx2"); return;
      case Iop_Min32F0x4: VG_(strcpy)(buffer, "Min32F0x4"); return;
      case Iop_Min64Fx4:  VG_(strcpy)(buffer, "Min64Fx4"); return;
      case Iop_Min64Fx2:  VG_(strcpy)(buffer, "Min64Fx2"); return;
      case Iop_Min64F0x2: VG_(strcpy)(buffer, "Min64F0x2"); return;

      case Iop_Mul32Fx4:  VG_(strcpy)(buffer, "Mul32Fx4"); return;
      case Iop_Mul32F0x4: VG_(strcpy)(buffer, "Mul32F0x4"); return;
      case Iop_Mul64Fx2:  VG_(strcpy)(buffer, "Mul64Fx2"); return;
      case Iop_Mul64F0x2: VG_(strcpy)(buffer, "Mul64F0x2"); return;

#ifdef T380
      case Iop_Recip32x2: VG_(strcpy)(buffer, "Recip32x2"); return;
      case Iop_Recip32Fx2:  VG_(strcpy)(buffer, "Recip32Fx2"); return;
      case Iop_Recip32Fx4:  VG_(strcpy)(buffer, "Recip32Fx4"); return;
      case Iop_Recip32Fx8:  VG_(strcpy)(buffer, "Recip32Fx8"); return;
      case Iop_Recip32x4:  VG_(strcpy)(buffer, "Recip32x4"); return;
      case Iop_Recip32F0x4: VG_(strcpy)(buffer, "Recip32F0x4"); return;
      case Iop_Recip64Fx2:  VG_(strcpy)(buffer, "Recip64Fx2"); return;
      case Iop_Recip64F0x2: VG_(strcpy)(buffer, "Recip64F0x2"); return;
      case Iop_Recps32Fx2:  VG_(strcpy)(buffer, "VRecps32Fx2"); return;
      case Iop_Recps32Fx4:  VG_(strcpy)(buffer, "VRecps32Fx4"); return;
#else
      case Iop_RecipEst32Ux2:		VG_(strcpy)(buffer, "Recip32x2"); return;
      case Iop_RecipEst32Fx2:		VG_(strcpy)(buffer, "Recip32Fx2"); return;
      case Iop_RecipEst32Fx4:		VG_(strcpy)(buffer, "Recip32Fx4"); return;
      case Iop_RecipEst32Fx8:		VG_(strcpy)(buffer, "Recip32Fx8"); return;
      case Iop_RecipEst32Ux4:		VG_(strcpy)(buffer, "Recip32x4"); return;
      case Iop_RecipEst32F0x4:	VG_(strcpy)(buffer, "Recip32F0x4"); return;
      case Iop_RecipEst64Fx2:		VG_(strcpy)(buffer, "Recip64Fx2"); return;
      //case Iop_RecipEst64F0x2:	VG_(strcpy)(buffer, "Recip64F0x2"); return;
      case Iop_RecipStep32Fx2:	VG_(strcpy)(buffer, "VRecps32Fx2"); return;
      case Iop_RecipStep32Fx4:	VG_(strcpy)(buffer, "VRecps32Fx4"); return;
#endif
      case Iop_Abs32Fx4:  VG_(strcpy)(buffer, "Abs32Fx4"); return;
#ifdef T380
      case Iop_Rsqrts32Fx4:  VG_(strcpy)(buffer, "VRsqrts32Fx4"); return;
      case Iop_Rsqrts32Fx2:  VG_(strcpy)(buffer, "VRsqrts32Fx2"); return;
      case Iop_RSqrt32Fx4:  VG_(strcpy)(buffer, "RSqrt32Fx4"); return;
      case Iop_RSqrt32F0x4: VG_(strcpy)(buffer, "RSqrt32F0x4"); return;
      case Iop_RSqrt32Fx8:  VG_(strcpy)(buffer, "RSqrt32Fx8"); return;
      case Iop_RSqrt64Fx2:  VG_(strcpy)(buffer, "RSqrt64Fx2"); return;
      case Iop_RSqrt64F0x2: VG_(strcpy)(buffer, "RSqrt64F0x2"); return;
#else
      case Iop_RSqrtStep32Fx4:  VG_(strcpy)(buffer, "VRsqrts32Fx4"); return;
      case Iop_RSqrtStep32Fx2:  VG_(strcpy)(buffer, "VRsqrts32Fx2"); return;
      //case Iop_RSqrtEst32Fx4:  VG_(strcpy)(buffer, "RSqrt32Fx4"); return;
      case Iop_RSqrtEst32F0x4: VG_(strcpy)(buffer, "RSqrt32F0x4"); return;
      case Iop_RSqrtEst32Fx8:  VG_(strcpy)(buffer, "RSqrt32Fx8"); return;
      case Iop_RSqrtEst64Fx2:  VG_(strcpy)(buffer, "RSqrt64Fx2"); return;
      //case Iop_RSqrtEst64F0x2: VG_(strcpy)(buffer, "RSqrt64F0x2"); return;
#endif

      case Iop_Sqrt32Fx4:  VG_(strcpy)(buffer, "Sqrt32Fx4"); return;
      case Iop_Sqrt32F0x4: VG_(strcpy)(buffer, "Sqrt32F0x4"); return;
      case Iop_Sqrt64Fx2:  VG_(strcpy)(buffer, "Sqrt64Fx2"); return;
      case Iop_Sqrt64F0x2: VG_(strcpy)(buffer, "Sqrt64F0x2"); return;
      case Iop_Sqrt32Fx8:  VG_(strcpy)(buffer, "Sqrt32Fx8"); return;
      case Iop_Sqrt64Fx4:  VG_(strcpy)(buffer, "Sqrt64Fx4"); return;

      case Iop_Sub32Fx4:  VG_(strcpy)(buffer, "Sub32Fx4"); return;
      case Iop_Sub32Fx2:  VG_(strcpy)(buffer, "Sub32Fx2"); return;
      case Iop_Sub32F0x4: VG_(strcpy)(buffer, "Sub32F0x4"); return;
      case Iop_Sub64Fx2:  VG_(strcpy)(buffer, "Sub64Fx2"); return;
      case Iop_Sub64F0x2: VG_(strcpy)(buffer, "Sub64F0x2"); return;

      case Iop_CmpEQ32Fx4: VG_(strcpy)(buffer, "CmpEQ32Fx4"); return;
      case Iop_CmpLT32Fx4: VG_(strcpy)(buffer, "CmpLT32Fx4"); return;
      case Iop_CmpLE32Fx4: VG_(strcpy)(buffer, "CmpLE32Fx4"); return;
      case Iop_CmpGT32Fx4: VG_(strcpy)(buffer, "CmpGT32Fx4"); return;
      case Iop_CmpGE32Fx4: VG_(strcpy)(buffer, "CmpGE32Fx4"); return;
      case Iop_CmpUN32Fx4: VG_(strcpy)(buffer, "CmpUN32Fx4"); return;
      case Iop_CmpEQ64Fx2: VG_(strcpy)(buffer, "CmpEQ64Fx2"); return;
      case Iop_CmpLT64Fx2: VG_(strcpy)(buffer, "CmpLT64Fx2"); return;
      case Iop_CmpLE64Fx2: VG_(strcpy)(buffer, "CmpLE64Fx2"); return;
      case Iop_CmpUN64Fx2: VG_(strcpy)(buffer, "CmpUN64Fx2"); return;
      case Iop_CmpGT32Fx2: VG_(strcpy)(buffer, "CmpGT32Fx2"); return;
      case Iop_CmpEQ32Fx2: VG_(strcpy)(buffer, "CmpEQ32Fx2"); return;
      case Iop_CmpGE32Fx2: VG_(strcpy)(buffer, "CmpGE32Fx2"); return;

      case Iop_CmpEQ32F0x4: VG_(strcpy)(buffer, "CmpEQ32F0x4"); return;
      case Iop_CmpLT32F0x4: VG_(strcpy)(buffer, "CmpLT32F0x4"); return;
      case Iop_CmpLE32F0x4: VG_(strcpy)(buffer, "CmpLE32F0x4"); return;
      case Iop_CmpUN32F0x4: VG_(strcpy)(buffer, "CmpUN32F0x4"); return;
      case Iop_CmpEQ64F0x2: VG_(strcpy)(buffer, "CmpEQ64F0x2"); return;
      case Iop_CmpLT64F0x2: VG_(strcpy)(buffer, "CmpLT64F0x2"); return;
      case Iop_CmpLE64F0x2: VG_(strcpy)(buffer, "CmpLE64F0x2"); return;
      case Iop_CmpUN64F0x2: VG_(strcpy)(buffer, "CmpUN64F0x2"); return;

      case Iop_Neg32Fx4: VG_(strcpy)(buffer, "Neg32Fx4"); return;
      case Iop_Neg32Fx2: VG_(strcpy)(buffer, "Neg32Fx2"); return;

      case Iop_V128to64:   VG_(strcpy)(buffer, "V128to64");   return;
      case Iop_V128HIto64: VG_(strcpy)(buffer, "V128HIto64"); return;
      case Iop_64HLtoV128: VG_(strcpy)(buffer, "64HLtoV128"); return;

      case Iop_64UtoV128:   VG_(strcpy)(buffer, "64UtoV128"); return;
      case Iop_SetV128lo64: VG_(strcpy)(buffer, "SetV128lo64"); return;

      case Iop_32UtoV128:   VG_(strcpy)(buffer, "32UtoV128"); return;
      case Iop_V128to32:    VG_(strcpy)(buffer, "V128to32"); return;
      case Iop_SetV128lo32: VG_(strcpy)(buffer, "SetV128lo32"); return;

      case Iop_Dup8x16: VG_(strcpy)(buffer, "Dup8x16"); return;
      case Iop_Dup16x8: VG_(strcpy)(buffer, "Dup16x8"); return;
      case Iop_Dup32x4: VG_(strcpy)(buffer, "Dup32x4"); return;
      case Iop_Dup8x8: VG_(strcpy)(buffer, "Dup8x8"); return;
      case Iop_Dup16x4: VG_(strcpy)(buffer, "Dup16x4"); return;
      case Iop_Dup32x2: VG_(strcpy)(buffer, "Dup32x2"); return;

      case Iop_NotV128:    VG_(strcpy)(buffer, "NotV128"); return;
      case Iop_AndV128:    VG_(strcpy)(buffer, "AndV128"); return;
      case Iop_OrV128:     VG_(strcpy)(buffer, "OrV128");  return;
      case Iop_XorV128:    VG_(strcpy)(buffer, "XorV128"); return;

      case Iop_CmpNEZ8x16: VG_(strcpy)(buffer, "CmpNEZ8x16"); return;
      case Iop_CmpNEZ16x8: VG_(strcpy)(buffer, "CmpNEZ16x8"); return;
      case Iop_CmpNEZ32x4: VG_(strcpy)(buffer, "CmpNEZ32x4"); return;
      case Iop_CmpNEZ64x2: VG_(strcpy)(buffer, "CmpNEZ64x2"); return;

      case Iop_Abs8x16: VG_(strcpy)(buffer, "Abs8x16"); return;
      case Iop_Abs16x8: VG_(strcpy)(buffer, "Abs16x8"); return;
      case Iop_Abs32x4: VG_(strcpy)(buffer, "Abs32x4"); return;

      case Iop_Add8x16:   VG_(strcpy)(buffer, "Add8x16"); return;
      case Iop_Add16x8:   VG_(strcpy)(buffer, "Add16x8"); return;
      case Iop_Add32x4:   VG_(strcpy)(buffer, "Add32x4"); return;
      case Iop_Add64x2:   VG_(strcpy)(buffer, "Add64x2"); return;
      case Iop_QAdd8Ux16: VG_(strcpy)(buffer, "QAdd8Ux16"); return;
      case Iop_QAdd16Ux8: VG_(strcpy)(buffer, "QAdd16Ux8"); return;
      case Iop_QAdd32Ux4: VG_(strcpy)(buffer, "QAdd32Ux4"); return;
      case Iop_QAdd8Sx16: VG_(strcpy)(buffer, "QAdd8Sx16"); return;
      case Iop_QAdd16Sx8: VG_(strcpy)(buffer, "QAdd16Sx8"); return;
      case Iop_QAdd32Sx4: VG_(strcpy)(buffer, "QAdd32Sx4"); return;
      case Iop_QAdd64Ux2: VG_(strcpy)(buffer, "QAdd64Ux2"); return;
      case Iop_QAdd64Sx2: VG_(strcpy)(buffer, "QAdd64Sx2"); return;
      case Iop_PwAdd8x16: VG_(strcpy)(buffer, "PwAdd8x16"); return;
      case Iop_PwAdd16x8: VG_(strcpy)(buffer, "PwAdd16x8"); return;
      case Iop_PwAdd32x4: VG_(strcpy)(buffer, "PwAdd32x4"); return;
      case Iop_PwAddL8Ux16: VG_(strcpy)(buffer, "PwAddL8Ux16"); return;
      case Iop_PwAddL16Ux8: VG_(strcpy)(buffer, "PwAddL16Ux8"); return;
      case Iop_PwAddL32Ux4: VG_(strcpy)(buffer, "PwAddL32Ux4"); return;
      case Iop_PwAddL8Sx16: VG_(strcpy)(buffer, "PwAddL8Sx16"); return;
      case Iop_PwAddL16Sx8: VG_(strcpy)(buffer, "PwAddL16Sx8"); return;
      case Iop_PwAddL32Sx4: VG_(strcpy)(buffer, "PwAddL32Sx4"); return;

      case Iop_Sub8x16:   VG_(strcpy)(buffer, "Sub8x16"); return;
      case Iop_Sub16x8:   VG_(strcpy)(buffer, "Sub16x8"); return;
      case Iop_Sub32x4:   VG_(strcpy)(buffer, "Sub32x4"); return;
      case Iop_Sub64x2:   VG_(strcpy)(buffer, "Sub64x2"); return;
      case Iop_QSub8Ux16: VG_(strcpy)(buffer, "QSub8Ux16"); return;
      case Iop_QSub16Ux8: VG_(strcpy)(buffer, "QSub16Ux8"); return;
      case Iop_QSub32Ux4: VG_(strcpy)(buffer, "QSub32Ux4"); return;
      case Iop_QSub8Sx16: VG_(strcpy)(buffer, "QSub8Sx16"); return;
      case Iop_QSub16Sx8: VG_(strcpy)(buffer, "QSub16Sx8"); return;
      case Iop_QSub32Sx4: VG_(strcpy)(buffer, "QSub32Sx4"); return;
      case Iop_QSub64Ux2: VG_(strcpy)(buffer, "QSub64Ux2"); return;
      case Iop_QSub64Sx2: VG_(strcpy)(buffer, "QSub64Sx2"); return;

      case Iop_Mul8x16:    VG_(strcpy)(buffer, "Mul8x16"); return;
      case Iop_Mul16x8:    VG_(strcpy)(buffer, "Mul16x8"); return;
      case Iop_Mul32x4:    VG_(strcpy)(buffer, "Mul32x4"); return;
      case Iop_Mull8Ux8:    VG_(strcpy)(buffer, "Mull8Ux8"); return;
      case Iop_Mull8Sx8:    VG_(strcpy)(buffer, "Mull8Sx8"); return;
      case Iop_Mull16Ux4:    VG_(strcpy)(buffer, "Mull16Ux4"); return;
      case Iop_Mull16Sx4:    VG_(strcpy)(buffer, "Mull16Sx4"); return;
      case Iop_Mull32Ux2:    VG_(strcpy)(buffer, "Mull32Ux2"); return;
      case Iop_Mull32Sx2:    VG_(strcpy)(buffer, "Mull32Sx2"); return;
      case Iop_PolynomialMul8x16: VG_(strcpy)(buffer, "PolynomialMul8x16"); return;
      case Iop_PolynomialMull8x8: VG_(strcpy)(buffer, "PolynomialMull8x8"); return;
      case Iop_MulHi16Ux8: VG_(strcpy)(buffer, "MulHi16Ux8"); return;
      case Iop_MulHi32Ux4: VG_(strcpy)(buffer, "MulHi32Ux4"); return;
      case Iop_MulHi16Sx8: VG_(strcpy)(buffer, "MulHi16Sx8"); return;
      case Iop_MulHi32Sx4: VG_(strcpy)(buffer, "MulHi32Sx4"); return;
      case Iop_QDMulHi16Sx8: VG_(strcpy)(buffer, "QDMulHi16Sx8"); return;
      case Iop_QDMulHi32Sx4: VG_(strcpy)(buffer, "QDMulHi32Sx4"); return;
      case Iop_QRDMulHi16Sx8: VG_(strcpy)(buffer, "QRDMulHi16Sx8"); return;
      case Iop_QRDMulHi32Sx4: VG_(strcpy)(buffer, "QRDMulHi32Sx4"); return;

      case Iop_MullEven8Ux16: VG_(strcpy)(buffer, "MullEven8Ux16"); return;
      case Iop_MullEven16Ux8: VG_(strcpy)(buffer, "MullEven16Ux8"); return;
      case Iop_MullEven8Sx16: VG_(strcpy)(buffer, "MullEven8Sx16"); return;
      case Iop_MullEven16Sx8: VG_(strcpy)(buffer, "MullEven16Sx8"); return;

      case Iop_Avg8Ux16: VG_(strcpy)(buffer, "Avg8Ux16"); return;
      case Iop_Avg16Ux8: VG_(strcpy)(buffer, "Avg16Ux8"); return;
      case Iop_Avg32Ux4: VG_(strcpy)(buffer, "Avg32Ux4"); return;
      case Iop_Avg8Sx16: VG_(strcpy)(buffer, "Avg8Sx16"); return;
      case Iop_Avg16Sx8: VG_(strcpy)(buffer, "Avg16Sx8"); return;
      case Iop_Avg32Sx4: VG_(strcpy)(buffer, "Avg32Sx4"); return;

      case Iop_Max8Sx16: VG_(strcpy)(buffer, "Max8Sx16"); return;
      case Iop_Max16Sx8: VG_(strcpy)(buffer, "Max16Sx8"); return;
      case Iop_Max32Sx4: VG_(strcpy)(buffer, "Max32Sx4"); return;
      case Iop_Max8Ux16: VG_(strcpy)(buffer, "Max8Ux16"); return;
      case Iop_Max16Ux8: VG_(strcpy)(buffer, "Max16Ux8"); return;
      case Iop_Max32Ux4: VG_(strcpy)(buffer, "Max32Ux4"); return;

      case Iop_Min8Sx16: VG_(strcpy)(buffer, "Min8Sx16"); return;
      case Iop_Min16Sx8: VG_(strcpy)(buffer, "Min16Sx8"); return;
      case Iop_Min32Sx4: VG_(strcpy)(buffer, "Min32Sx4"); return;
      case Iop_Min8Ux16: VG_(strcpy)(buffer, "Min8Ux16"); return;
      case Iop_Min16Ux8: VG_(strcpy)(buffer, "Min16Ux8"); return;
      case Iop_Min32Ux4: VG_(strcpy)(buffer, "Min32Ux4"); return;

      case Iop_CmpEQ8x16:  VG_(strcpy)(buffer, "CmpEQ8x16"); return;
      case Iop_CmpEQ16x8:  VG_(strcpy)(buffer, "CmpEQ16x8"); return;
      case Iop_CmpEQ32x4:  VG_(strcpy)(buffer, "CmpEQ32x4"); return;
      case Iop_CmpEQ64x2:  VG_(strcpy)(buffer, "CmpEQ64x2"); return;
      case Iop_CmpGT8Sx16: VG_(strcpy)(buffer, "CmpGT8Sx16"); return;
      case Iop_CmpGT16Sx8: VG_(strcpy)(buffer, "CmpGT16Sx8"); return;
      case Iop_CmpGT32Sx4: VG_(strcpy)(buffer, "CmpGT32Sx4"); return;
      case Iop_CmpGT64Sx2: VG_(strcpy)(buffer, "CmpGT64Sx2"); return;
      case Iop_CmpGT8Ux16: VG_(strcpy)(buffer, "CmpGT8Ux16"); return;
      case Iop_CmpGT16Ux8: VG_(strcpy)(buffer, "CmpGT16Ux8"); return;
      case Iop_CmpGT32Ux4: VG_(strcpy)(buffer, "CmpGT32Ux4"); return;

      case Iop_Cnt8x16: VG_(strcpy)(buffer, "Cnt8x16"); return;
#ifdef T380
      case Iop_Clz8Sx16: VG_(strcpy)(buffer, "Clz8Sx16"); return;
      case Iop_Clz16Sx8: VG_(strcpy)(buffer, "Clz16Sx8"); return;
      case Iop_Clz32Sx4: VG_(strcpy)(buffer, "Clz32Sx4"); return;
      case Iop_Cls8Sx16: VG_(strcpy)(buffer, "Cls8Sx16"); return;
      case Iop_Cls16Sx8: VG_(strcpy)(buffer, "Cls16Sx8"); return;
      case Iop_Cls32Sx4: VG_(strcpy)(buffer, "Cls32Sx4"); return;
#else
      case Iop_Clz8x16: VG_(strcpy)(buffer, "Clz8Sx16"); return;
      case Iop_Clz16x8: VG_(strcpy)(buffer, "Clz16Sx8"); return;
      case Iop_Clz32x4: VG_(strcpy)(buffer, "Clz32Sx4"); return;
      case Iop_Cls8x16: VG_(strcpy)(buffer, "Cls8Sx16"); return;
      case Iop_Cls16x8: VG_(strcpy)(buffer, "Cls16Sx8"); return;
      case Iop_Cls32x4: VG_(strcpy)(buffer, "Cls32Sx4"); return;
#endif

      case Iop_ShlV128: VG_(strcpy)(buffer, "ShlV128"); return;
      case Iop_ShrV128: VG_(strcpy)(buffer, "ShrV128"); return;

      case Iop_ShlN8x16: VG_(strcpy)(buffer, "ShlN8x16"); return;
      case Iop_ShlN16x8: VG_(strcpy)(buffer, "ShlN16x8"); return;
      case Iop_ShlN32x4: VG_(strcpy)(buffer, "ShlN32x4"); return;
      case Iop_ShlN64x2: VG_(strcpy)(buffer, "ShlN64x2"); return;
      case Iop_ShrN8x16: VG_(strcpy)(buffer, "ShrN8x16"); return;
      case Iop_ShrN16x8: VG_(strcpy)(buffer, "ShrN16x8"); return;
      case Iop_ShrN32x4: VG_(strcpy)(buffer, "ShrN32x4"); return;
      case Iop_ShrN64x2: VG_(strcpy)(buffer, "ShrN64x2"); return;
      case Iop_SarN8x16: VG_(strcpy)(buffer, "SarN8x16"); return;
      case Iop_SarN16x8: VG_(strcpy)(buffer, "SarN16x8"); return;
      case Iop_SarN32x4: VG_(strcpy)(buffer, "SarN32x4"); return;
      case Iop_SarN64x2: VG_(strcpy)(buffer, "SarN64x2"); return;

      case Iop_Shl8x16: VG_(strcpy)(buffer, "Shl8x16"); return;
      case Iop_Shl16x8: VG_(strcpy)(buffer, "Shl16x8"); return;
      case Iop_Shl32x4: VG_(strcpy)(buffer, "Shl32x4"); return;
      case Iop_Shl64x2: VG_(strcpy)(buffer, "Shl64x2"); return;
      case Iop_QSal8x16: VG_(strcpy)(buffer, "QSal8x16"); return;
      case Iop_QSal16x8: VG_(strcpy)(buffer, "QSal16x8"); return;
      case Iop_QSal32x4: VG_(strcpy)(buffer, "QSal32x4"); return;
      case Iop_QSal64x2: VG_(strcpy)(buffer, "QSal64x2"); return;
      case Iop_QShl8x16: VG_(strcpy)(buffer, "QShl8x16"); return;
      case Iop_QShl16x8: VG_(strcpy)(buffer, "QShl16x8"); return;
      case Iop_QShl32x4: VG_(strcpy)(buffer, "QShl32x4"); return;
      case Iop_QShl64x2: VG_(strcpy)(buffer, "QShl64x2"); return;
#ifdef T380
      case Iop_QSalN8x16: VG_(strcpy)(buffer, "QSalN8x16"); return;
      case Iop_QSalN16x8: VG_(strcpy)(buffer, "QSalN16x8"); return;
      case Iop_QSalN32x4: VG_(strcpy)(buffer, "QSalN32x4"); return;
      case Iop_QSalN64x2: VG_(strcpy)(buffer, "QSalN64x2"); return;
      case Iop_QShlN8x16: VG_(strcpy)(buffer, "QShlN8x16"); return;
      case Iop_QShlN16x8: VG_(strcpy)(buffer, "QShlN16x8"); return;
      case Iop_QShlN32x4: VG_(strcpy)(buffer, "QShlN32x4"); return;
      case Iop_QShlN64x2: VG_(strcpy)(buffer, "QShlN64x2"); return;
      case Iop_QShlN8Sx16: VG_(strcpy)(buffer, "QShlN8Sx16"); return;
      case Iop_QShlN16Sx8: VG_(strcpy)(buffer, "QShlN16Sx8"); return;
      case Iop_QShlN32Sx4: VG_(strcpy)(buffer, "QShlN32Sx4"); return;
      case Iop_QShlN64Sx2: VG_(strcpy)(buffer, "QShlN64Sx2"); return;
#else
      case Iop_QShlNsatSU8x16: VG_(strcpy)(buffer, "QShlN8Sx16"); return;
      case Iop_QShlNsatSU16x8: VG_(strcpy)(buffer, "QShlN16Sx8"); return;
      case Iop_QShlNsatSU32x4: VG_(strcpy)(buffer, "QShlN32Sx4"); return;
      case Iop_QShlNsatSU64x2: VG_(strcpy)(buffer, "QShlN64Sx2"); return;
      
			case Iop_QShlNsatUU8x16: VG_(strcpy)(buffer, "QShlN8x16"); return;
      case Iop_QShlNsatUU16x8: VG_(strcpy)(buffer, "QShlN16x8"); return;
      case Iop_QShlNsatUU32x4: VG_(strcpy)(buffer, "QShlN32x4"); return;
      case Iop_QShlNsatUU64x2: VG_(strcpy)(buffer, "QShlN64x2"); return;
      
			case Iop_QShlNsatSS8x16: VG_(strcpy)(buffer, "QSalN8x16"); return;
      case Iop_QShlNsatSS16x8: VG_(strcpy)(buffer, "QSalN16x8"); return;
      case Iop_QShlNsatSS32x4: VG_(strcpy)(buffer, "QSalN32x4"); return;
      case Iop_QShlNsatSS64x2: VG_(strcpy)(buffer, "QSalN64x2"); return;
#endif
      case Iop_Shr8x16: VG_(strcpy)(buffer, "Shr8x16"); return;
      case Iop_Shr16x8: VG_(strcpy)(buffer, "Shr16x8"); return;
      case Iop_Shr32x4: VG_(strcpy)(buffer, "Shr32x4"); return;
      case Iop_Shr64x2: VG_(strcpy)(buffer, "Shr64x2"); return;
      case Iop_Sar8x16: VG_(strcpy)(buffer, "Sar8x16"); return;
      case Iop_Sar16x8: VG_(strcpy)(buffer, "Sar16x8"); return;
      case Iop_Sar32x4: VG_(strcpy)(buffer, "Sar32x4"); return;
      case Iop_Sar64x2: VG_(strcpy)(buffer, "Sar64x2"); return;
      case Iop_Sal8x16: VG_(strcpy)(buffer, "Sal8x16"); return;
      case Iop_Sal16x8: VG_(strcpy)(buffer, "Sal16x8"); return;
      case Iop_Sal32x4: VG_(strcpy)(buffer, "Sal32x4"); return;
      case Iop_Sal64x2: VG_(strcpy)(buffer, "Sal64x2"); return;
      case Iop_Rol8x16: VG_(strcpy)(buffer, "Rol8x16"); return;
      case Iop_Rol16x8: VG_(strcpy)(buffer, "Rol16x8"); return;
      case Iop_Rol32x4: VG_(strcpy)(buffer, "Rol32x4"); return;

      case Iop_NarrowBin16to8x16:    VG_(strcpy)(buffer, "NarrowBin16to8x16"); return;
      case Iop_NarrowBin32to16x8:    VG_(strcpy)(buffer, "NarrowBin32to16x8"); return;
      case Iop_QNarrowBin16Uto8Ux16: VG_(strcpy)(buffer, "QNarrowBin16Uto8Ux16"); return;
      case Iop_QNarrowBin32Sto16Ux8: VG_(strcpy)(buffer, "QNarrowBin32Sto16Ux8"); return;
      case Iop_QNarrowBin16Sto8Ux16: VG_(strcpy)(buffer, "QNarrowBin16Sto8Ux16"); return;
      case Iop_QNarrowBin32Uto16Ux8: VG_(strcpy)(buffer, "QNarrowBin32Uto16Ux8"); return;
      case Iop_QNarrowBin16Sto8Sx16: VG_(strcpy)(buffer, "QNarrowBin16Sto8Sx16"); return;
      case Iop_QNarrowBin32Sto16Sx8: VG_(strcpy)(buffer, "QNarrowBin32Sto16Sx8"); return;
      case Iop_NarrowUn16to8x8:     VG_(strcpy)(buffer, "NarrowUn16to8x8");  return;
      case Iop_NarrowUn32to16x4:    VG_(strcpy)(buffer, "NarrowUn32to16x4"); return;
      case Iop_NarrowUn64to32x2:    VG_(strcpy)(buffer, "NarrowUn64to32x2"); return;
      case Iop_QNarrowUn16Uto8Ux8:  VG_(strcpy)(buffer, "QNarrowUn16Uto8Ux8");  return;
      case Iop_QNarrowUn32Uto16Ux4: VG_(strcpy)(buffer, "QNarrowUn32Uto16Ux4"); return;
      case Iop_QNarrowUn64Uto32Ux2: VG_(strcpy)(buffer, "QNarrowUn64Uto32Ux2"); return;
      case Iop_QNarrowUn16Sto8Sx8:  VG_(strcpy)(buffer, "QNarrowUn16Sto8Sx8");  return;
      case Iop_QNarrowUn32Sto16Sx4: VG_(strcpy)(buffer, "QNarrowUn32Sto16Sx4"); return;
      case Iop_QNarrowUn64Sto32Sx2: VG_(strcpy)(buffer, "QNarrowUn64Sto32Sx2"); return;
      case Iop_QNarrowUn16Sto8Ux8:  VG_(strcpy)(buffer, "QNarrowUn16Sto8Ux8");  return;
      case Iop_QNarrowUn32Sto16Ux4: VG_(strcpy)(buffer, "QNarrowUn32Sto16Ux4"); return;
      case Iop_QNarrowUn64Sto32Ux2: VG_(strcpy)(buffer, "QNarrowUn64Sto32Ux2"); return;
      case Iop_Widen8Uto16x8:  VG_(strcpy)(buffer, "Widen8Uto16x8");  return;
      case Iop_Widen16Uto32x4: VG_(strcpy)(buffer, "Widen16Uto32x4"); return;
      case Iop_Widen32Uto64x2: VG_(strcpy)(buffer, "Widen32Uto64x2"); return;
      case Iop_Widen8Sto16x8:  VG_(strcpy)(buffer, "Widen8Sto16x8");  return;
      case Iop_Widen16Sto32x4: VG_(strcpy)(buffer, "Widen16Sto32x4"); return;
      case Iop_Widen32Sto64x2: VG_(strcpy)(buffer, "Widen32Sto64x2"); return;

      case Iop_InterleaveHI8x16: VG_(strcpy)(buffer, "InterleaveHI8x16"); return;
      case Iop_InterleaveHI16x8: VG_(strcpy)(buffer, "InterleaveHI16x8"); return;
      case Iop_InterleaveHI32x4: VG_(strcpy)(buffer, "InterleaveHI32x4"); return;
      case Iop_InterleaveHI64x2: VG_(strcpy)(buffer, "InterleaveHI64x2"); return;
      case Iop_InterleaveLO8x16: VG_(strcpy)(buffer, "InterleaveLO8x16"); return;
      case Iop_InterleaveLO16x8: VG_(strcpy)(buffer, "InterleaveLO16x8"); return;
      case Iop_InterleaveLO32x4: VG_(strcpy)(buffer, "InterleaveLO32x4"); return;
      case Iop_InterleaveLO64x2: VG_(strcpy)(buffer, "InterleaveLO64x2"); return;

      case Iop_CatOddLanes8x16: VG_(strcpy)(buffer, "CatOddLanes8x16"); return;
      case Iop_CatOddLanes16x8: VG_(strcpy)(buffer, "CatOddLanes16x8"); return;
      case Iop_CatOddLanes32x4: VG_(strcpy)(buffer, "CatOddLanes32x4"); return;
      case Iop_CatEvenLanes8x16: VG_(strcpy)(buffer, "CatEvenLanes8x16"); return;
      case Iop_CatEvenLanes16x8: VG_(strcpy)(buffer, "CatEvenLanes16x8"); return;
      case Iop_CatEvenLanes32x4: VG_(strcpy)(buffer, "CatEvenLanes32x4"); return;

      case Iop_InterleaveOddLanes8x16: VG_(strcpy)(buffer, "InterleaveOddLanes8x16"); return;
      case Iop_InterleaveOddLanes16x8: VG_(strcpy)(buffer, "InterleaveOddLanes16x8"); return;
      case Iop_InterleaveOddLanes32x4: VG_(strcpy)(buffer, "InterleaveOddLanes32x4"); return;
      case Iop_InterleaveEvenLanes8x16: VG_(strcpy)(buffer, "InterleaveEvenLanes8x16"); return;
      case Iop_InterleaveEvenLanes16x8: VG_(strcpy)(buffer, "InterleaveEvenLanes16x8"); return;
      case Iop_InterleaveEvenLanes32x4: VG_(strcpy)(buffer, "InterleaveEvenLanes32x4"); return;

      case Iop_GetElem8x16: VG_(strcpy)(buffer, "GetElem8x16"); return;
      case Iop_GetElem16x8: VG_(strcpy)(buffer, "GetElem16x8"); return;
      case Iop_GetElem32x4: VG_(strcpy)(buffer, "GetElem32x4"); return;
      case Iop_GetElem64x2: VG_(strcpy)(buffer, "GetElem64x2"); return;

      case Iop_GetElem8x8: VG_(strcpy)(buffer, "GetElem8x8"); return;
      case Iop_GetElem16x4: VG_(strcpy)(buffer, "GetElem16x4"); return;
      case Iop_GetElem32x2: VG_(strcpy)(buffer, "GetElem32x2"); return;
      case Iop_SetElem8x8: VG_(strcpy)(buffer, "SetElem8x8"); return;
      case Iop_SetElem16x4: VG_(strcpy)(buffer, "SetElem16x4"); return;
      case Iop_SetElem32x2: VG_(strcpy)(buffer, "SetElem32x2"); return;

#ifdef T380
      case Iop_Extract64: VG_(strcpy)(buffer, "Extract64"); return;
      case Iop_ExtractV128: VG_(strcpy)(buffer, "ExtractV128"); return;
#else
      case Iop_Slice64: VG_(strcpy)(buffer, "Extract64"); return;
      case Iop_SliceV128: VG_(strcpy)(buffer, "ExtractV128"); return;
#endif

      case Iop_Perm8x16: VG_(strcpy)(buffer, "Perm8x16"); return;
      case Iop_Perm32x4: VG_(strcpy)(buffer, "Perm32x4"); return;
#ifdef T380
      case Iop_Reverse16_8x16: VG_(strcpy)(buffer, "Reverse16_8x16"); return;
      case Iop_Reverse32_8x16: VG_(strcpy)(buffer, "Reverse32_8x16"); return;
      case Iop_Reverse32_16x8: VG_(strcpy)(buffer, "Reverse32_16x8"); return;
      case Iop_Reverse64_8x16: VG_(strcpy)(buffer, "Reverse64_8x16"); return;
      case Iop_Reverse64_16x8: VG_(strcpy)(buffer, "Reverse64_16x8"); return;
      case Iop_Reverse64_32x4: VG_(strcpy)(buffer, "Reverse64_32x4"); return;
#else
      case Iop_Reverse8sIn16_x8:	VG_(strcpy)(buffer, "Reverse16_8x16"); return;
      case Iop_Reverse8sIn32_x4:	VG_(strcpy)(buffer, "Reverse32_8x16"); return;
      case Iop_Reverse16sIn32_x4: VG_(strcpy)(buffer, "Reverse32_16x8"); return;
      case Iop_Reverse8sIn64_x2:  VG_(strcpy)(buffer, "Reverse64_8x16"); return;
      case Iop_Reverse16sIn64_x2: VG_(strcpy)(buffer, "Reverse64_16x8"); return;
      case Iop_Reverse32sIn64_x2: VG_(strcpy)(buffer, "Reverse64_32x4"); return;
			case Iop_Reverse1sIn8_x16:	VG_(strcmp)(buffer, "Reverse8_8x1"); return;
#endif

      case Iop_F32ToFixed32Ux4_RZ: VG_(strcpy)(buffer, "F32ToFixed32Ux4_RZ"); return;
      case Iop_F32ToFixed32Sx4_RZ: VG_(strcpy)(buffer, "F32ToFixed32Sx4_RZ"); return;
      case Iop_Fixed32UToF32x4_RN: VG_(strcpy)(buffer, "Fixed32UToF32x4_RN"); return;
      case Iop_Fixed32SToF32x4_RN: VG_(strcpy)(buffer, "Fixed32SToF32x4_RN"); return;
      case Iop_F32ToFixed32Ux2_RZ: VG_(strcpy)(buffer, "F32ToFixed32Ux2_RZ"); return;
      case Iop_F32ToFixed32Sx2_RZ: VG_(strcpy)(buffer, "F32ToFixed32Sx2_RZ"); return;
      case Iop_Fixed32UToF32x2_RN: VG_(strcpy)(buffer, "Fixed32UToF32x2_RN"); return;
      case Iop_Fixed32SToF32x2_RN: VG_(strcpy)(buffer, "Fixed32SToF32x2_RN"); return;

      case Iop_D32toD64:  VG_(strcpy)(buffer, "D32toD64");   return;
      case Iop_D64toD32:  VG_(strcpy)(buffer, "D64toD32");   return;
      case Iop_AddD64:  VG_(strcpy)(buffer, "AddD64");   return;
      case Iop_SubD64:  VG_(strcpy)(buffer, "SubD64");   return;
      case Iop_MulD64:  VG_(strcpy)(buffer, "MulD64");   return;
      case Iop_DivD64:  VG_(strcpy)(buffer, "DivD64");   return;
      case Iop_ShlD64:  VG_(strcpy)(buffer, "ShlD64"); return;
      case Iop_ShrD64:  VG_(strcpy)(buffer, "ShrD64"); return;
      case Iop_D64toI64S:  VG_(strcpy)(buffer, "D64toI64S");  return;
      case Iop_I64StoD64:  VG_(strcpy)(buffer, "I64StoD64");  return;
      case Iop_I64StoD128: VG_(strcpy)(buffer, "I64StoD128"); return;
      case Iop_D64toD128:  VG_(strcpy)(buffer, "D64toD128");  return;
      case Iop_D128toD64:  VG_(strcpy)(buffer, "D128toD64");  return;
      case Iop_D128toI64S: VG_(strcpy)(buffer, "D128toI64S"); return;
      case Iop_AddD128: VG_(strcpy)(buffer, "AddD128");  return;
      case Iop_SubD128: VG_(strcpy)(buffer, "SubD128");  return;
      case Iop_MulD128: VG_(strcpy)(buffer, "MulD128");  return;
      case Iop_DivD128: VG_(strcpy)(buffer, "DivD128");  return;
      case Iop_ShlD128: VG_(strcpy)(buffer, "ShlD128");  return;
      case Iop_ShrD128: VG_(strcpy)(buffer, "ShrD128");  return;
      case Iop_RoundD64toInt:  VG_(strcpy)(buffer, "Iop_RoundD64toInt");  return;
      case Iop_RoundD128toInt: VG_(strcpy)(buffer, "Iop_RoundD128toInt"); return;
      case Iop_QuantizeD64:    VG_(strcpy)(buffer, "Iop_QuantizeD64");    return;
      case Iop_QuantizeD128:   VG_(strcpy)(buffer, "Iop_QuantizeD128");   return;
      case Iop_ExtractExpD64:  VG_(strcpy)(buffer, "Iop_ExtractExpD64");  return;
      case Iop_ExtractExpD128: VG_(strcpy)(buffer, "Iop_ExtractExpD128"); return;
      case Iop_InsertExpD64:   VG_(strcpy)(buffer, "Iop_InsertExpD64");   return;
      case Iop_InsertExpD128:  VG_(strcpy)(buffer, "Iop_InsertExpD128");  return;
      case Iop_CmpD64:         VG_(strcpy)(buffer, "CmpD64");    return;
      case Iop_CmpD128:        VG_(strcpy)(buffer, "CmpD128");   return;
      case Iop_D64HLtoD128: VG_(strcpy)(buffer, "D64HLtoD128");  return;
      case Iop_D128HItoD64: VG_(strcpy)(buffer, "D128HItoD64");  return;
      case Iop_D128LOtoD64: VG_(strcpy)(buffer, "D128LOtoD64");  return;
      case Iop_SignificanceRoundD64: VG_(strcpy)(buffer, "Iop_SignificanceRoundD64");
         return;
      case Iop_SignificanceRoundD128: VG_(strcpy)(buffer, "Iop_SignificanceRoundD128");
         return;
      case Iop_ReinterpI64asD64: VG_(strcpy)(buffer, "ReinterpI64asD64"); return;
      case Iop_ReinterpD64asI64: VG_(strcpy)(buffer, "ReinterpD64asI64"); return;
      case Iop_V256to64_0: VG_(strcpy)(buffer, "V256to64_0"); return;
      case Iop_V256to64_1: VG_(strcpy)(buffer, "V256to64_1"); return;
      case Iop_V256to64_2: VG_(strcpy)(buffer, "V256to64_2"); return;
      case Iop_V256to64_3: VG_(strcpy)(buffer, "V256to64_3"); return;
      case Iop_64x4toV256: VG_(strcpy)(buffer, "64x4toV256"); return;
      case Iop_V256toV128_0: VG_(strcpy)(buffer, "V256toV128_0"); return;
      case Iop_V256toV128_1: VG_(strcpy)(buffer, "V256toV128_1"); return;
      case Iop_V128HLtoV256: VG_(strcpy)(buffer, "V128HLtoV256"); return;
      case Iop_DPBtoBCD: VG_(strcpy)(buffer, "DPBtoBCD"); return;
      case Iop_BCDtoDPB: VG_(strcpy)(buffer, "BCDtoDPB"); return;
      case Iop_Add64Fx4: VG_(strcpy)(buffer, "Add64Fx4"); return;
      case Iop_Sub64Fx4: VG_(strcpy)(buffer, "Sub64Fx4"); return;
      case Iop_Mul64Fx4: VG_(strcpy)(buffer, "Mul64Fx4"); return;
      case Iop_Div64Fx4: VG_(strcpy)(buffer, "Div64Fx4"); return;
      case Iop_Add32Fx8: VG_(strcpy)(buffer, "Add32Fx8"); return;
      case Iop_Sub32Fx8: VG_(strcpy)(buffer, "Sub32Fx8"); return;
      case Iop_Mul32Fx8: VG_(strcpy)(buffer, "Mul32Fx8"); return;
      case Iop_Div32Fx8: VG_(strcpy)(buffer, "Div32Fx8"); return;
      case Iop_AndV256: VG_(strcpy)(buffer, "AndV256"); return;
      case Iop_OrV256:  VG_(strcpy)(buffer, "OrV256"); return;
      case Iop_XorV256: VG_(strcpy)(buffer, "XorV256"); return;
      case Iop_NotV256: VG_(strcpy)(buffer, "NotV256"); return;
      case Iop_CmpNEZ64x4: VG_(strcpy)(buffer, "CmpNEZ64x4"); return;
      case Iop_CmpNEZ32x8: VG_(strcpy)(buffer, "CmpNEZ32x8"); return;
      default: vpanic("IROp_to_str(1)");
   }

   // vassert(str);
   switch (op - base) {
      case 0: VG_(strcpy)(buffer, str); VG_(strcat)(buffer, "8"); break;
      case 1: VG_(strcpy)(buffer, str); VG_(strcat)(buffer, "16"); break;
      case 2: VG_(strcpy)(buffer, str); VG_(strcat)(buffer, "32"); break;
      case 3: VG_(strcpy)(buffer, str); VG_(strcat)(buffer, "64"); break;
      default: vpanic("IROp_to_str(2)");
   }
}
