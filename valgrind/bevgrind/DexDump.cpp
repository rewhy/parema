/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The "dexdump" tool is intended to mimic "objdump".  When possible, use
 * similar command-line arguments.
 *
 * TODO: rework the "plain" output format to be more regexp-friendly
 *
 * Differences between XML output and the "current.xml" file:
 * - classes in same package are not all grouped together; generally speaking
 *   nothing is sorted
 * - no "deprecated" on fields and methods
 * - no "value" on fields
 * - no parameter names
 * - no generic signatures on parameters, e.g. type="java.lang.Class&lt;?&gt;"
 * - class shows declared fields and methods; does not show inherited fields
 */

#include "libdex/DexFile.h"

#include "libdex/CmdUtils.h"
#include "libdex/DexCatch.h"
#include "libdex/DexClass.h"
#include "libdex/DexDebugInfo.h"
#include "libdex/DexOpcodes.h"
#include "libdex/DexProto.h"
#include "libdex/InstrUtils.h"
#include "libdex/SysUtil.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>

static const HChar* gProgName = "dexdump";

enum OutputFormat {
	OUTPUT_PLAIN = 0,               /* default */
	OUTPUT_XML,                     /* fancy */
};

/* command-line options */
struct Options {
	Bool checksumOnly;
	Bool disassemble;
	Bool showFileHeaders;
	Bool showSectionHeaders;
	Bool ignoreBadChecksum;
	Bool dumpRegisterMaps;
	OutputFormat outputFormat;
	const HChar* tempFileName;
	Bool exportsOnly;
	Bool verbose;
};

struct Options gOptions;

/* basic info about a field or method */
struct FieldMethodInfo {
	const HChar* classDescriptor;
	const HChar* name;
	const HChar* signature;
};

/*
 * Get 2 little-endian bytes.
 */
static inline UShort get2LE(unsigned HChar const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8);
}

/*
 * Get 4 little-endian bytes.
 */
static inline UInt get4LE(unsigned HChar const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8) | (pSrc[2] << 16) | (pSrc[3] << 24);
}

/*
 * Converts a single-HCharacter primitive type into its human-readable
 * equivalent.
 */
static const HChar* primitiveTypeLabel(HChar typeChar)
{
	switch (typeChar) {
		case 'B':   return "byte";
		case 'C':   return "HChar";
		case 'D':   return "double";
		case 'F':   return "float";
		case 'I':   return "int";
		case 'J':   return "long";
		case 'S':   return "short";
		case 'V':   return "void";
		case 'Z':   return "Boolean";
		default:
								return "UNKNOWN";
	}
}

/*
 * Converts a type descriptor to human-readable "dotted" form.  For
 * example, "Ljava/lang/String;" becomes "java.lang.String", and
 * "[I" becomes "int[]".  Also converts '$' to '.', which means this
 * form can't be converted back to a descriptor.
 */
static HChar* descriptorToDot(const HChar* str)
{
	Int targetLen = strlen(str);
	Int offset = 0;
	Int arrayDepth = 0;
	HChar* newStr;

	/* strip leading [s; will be added to end */
	while (targetLen > 1 && str[offset] == '[') {
		offset++;
		targetLen--;
	}
	arrayDepth = offset;

	if (targetLen == 1) {
		/* primitive type */
		str = primitiveTypeLabel(str[offset]);
		offset = 0;
		targetLen = strlen(str);
	} else {
		/* account for leading 'L' and trailing ';' */
		if (targetLen >= 2 && str[offset] == 'L' &&
				str[offset+targetLen-1] == ';')
		{
			targetLen -= 2;
			offset++;
		}
	}

	newStr = (HChar*)VG_(malloc)(targetLen + arrayDepth * 2 +1);

	/* copy class name over */
	Int i;
	for (i = 0; i < targetLen; i++) {
		HChar ch = str[offset + i];
		newStr[i] = (ch == '/' || ch == '$') ? '.' : ch;
	}

	/* add the appropriate number of brackets for arrays */
	while (arrayDepth-- > 0) {
		newStr[i++] = '[';
		newStr[i++] = ']';
	}
	newStr[i] = '\0';
	assert(i == targetLen + arrayDepth * 2);

	return newStr;
}

/*
 * Converts the class name portion of a type descriptor to human-readable
 * "dotted" form.
 *
 * Returns a newly-allocated string.
 */
static HChar* descriptorClassToDot(const HChar* str)
{
	const HChar* lastSlash;
	HChar* newStr;
	HChar* cp;

	/* reduce to just the class name, trimming trailing ';' */
	lastSlash = strrchr(str, '/');
	if (lastSlash == NULL)
		lastSlash = str + 1;        /* start past 'L' */
	else
		lastSlash++;                /* start past '/' */

	newStr = strdup(lastSlash);
	newStr[strlen(lastSlash)-1] = '\0';
	for (cp = newStr; *cp != '\0'; cp++) {
		if (*cp == '$')
			*cp = '.';
	}

	return newStr;
}

/*
 * Returns a quoted string representing the Boolean value.
 */
static const HChar* quotedBool(Bool val)
{
	if (val)
		return "\"true\"";
	else
		return "\"false\"";
}

static const HChar* quotedVisibility(UInt accessFlags)
{
	if ((accessFlags & ACC_PUBLIC) != 0)
		return "\"public\"";
	else if ((accessFlags & ACC_PROTECTED) != 0)
		return "\"protected\"";
	else if ((accessFlags & ACC_PRIVATE) != 0)
		return "\"private\"";
	else
		return "\"package\"";
}

/*
 * Count the number of '1' bits in a word.
 */
static Int countOnes(UInt val)
{
	Int count = 0;

	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;

	return count;
}

/*
 * Flag for use with createAccessFlagStr().
 */
enum AccessFor {
	kAccessForClass = 0, kAccessForMethod = 1, kAccessForField = 2,
	kAccessForMAX
};

/*
 * Create a new string with human-readable access flags.
 *
 * In the base language the access_flags fields are type UShort; in Dalvik
 * they're UInt.
 */
static HChar* createAccessFlagStr(UInt flags, AccessFor forWhat)
{
#define NUM_FLAGS   18
	static const HChar* kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
		{
			/* class, inner class */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"?",                /* 0x0020 */
			"?",                /* 0x0040 */
			"?",                /* 0x0080 */
			"?",                /* 0x0100 */
			"INTERFACE",        /* 0x0200 */
			"ABSTRACT",         /* 0x0400 */
			"?",                /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"ANNOTATION",       /* 0x2000 */
			"ENUM",             /* 0x4000 */
			"?",                /* 0x8000 */
			"VERIFIED",         /* 0x10000 */
			"OPTIMIZED",        /* 0x20000 */
		},
		{
			/* method */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"SYNCHRONIZED",     /* 0x0020 */
			"BRIDGE",           /* 0x0040 */
			"VARARGS",          /* 0x0080 */
			"NATIVE",           /* 0x0100 */
			"?",                /* 0x0200 */
			"ABSTRACT",         /* 0x0400 */
			"STRICT",           /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"?",                /* 0x2000 */
			"?",                /* 0x4000 */
			"MIRANDA",          /* 0x8000 */
			"CONSTRUCTOR",      /* 0x10000 */
			"DECLARED_SYNCHRONIZED", /* 0x20000 */
		},
		{
			/* field */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"?",                /* 0x0020 */
			"VOLATILE",         /* 0x0040 */
			"TRANSIENT",        /* 0x0080 */
			"?",                /* 0x0100 */
			"?",                /* 0x0200 */
			"?",                /* 0x0400 */
			"?",                /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"?",                /* 0x2000 */
			"ENUM",             /* 0x4000 */
			"?",                /* 0x8000 */
			"?",                /* 0x10000 */
			"?",                /* 0x20000 */
		},
	};
	const Int kLongest = 21;        /* strlen of longest string above */
	Int i, count;
	HChar* str;
	HChar* cp;

	/*
	 * Allocate enough storage to hold the expected number of strings,
	 * plus a space between each.  We over-allocate, using the longest
	 * string above as the base metric.
	 */
	count = countOnes(flags);
	cp = str = (HChar*) VG_(malloc)(count * (kLongest+1) +1);

	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 0x01) {
			const HChar* accessStr = kAccessStrings[forWhat][i];
			Int len = strlen(accessStr);
			if (cp != str)
				*cp++ = ' ';

			memcpy(cp, accessStr, len);
			cp += len;
		}
		flags >>= 1;
	}
	*cp = '\0';

	return str;
}


/*
 * Copy HCharacter data from "data" to "out", converting non-ASCII values
 * to printf format HChars or an ASCII filler ('.' or '?').
 *
 * The output buffer must be able to hold (2*len)+1 bytes.  The result is
 * NUL-terminated.
 */
static void asciify(HChar* out, const unsigned HChar* data, size_t len)
{
	while (len--) {
		if (*data < 0x20) {
			/* could do more here, but we don't need them yet */
			switch (*data) {
				case '\0':
					*out++ = '\\';
					*out++ = '0';
					break;
				case '\n':
					*out++ = '\\';
					*out++ = 'n';
					break;
				default:
					*out++ = '.';
					break;
			}
		} else if (*data >= 0x80) {
			*out++ = '?';
		} else {
			*out++ = *data;
		}
		data++;
	}
	*out = '\0';
}

/*
 * Dump the file header.
 */
void dumpFileHeader(const DexFile* pDexFile)
{
	const DexOptHeader* pOptHeader = pDexFile->pOptHeader;
	const DexHeader* pHeader = pDexFile->pHeader;
	HChar sanitized[sizeof(pHeader->magic)*2 +1];

	assert(sizeof(pHeader->magic) == sizeof(pOptHeader->magic));

	if (pOptHeader != NULL) {
		OAT_LOGI("Optimized DEX file header:\n");

		asciify(sanitized, pOptHeader->magic, sizeof(pOptHeader->magic));
		OAT_LOGI("magic               : '%s'\n", sanitized);
		OAT_LOGI("dex_offset          : %d (0x%06x)\n",
				pOptHeader->dexOffset, pOptHeader->dexOffset);
		OAT_LOGI("dex_length          : %d\n", pOptHeader->dexLength);
		OAT_LOGI("deps_offset         : %d (0x%06x)\n",
				pOptHeader->depsOffset, pOptHeader->depsOffset);
		OAT_LOGI("deps_length         : %d\n", pOptHeader->depsLength);
		OAT_LOGI("opt_offset          : %d (0x%06x)\n",
				pOptHeader->optOffset, pOptHeader->optOffset);
		OAT_LOGI("opt_length          : %d\n", pOptHeader->optLength);
		OAT_LOGI("flags               : %08x\n", pOptHeader->flags);
		OAT_LOGI("checksum            : %08x\n", pOptHeader->checksum);
		OAT_LOGI("\n");
	}

	OAT_LOGI("DEX file header:\n");
	asciify(sanitized, pHeader->magic, sizeof(pHeader->magic));
	OAT_LOGI("magic               : '%s'\n", sanitized);
	OAT_LOGI("checksum            : %08x\n", pHeader->checksum);
	OAT_LOGI("signature           : %02x%02x...%02x%02x\n",
			pHeader->signature[0], pHeader->signature[1],
			pHeader->signature[kSHA1DigestLen-2],
			pHeader->signature[kSHA1DigestLen-1]);
	OAT_LOGI("file_size           : %d\n", pHeader->fileSize);
	OAT_LOGI("header_size         : %d\n", pHeader->headerSize);
	OAT_LOGI("link_size           : %d\n", pHeader->linkSize);
	OAT_LOGI("link_off            : %d (0x%06x)\n",
			pHeader->linkOff, pHeader->linkOff);
	OAT_LOGI("string_ids_size     : %d\n", pHeader->stringIdsSize);
	OAT_LOGI("string_ids_off      : %d (0x%06x)\n",
			pHeader->stringIdsOff, pHeader->stringIdsOff);
	OAT_LOGI("type_ids_size       : %d\n", pHeader->typeIdsSize);
	OAT_LOGI("type_ids_off        : %d (0x%06x)\n",
			pHeader->typeIdsOff, pHeader->typeIdsOff);
	OAT_LOGI("proto_ids_size       : %d\n", pHeader->protoIdsSize);
	OAT_LOGI("proto_ids_off        : %d (0x%06x)\n",
			pHeader->protoIdsOff, pHeader->protoIdsOff);
	OAT_LOGI("field_ids_size      : %d\n", pHeader->fieldIdsSize);
	OAT_LOGI("field_ids_off       : %d (0x%06x)\n",
			pHeader->fieldIdsOff, pHeader->fieldIdsOff);
	OAT_LOGI("method_ids_size     : %d\n", pHeader->methodIdsSize);
	OAT_LOGI("method_ids_off      : %d (0x%06x)\n",
			pHeader->methodIdsOff, pHeader->methodIdsOff);
	OAT_LOGI("class_defs_size     : %d\n", pHeader->classDefsSize);
	OAT_LOGI("class_defs_off      : %d (0x%06x)\n",
			pHeader->classDefsOff, pHeader->classDefsOff);
	OAT_LOGI("data_size           : %d\n", pHeader->dataSize);
	OAT_LOGI("data_off            : %d (0x%06x)\n",
			pHeader->dataOff, pHeader->dataOff);
	OAT_LOGI("\n");
}

/*
 * Dump the "table of contents" for the opt area.
 */
void dumpOptDirectory(const DexFile* pDexFile)
{
	const DexOptHeader* pOptHeader = pDexFile->pOptHeader;
	if (pOptHeader == NULL)
		return;

	OAT_LOGI("OPT section contents:\n");

	const UInt* pOpt = (const UInt*) ((UChar*) pOptHeader + pOptHeader->optOffset);

	if (*pOpt == 0) {
		OAT_LOGI("(1.0 format, only class lookup table is present)\n\n");
		return;
	}

	/*
	 * The "opt" section is in "chunk" format: a 32-bit identifier, a 32-bit
	 * length, then the data.  Chunks start on 64-bit boundaries.
	 */
	while (*pOpt != kDexChunkEnd) {
		const HChar* verboseStr;

		UInt size = *(pOpt+1);

		switch (*pOpt) {
			case kDexChunkClassLookup:
				verboseStr = "class lookup hash table";
				break;
			case kDexChunkRegisterMaps:
				verboseStr = "register maps";
				break;
			default:
				verboseStr = "(unknown chunk type)";
				break;
		}

		OAT_LOGI("Chunk %08x (%c%c%c%c) - %s (%d bytes)\n", *pOpt,
				*pOpt >> 24, (HChar)(*pOpt >> 16), (HChar)(*pOpt >> 8), (HChar)*pOpt,
				verboseStr, size);

		size = (size + 8 + 7) & ~7;
		pOpt += size / sizeof(UInt);
	}
	OAT_LOGI("\n");
}

/*
 * Dump a class_def_item.
 */
void dumpClassDef(DexFile* pDexFile, Int idx)
{
	const DexClassDef* pClassDef;
	const UChar* pEncodedData;
	DexClassData* pClassData;

	pClassDef = dexGetClassDef(pDexFile, idx);
	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);

	if (pClassData == NULL) {
		fOAT_LOGI(stderr, "Trouble reading class data\n");
		return;
	}

	OAT_LOGI("Class #%d header:\n", idx);
	OAT_LOGI("class_idx           : %d\n", pClassDef->classIdx);
	OAT_LOGI("access_flags        : %d (0x%04x)\n",
			pClassDef->accessFlags, pClassDef->accessFlags);
	OAT_LOGI("superclass_idx      : %d\n", pClassDef->superclassIdx);
	OAT_LOGI("interfaces_off      : %d (0x%06x)\n",
			pClassDef->interfacesOff, pClassDef->interfacesOff);
	OAT_LOGI("source_file_idx     : %d\n", pClassDef->sourceFileIdx);
	OAT_LOGI("annotations_off     : %d (0x%06x)\n",
			pClassDef->annotationsOff, pClassDef->annotationsOff);
	OAT_LOGI("class_data_off      : %d (0x%06x)\n",
			pClassDef->classDataOff, pClassDef->classDataOff);
	OAT_LOGI("static_fields_size  : %d\n", pClassData->header.staticFieldsSize);
	OAT_LOGI("instance_fields_size: %d\n",
			pClassData->header.instanceFieldsSize);
	OAT_LOGI("direct_methods_size : %d\n", pClassData->header.directMethodsSize);
	OAT_LOGI("virtual_methods_size: %d\n",
			pClassData->header.virtualMethodsSize);
	OAT_LOGI("\n");

	VG_(free)(pClassData);
}

/*
 * Dump an interface that a class declares to implement.
 */
void dumpInterface(const DexFile* pDexFile, const DexTypeItem* pTypeItem,
		Int i)
{
	const HChar* interfaceName =
		dexStringByTypeIdx(pDexFile, pTypeItem->typeIdx);

	if (gOptions.outputFormat == OUTPUT_PLAIN) {
		OAT_LOGI("    #%d              : '%s'\n", i, interfaceName);
	} else {
		HChar* dotted = descriptorToDot(interfaceName);
		OAT_LOGI("<implements name=\"%s\">\n</implements>\n", dotted);
		VG_(free)(dotted);
	}
}

/*
 * Dump the catches table associated with the code.
 */
void dumpCatches(DexFile* pDexFile, const DexCode* pCode)
{
	UInt triesSize = pCode->triesSize;

	if (triesSize == 0) {
		OAT_LOGI("      catches       : (none)\n");
		return;
	}

	OAT_LOGI("      catches       : %d\n", triesSize);

	const DexTry* pTries = dexGetTries(pCode);
	UInt i;

	for (i = 0; i < triesSize; i++) {
		const DexTry* pTry = &pTries[i];
		UInt start = pTry->startAddr;
		UInt end = start + pTry->insnCount;
		DexCatchIterator iterator;

		OAT_LOGI("        0x%04x - 0x%04x\n", start, end);

		dexCatchIteratorInit(&iterator, pCode, pTry->handlerOff);

		for (;;) {
			DexCatchHandler* handler = dexCatchIteratorNext(&iterator);
			const HChar* descriptor;

			if (handler == NULL) {
				break;
			}

			descriptor = (handler->typeIdx == kDexNoIndex) ? "<any>" :
				dexStringByTypeIdx(pDexFile, handler->typeIdx);

			OAT_LOGI("          %s -> 0x%04x\n", descriptor,
					handler->address);
		}
	}
}

static Int dumpPositionsCb(void * /* cnxt */, UInt address, UInt lineNum)
{
	OAT_LOGI("        0x%04x line=%d\n", address, lineNum);
	return 0;
}

/*
 * Dump the positions list.
 */
void dumpPositions(DexFile* pDexFile, const DexCode* pCode,
		const DexMethod *pDexMethod)
{
	OAT_LOGI("      positions     : \n");
	const DexMethodId *pMethodId
		= dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	const HChar *classDescriptor
		= dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

	dexDecodeDebugInfo(pDexFile, pCode, classDescriptor, pMethodId->protoIdx,
			pDexMethod->accessFlags, dumpPositionsCb, NULL, NULL);
}

static void dumpLocalsCb(void * /* cnxt */, UShort reg, UInt startAddress,
		UInt endAddress, const HChar *name, const HChar *descriptor,
		const HChar *signature)
{
	OAT_LOGI("        0x%04x - 0x%04x reg=%d %s %s %s\n",
			startAddress, endAddress, reg, name, descriptor,
			signature);
}

/*
 * Dump the locals list.
 */
void dumpLocals(DexFile* pDexFile, const DexCode* pCode,
		const DexMethod *pDexMethod)
{
	OAT_LOGI("      locals        : \n");

	const DexMethodId *pMethodId
		= dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	const HChar *classDescriptor
		= dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

	dexDecodeDebugInfo(pDexFile, pCode, classDescriptor, pMethodId->protoIdx,
			pDexMethod->accessFlags, NULL, dumpLocalsCb, NULL);
}

/*
 * Get information about a method.
 */
Bool getMethodInfo(DexFile* pDexFile, UInt methodIdx, FieldMethodInfo* pMethInfo)
{
	const DexMethodId* pMethodId;

	if (methodIdx >= pDexFile->pHeader->methodIdsSize)
		return false;

	pMethodId = dexGetMethodId(pDexFile, methodIdx);
	pMethInfo->name = dexStringById(pDexFile, pMethodId->nameIdx);
	pMethInfo->signature = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

	pMethInfo->classDescriptor =
		dexStringByTypeIdx(pDexFile, pMethodId->classIdx);
	return true;
}

/*
 * Get information about a field.
 */
Bool getFieldInfo(DexFile* pDexFile, UInt fieldIdx, FieldMethodInfo* pFieldInfo)
{
	const DexFieldId* pFieldId;

	if (fieldIdx >= pDexFile->pHeader->fieldIdsSize)
		return false;

	pFieldId = dexGetFieldId(pDexFile, fieldIdx);
	pFieldInfo->name = dexStringById(pDexFile, pFieldId->nameIdx);
	pFieldInfo->signature = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
	pFieldInfo->classDescriptor =
		dexStringByTypeIdx(pDexFile, pFieldId->classIdx);
	return true;
}


/*
 * Look up a class' descriptor.
 */
const HChar* getClassDescriptor(DexFile* pDexFile, UInt classIdx)
{
	return dexStringByTypeIdx(pDexFile, classIdx);
}

/*
 * Helper for dumpInstruction(), which builds the string
 * representation for the index in the given instruction. This will
 * first try to use the given buffer, but if the result won't fit,
 * then this will allocate a new buffer to hold the result. A pointer
 * to the buffer which holds the full result is always returned, and
 * this can be compared with the one passed in, to see if the result
 * needs to be VG_(free)()d.
 */
static HChar* indexString(DexFile* pDexFile,
		const DecodedInstruction* pDecInsn, HChar* buf, size_t bufSize)
{
	Int outSize;
	UInt index;
	UInt width;

	/* TODO: Make the index *always* be in field B, to simplify this code. */
	switch (dexGetFormatFromOpcode(pDecInsn->opcode)) {
		case kFmt20bc:
		case kFmt21c:
		case kFmt35c:
		case kFmt35ms:
		case kFmt3rc:
		case kFmt3rms:
		case kFmt35mi:
		case kFmt3rmi:
			index = pDecInsn->vB;
			width = 4;
			break;
		case kFmt31c:
			index = pDecInsn->vB;
			width = 8;
			break;
		case kFmt22c:
		case kFmt22cs:
			index = pDecInsn->vC;
			width = 4;
			break;
		default:
			index = 0;
			width = 4;
			break;
	}

	switch (pDecInsn->indexType) {
		case kIndexUnknown:
			/*
			 * This function shouldn't ever get called for this type, but do
			 * something sensible here, just to help with debugging.
			 */
			outSize = VG_(snprintf)(buf, bufSize, "<unknown-index>");
			break;
		case kIndexNone:
			/*
			 * This function shouldn't ever get called for this type, but do
			 * something sensible here, just to help with debugging.
			 */
			outSize = VG_(snprintf)(buf, bufSize, "<no-index>");
			break;
		case kIndexVaries:
			/*
			 * This one should never show up in a dexdump, so no need to try
			 * to get fancy here.
			 */
			outSize = VG_(snprintf)(buf, bufSize, "<index-varies> // thing@%0*x",
					width, index);
			break;
		case kIndexTypeRef:
			if (index < pDexFile->pHeader->typeIdsSize) {
				outSize = VG_(snprintf)(buf, bufSize, "%s // type@%0*x",
						getClassDescriptor(pDexFile, index), width, index);
			} else {
				outSize = VG_(snprintf)(buf, bufSize, "<type?> // type@%0*x", width, index);
			}
			break;
		case kIndexStringRef:
			if (index < pDexFile->pHeader->stringIdsSize) {
				outSize = VG_(snprintf)(buf, bufSize, "\"%s\" // string@%0*x",
						dexStringById(pDexFile, index), width, index);
			} else {
				outSize = VG_(snprintf)(buf, bufSize, "<string?> // string@%0*x",
						width, index);
			}
			break;
		case kIndexMethodRef:
			{
				FieldMethodInfo methInfo;
				if (getMethodInfo(pDexFile, index, &methInfo)) {
					outSize = VG_(snprintf)(buf, bufSize, "%s.%s:%s // method@%0*x",
							methInfo.classDescriptor, methInfo.name,
							methInfo.signature, width, index);
					VG_(free)((void *) methInfo.signature);
				} else {
					outSize = VG_(snprintf)(buf, bufSize, "<method?> // method@%0*x",
							width, index);
				}
			}
			break;
		case kIndexFieldRef:
			{
				FieldMethodInfo fieldInfo;
				if (getFieldInfo(pDexFile, index, &fieldInfo)) {
					outSize = VG_(snprintf)(buf, bufSize, "%s.%s:%s // field@%0*x",
							fieldInfo.classDescriptor, fieldInfo.name,
							fieldInfo.signature, width, index);
				} else {
					outSize = VG_(snprintf)(buf, bufSize, "<field?> // field@%0*x",
							width, index);
				}
			}
			break;
		case kIndexInlineMethod:
			outSize = VG_(snprintf)(buf, bufSize, "[%0*x] // inline #%0*x",
					width, index, width, index);
			break;
		case kIndexVtableOffset:
			outSize = VG_(snprintf)(buf, bufSize, "[%0*x] // vtable #%0*x",
					width, index, width, index);
			break;
		case kIndexFieldOffset:
			outSize = VG_(snprintf)(buf, bufSize, "[obj+%0*x]", width, index);
			break;
		default:
			outSize = VG_(snprintf)(buf, bufSize, "<?>");
			break;
	}

	if (outSize >= (Int) bufSize) {
		/*
		 * The buffer wasn't big enough; allocate and retry. Note:
		 * VG_(snprintf)() doesn't count the '\0' as part of its returned
		 * size, so we add explicit space for it here.
		 */
		outSize++;
		buf = (HChar*)VG_(malloc)(outSize);
		if (buf == NULL) {
			return NULL;
		}
		return indexString(pDexFile, pDecInsn, buf, outSize);
	} else {
		return buf;
	}
}

/*
 * Dump a single instruction.
 */
void dumpInstruction(struct DexFile* pDexFile, const struct DexCode* pCode, Int insnIdx,
		Int insnWidth, const struct DecodedInstruction* pDecInsn)
{
	HChar indexBufChars[200];
	HChar *indexBuf = indexBufChars;
	const UShort* insns = pCode->insns;
	Int i;

	// Address of instruction (expressed as byte offset).
	OAT_LOGI("%06zx:", ((UChar*)insns - pDexFile->baseAddr) + insnIdx*2);

	for (i = 0; i < 8; i++) {
		if (i < insnWidth) {
			if (i == 7) {
				OAT_LOGI(" ... ");
			} else {
				/* prInt 16-bit value in little-endian order */
				const UChar* bytePtr = (const UChar*) &insns[insnIdx+i];
				OAT_LOGI(" %02x%02x", bytePtr[0], bytePtr[1]);
			}
		} else {
			fputs("     ", stdout);
		}
	}

	if (pDecInsn->opcode == OP_NOP) {
		UShort instr = get2LE((const UChar*) &insns[insnIdx]);
		if (instr == kPackedSwitchSignature) {
			OAT_LOGI("|%04x: packed-switch-data (%d units)",
					insnIdx, insnWidth);
		} else if (instr == kSparseSwitchSignature) {
			OAT_LOGI("|%04x: sparse-switch-data (%d units)",
					insnIdx, insnWidth);
		} else if (instr == kArrayDataSignature) {
			OAT_LOGI("|%04x: array-data (%d units)",
					insnIdx, insnWidth);
		} else {
			OAT_LOGI("|%04x: nop // spacer", insnIdx);
		}
	} else {
		OAT_LOGI("|%04x: %s", insnIdx, dexGetOpcodeName(pDecInsn->opcode));
	}

	if (pDecInsn->indexType != kIndexNone) {
		indexBuf = indexString(pDexFile, pDecInsn,
				indexBufChars, sizeof(indexBufChars));
	}

	switch (dexGetFormatFromOpcode(pDecInsn->opcode)) {
		case kFmt10x:        // op
			break;
		case kFmt12x:        // op vA, vB
			OAT_LOGI(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
			break;
		case kFmt11n:        // op vA, #+B
			OAT_LOGI(" v%d, #Int %d // #%x",
					pDecInsn->vA, (s4)pDecInsn->vB, (UChar)pDecInsn->vB);
			break;
		case kFmt11x:        // op vAA
			OAT_LOGI(" v%d", pDecInsn->vA);
			break;
		case kFmt10t:        // op +AA
		case kFmt20t:        // op +AAAA
			{
				s4 targ = (s4) pDecInsn->vA;
				OAT_LOGI(" %04x // %c%04x",
						insnIdx + targ,
						(targ < 0) ? '-' : '+',
						(targ < 0) ? -targ : targ);
			}
			break;
		case kFmt22x:        // op vAA, vBBBB
			OAT_LOGI(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
			break;
		case kFmt21t:        // op vAA, +BBBB
			{
				s4 targ = (s4) pDecInsn->vB;
				OAT_LOGI(" v%d, %04x // %c%04x", pDecInsn->vA,
						insnIdx + targ,
						(targ < 0) ? '-' : '+',
						(targ < 0) ? -targ : targ);
			}
			break;
		case kFmt21s:        // op vAA, #+BBBB
			OAT_LOGI(" v%d, #Int %d // #%x",
					pDecInsn->vA, (s4)pDecInsn->vB, (UShort)pDecInsn->vB);
			break;
		case kFmt21h:        // op vAA, #+BBBB0000[00000000]
			// The printed format varies a bit based on the actual opcode.
			if (pDecInsn->opcode == OP_CONST_HIGH16) {
				s4 value = pDecInsn->vB << 16;
				OAT_LOGI(" v%d, #Int %d // #%x",
						pDecInsn->vA, value, (UShort)pDecInsn->vB);
			} else {
				s8 value = ((s8) pDecInsn->vB) << 48;
				OAT_LOGI(" v%d, #long %" PRId64 " // #%x",
						pDecInsn->vA, value, (UShort)pDecInsn->vB);
			}
			break;
		case kFmt21c:        // op vAA, thing@BBBB
		case kFmt31c:        // op vAA, thing@BBBBBBBB
			OAT_LOGI(" v%d, %s", pDecInsn->vA, indexBuf);
			break;
		case kFmt23x:        // op vAA, vBB, vCC
			OAT_LOGI(" v%d, v%d, v%d", pDecInsn->vA, pDecInsn->vB, pDecInsn->vC);
			break;
		case kFmt22b:        // op vAA, vBB, #+CC
			OAT_LOGI(" v%d, v%d, #Int %d // #%02x",
					pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (UChar)pDecInsn->vC);
			break;
		case kFmt22t:        // op vA, vB, +CCCC
			{
				s4 targ = (s4) pDecInsn->vC;
				OAT_LOGI(" v%d, v%d, %04x // %c%04x", pDecInsn->vA, pDecInsn->vB,
						insnIdx + targ,
						(targ < 0) ? '-' : '+',
						(targ < 0) ? -targ : targ);
			}
			break;
		case kFmt22s:        // op vA, vB, #+CCCC
			OAT_LOGI(" v%d, v%d, #Int %d // #%04x",
					pDecInsn->vA, pDecInsn->vB, (s4)pDecInsn->vC, (UShort)pDecInsn->vC);
			break;
		case kFmt22c:        // op vA, vB, thing@CCCC
		case kFmt22cs:       // [opt] op vA, vB, field offset CCCC
			OAT_LOGI(" v%d, v%d, %s", pDecInsn->vA, pDecInsn->vB, indexBuf);
			break;
		case kFmt30t:
			OAT_LOGI(" #%08x", pDecInsn->vA);
			break;
		case kFmt31i:        // op vAA, #+BBBBBBBB
			{
				/* this is often, but not always, a float */
				union {
					float f;
					UInt i;
				} conv;
				conv.i = pDecInsn->vB;
				OAT_LOGI(" v%d, #float %f // #%08x",
						pDecInsn->vA, conv.f, pDecInsn->vB);
			}
			break;
		case kFmt31t:       // op vAA, offset +BBBBBBBB
			OAT_LOGI(" v%d, %08x // +%08x",
					pDecInsn->vA, insnIdx + pDecInsn->vB, pDecInsn->vB);
			break;
		case kFmt32x:        // op vAAAA, vBBBB
			OAT_LOGI(" v%d, v%d", pDecInsn->vA, pDecInsn->vB);
			break;
		case kFmt35c:        // op {vC, vD, vE, vF, vG}, thing@BBBB
		case kFmt35ms:       // [opt] invoke-virtual+super
		case kFmt35mi:       // [opt] inline invoke
			{
				fputs(" {", stdout);
				for (i = 0; i < (Int) pDecInsn->vA; i++) {
					if (i == 0)
						OAT_LOGI("v%d", pDecInsn->arg[i]);
					else
						OAT_LOGI(", v%d", pDecInsn->arg[i]);
				}
				OAT_LOGI("}, %s", indexBuf);
			}
			break;
		case kFmt3rc:        // op {vCCCC .. v(CCCC+AA-1)}, thing@BBBB
		case kFmt3rms:       // [opt] invoke-virtual+super/range
		case kFmt3rmi:       // [opt] execute-inline/range
			{
				/*
				 * This doesn't match the "dx" output when some of the args are
				 * 64-bit values -- dx only shows the first register.
				 */
				fputs(" {", stdout);
				for (i = 0; i < (Int) pDecInsn->vA; i++) {
					if (i == 0)
						OAT_LOGI("v%d", pDecInsn->vC + i);
					else
						OAT_LOGI(", v%d", pDecInsn->vC + i);
				}
				OAT_LOGI("}, %s", indexBuf);
			}
			break;
		case kFmt51l:        // op vAA, #+BBBBBBBBBBBBBBBB
			{
				/* this is often, but not always, a double */
				union {
					double d;
					u8 j;
				} conv;
				conv.j = pDecInsn->vB_wide;
				OAT_LOGI(" v%d, #double %f // #%016" PRIx64,
						pDecInsn->vA, conv.d, pDecInsn->vB_wide);
			}
			break;
		case kFmt00x:        // unknown op or breakpoint
			break;
		default:
			OAT_LOGI(" ???");
			break;
	}

	putHChar('\n');

	if (indexBuf != indexBufChars) {
		VG_(free)(indexBuf);
	}
}

/*
 * Get the DexCode for a DexMethod.  Returns NULL if the class is native
 * or abstract.
 */
INLINE const struct DexCode* dexGetCode(const struct DexFile* pDexFile,
		const struct DexMethod* pDexMethod)
{    
	if (pDexMethod->codeOff == 0)
		return NULL;
	return (const struct DexCode*) (pDexFile->baseAddr + pDexMethod->codeOff);
}		

/*
 * Dump a bytecode disassembly.
 */
void dumpBytecodes(struct DexFile* pDexFile, const struct DexMethod* pDexMethod)
{
	const struct DexCode* pCode = dexGetCode(pDexFile, pDexMethod);
	const UShort* insns;
	Int insnIdx;
	FieldMethodInfo methInfo;
	Int startAddr;
	HChar* className = NULL;

	assert(pCode->insnsSize > 0);
	insns = pCode->insns;

	methInfo.classDescriptor =
		methInfo.name =
		methInfo.signature = NULL;

	getMethodInfo(pDexFile, pDexMethod->methodIdx, &methInfo);
	startAddr = ((UChar*)pCode - pDexFile->baseAddr);
	className = descriptorToDot(methInfo.classDescriptor);

	OAT_LOGI("%06x:                                        |[%06x] %s.%s:%s\n",
			startAddr, startAddr,
			className, methInfo.name, methInfo.signature);
	VG_(free)((void *) methInfo.signature);

	insnIdx = 0;
	while (insnIdx < (Int) pCode->insnsSize) {
		Int insnWidth;
		DecodedInstruction decInsn;
		UShort instr;

		/*
		 * Note: This code parallels the function
		 * dexGetWidthFromInstruction() in InstrUtils.c, but this version
		 * can deal with data in either endianness.
		 *
		 * TODO: Figure out if this really matters, and possibly change
		 * this to just use dexGetWidthFromInstruction().
		 */
		instr = get2LE((const UChar*)insns);
		if (instr == kPackedSwitchSignature) {
			insnWidth = 4 + get2LE((const UChar*)(insns+1)) * 2;
		} else if (instr == kSparseSwitchSignature) {
			insnWidth = 2 + get2LE((const UChar*)(insns+1)) * 4;
		} else if (instr == kArrayDataSignature) {
			Int width = get2LE((const UChar*)(insns+1));
			Int size = get2LE((const UChar*)(insns+2)) |
				(get2LE((const UChar*)(insns+3))<<16);
			// The plus 1 is to round up for odd size and width.
			insnWidth = 4 + ((size * width) + 1) / 2;
		} else {
			Opcode opcode = dexOpcodeFromCodeUnit(instr);
			insnWidth = dexGetWidthFromOpcode(opcode);
			if (insnWidth == 0) {
				fOAT_LOGI(stderr,
						"GLITCH: zero-width instruction at idx=0x%04x\n", insnIdx);
				break;
			}
		}

		dexDecodeInstruction(insns, &decInsn);
		dumpInstruction(pDexFile, pCode, insnIdx, insnWidth, &decInsn);

		insns += insnWidth;
		insnIdx += insnWidth;
	}

	VG_(free)(className);
}

/*
 * Dump a "code" struct.
 */
void dumpCode(struct DexFile* pDexFile, const struct DexMethod* pDexMethod)
{
	const struct DexCode* pCode = dexGetCode(pDexFile, pDexMethod);

	OAT_LOGI("      registers     : %d\n", pCode->registersSize);
	OAT_LOGI("      ins           : %d\n", pCode->insSize);
	OAT_LOGI("      outs          : %d\n", pCode->outsSize);
	OAT_LOGI("      insns size    : %d 16-bit code units\n", pCode->insnsSize);

	if (gOptions.disassemble)
		dumpBytecodes(pDexFile, pDexMethod);

	dumpCatches(pDexFile, pCode);
	/* both of these are encoded in debug info */
	dumpPositions(pDexFile, pCode, pDexMethod);
	dumpLocals(pDexFile, pCode, pDexMethod);
}

/*
 * Dump a method.
 */
void dumpMethod(struct DexFile* pDexFile, const struct DexMethod* pDexMethod, Int i)
{
	const struct DexMethodId* pMethodId;
	const HChar* backDescriptor;
	const HChar* name;
	HChar* typeDescriptor = NULL;
	HChar* accessStr = NULL;

	if (gOptions.exportsOnly &&
			(pDexMethod->accessFlags & (ACC_PUBLIC | ACC_PROTECTED)) == 0)
	{
		return;
	}

	pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	name = dexStringById(pDexFile, pMethodId->nameIdx);
	typeDescriptor = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

	backDescriptor = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

	accessStr = createAccessFlagStr(pDexMethod->accessFlags,
			kAccessForMethod);

	if (gOptions.outputFormat == OUTPUT_PLAIN) {
		OAT_LOGI("    #%d              : (in %s)\n", i, backDescriptor);
		OAT_LOGI("      name          : '%s'\n", name);
		OAT_LOGI("      type          : '%s'\n", typeDescriptor);
		OAT_LOGI("      access        : 0x%04x (%s)\n",
				pDexMethod->accessFlags, accessStr);

		if (pDexMethod->codeOff == 0) {
			OAT_LOGI("      code          : (none)\n");
		} else {
			OAT_LOGI("      code          -\n");
			dumpCode(pDexFile, pDexMethod);
		}

		if (gOptions.disassemble)
			putHChar('\n');
	} else if (gOptions.outputFormat == OUTPUT_XML) {
		Bool constructor = (name[0] == '<');

		if (constructor) {
			HChar* tmp;

			tmp = descriptorClassToDot(backDescriptor);
			OAT_LOGI("<constructor name=\"%s\"\n", tmp);
			VG_(free)(tmp);

			tmp = descriptorToDot(backDescriptor);
			OAT_LOGI(" type=\"%s\"\n", tmp);
			VG_(free)(tmp);
		} else {
			OAT_LOGI("<method name=\"%s\"\n", name);

			const HChar* returnType = strrchr(typeDescriptor, ')');
			if (returnType == NULL) {
				fOAT_LOGI(stderr, "bad method type descriptor '%s'\n",
						typeDescriptor);
				goto bail;
			}

			HChar* tmp = descriptorToDot(returnType+1);
			OAT_LOGI(" return=\"%s\"\n", tmp);
			VG_(free)(tmp);

			OAT_LOGI(" abstract=%s\n",
					quotedBool((pDexMethod->accessFlags & ACC_ABSTRACT) != 0));
			OAT_LOGI(" native=%s\n",
					quotedBool((pDexMethod->accessFlags & ACC_NATIVE) != 0));

			Bool isSync =
				(pDexMethod->accessFlags & ACC_SYNCHRONIZED) != 0 ||
				(pDexMethod->accessFlags & ACC_DECLARED_SYNCHRONIZED) != 0;
			OAT_LOGI(" synchronized=%s\n", quotedBool(isSync));
		}

		OAT_LOGI(" static=%s\n",
				quotedBool((pDexMethod->accessFlags & ACC_STATIC) != 0));
		OAT_LOGI(" final=%s\n",
				quotedBool((pDexMethod->accessFlags & ACC_FINAL) != 0));
		// "deprecated=" not knowable w/o parsing annotations
		OAT_LOGI(" visibility=%s\n",
				quotedVisibility(pDexMethod->accessFlags));

		OAT_LOGI(">\n");

		/*
		 * Parameters.
		 */
		if (typeDescriptor[0] != '(') {
			fOAT_LOGI(stderr, "ERROR: bad descriptor '%s'\n", typeDescriptor);
			goto bail;
		}

		HChar tmpBuf[strlen(typeDescriptor)+1];      /* more than big enough */
		Int argNum = 0;

		const HChar* base = typeDescriptor+1;

		while (*base != ')') {
			HChar* cp = tmpBuf;

			while (*base == '[')
				*cp++ = *base++;

			if (*base == 'L') {
				/* copy through ';' */
				do {
					*cp = *base++;
				} while (*cp++ != ';');
			} else {
				/* primitive HChar, copy it */
				if (strchr("ZBCSIFJD", *base) == NULL) {
					fOAT_LOGI(stderr, "ERROR: bad method signature '%s'\n", base);
					goto bail;
				}
				*cp++ = *base++;
			}

			/* null terminate and display */
			*cp++ = '\0';

			HChar* tmp = descriptorToDot(tmpBuf);
			OAT_LOGI("<parameter name=\"arg%d\" type=\"%s\">\n</parameter>\n",
					argNum++, tmp);
			VG_(free)(tmp);
		}

		if (constructor)
			OAT_LOGI("</constructor>\n");
		else
			OAT_LOGI("</method>\n");
	}

bail:
	VG_(free)(typeDescriptor);
	VG_(free)(accessStr);
}

/*
 * Dump a static (class) field.
 */
void dumpSField(const struct DexFile* pDexFile, const struct DexField* pSField, Int i)
{
	const struct DexFieldId* pFieldId;
	const HChar* backDescriptor;
	const HChar* name;
	const HChar* typeDescriptor;
	HChar* accessStr;

	if (gOptions.exportsOnly &&
			(pSField->accessFlags & (ACC_PUBLIC | ACC_PROTECTED)) == 0)
	{
		return;
	}

	pFieldId = dexGetFieldId(pDexFile, pSField->fieldIdx);
	name = dexStringById(pDexFile, pFieldId->nameIdx);
	typeDescriptor = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
	backDescriptor = dexStringByTypeIdx(pDexFile, pFieldId->classIdx);

	accessStr = createAccessFlagStr(pSField->accessFlags, kAccessForField);

	OAT_LOGI("    #%d              : (in %s)\n", i, backDescriptor);
	OAT_LOGI("      name          : '%s'\n", name);
	OAT_LOGI("      type          : '%s'\n", typeDescriptor);
	OAT_LOGI("      access        : 0x%04x (%s)\n",
			pSField->accessFlags, accessStr);
	VG_(free)(accessStr);
}

/*
 * Dump an instance field.
 */
void dumpIField(const struct DexFile* pDexFile, const struct DexField* pIField, Int i)
{
	dumpSField(pDexFile, pIField, i);
}

/*
 * Dump the class.
 *
 * Note "idx" is a DexClassDef index, not a DexTypeId index.
 *
 * If "*pLastPackage" is NULL or does not match the current class' package,
 * the value will be replaced with a newly-allocated string.
 */
void dumpClass(struct DexFile* pDexFile, Int idx, HChar** pLastPackage)
{
	const struct DexTypeList* pInterfaces;
	const struct DexClassDef* pClassDef;
	struct DexClassData* pClassData = NULL;
	const UChar* pEncodedData;
	const HChar* fileName;
	const HChar* classDescriptor;
	const HChar* superclassDescriptor;
	HChar* accessStr = NULL;
	Int i;

	pClassDef = dexGetClassDef(pDexFile, idx);

	if (gOptions.exportsOnly && (pClassDef->accessFlags & ACC_PUBLIC) == 0) {
		//OAT_LOGI("<!-- omitting non-public class %s -->\n",
		//    classDescriptor);
		goto bail;
	}

	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);

	if (pClassData == NULL) {
		OAT_LOGI("Trouble reading class data (#%d)\n", idx);
		goto bail;
	}

	classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

	/*
	 * For the XML output, show the package name.  Ideally we'd gather
	 * up the classes, sort them, and dump them alphabetically so the
	 * package name wouldn't jump around, but that's not a great plan
	 * for something that needs to run on the device.
	 */
	if (!(classDescriptor[0] == 'L' &&
				classDescriptor[strlen(classDescriptor)-1] == ';'))
	{
		/* arrays and primitives should not be defined explicitly */
		fOAT_LOGI(stderr, "Malformed class name '%s'\n", classDescriptor);
		/* keep going? */
	} else if (gOptions.outputFormat == OUTPUT_XML) {
		HChar* mangle;
		HChar* lastSlash;
		HChar* cp;

		mangle = strdup(classDescriptor + 1);
		mangle[strlen(mangle)-1] = '\0';

		/* reduce to just the package name */
		lastSlash = strrchr(mangle, '/');
		if (lastSlash != NULL) {
			*lastSlash = '\0';
		} else {
			*mangle = '\0';
		}

		for (cp = mangle; *cp != '\0'; cp++) {
			if (*cp == '/')
				*cp = '.';
		}

		if (*pLastPackage == NULL || strcmp(mangle, *pLastPackage) != 0) {
			/* start of a new package */
			if (*pLastPackage != NULL)
				OAT_LOGI("</package>\n");
			OAT_LOGI("<package name=\"%s\"\n>\n", mangle);
			VG_(free)(*pLastPackage);
			*pLastPackage = mangle;
		} else {
			VG_(free)(mangle);
		}
	}

	accessStr = createAccessFlagStr(pClassDef->accessFlags, kAccessForClass);

	if (pClassDef->superclassIdx == kDexNoIndex) {
		superclassDescriptor = NULL;
	} else {
		superclassDescriptor =
			dexStringByTypeIdx(pDexFile, pClassDef->superclassIdx);
	}

	if (gOptions.outputFormat == OUTPUT_PLAIN) {
		OAT_LOGI("Class #%d            -\n", idx);
		OAT_LOGI("  Class descriptor  : '%s'\n", classDescriptor);
		OAT_LOGI("  Access flags      : 0x%04x (%s)\n",
				pClassDef->accessFlags, accessStr);

		if (superclassDescriptor != NULL)
			OAT_LOGI("  Superclass        : '%s'\n", superclassDescriptor);

		OAT_LOGI("  Interfaces        -\n");
	} else {
		HChar* tmp;

		tmp = descriptorClassToDot(classDescriptor);
		OAT_LOGI("<class name=\"%s\"\n", tmp);
		VG_(free)(tmp);

		if (superclassDescriptor != NULL) {
			tmp = descriptorToDot(superclassDescriptor);
			OAT_LOGI(" extends=\"%s\"\n", tmp);
			VG_(free)(tmp);
		}
		OAT_LOGI(" abstract=%s\n",
				quotedBool((pClassDef->accessFlags & ACC_ABSTRACT) != 0));
		OAT_LOGI(" static=%s\n",
				quotedBool((pClassDef->accessFlags & ACC_STATIC) != 0));
		OAT_LOGI(" final=%s\n",
				quotedBool((pClassDef->accessFlags & ACC_FINAL) != 0));
		// "deprecated=" not knowable w/o parsing annotations
		OAT_LOGI(" visibility=%s\n",
				quotedVisibility(pClassDef->accessFlags));
		OAT_LOGI(">\n");
	}
	pInterfaces = dexGetInterfacesList(pDexFile, pClassDef);
	if (pInterfaces != NULL) {
		for (i = 0; i < (Int) pInterfaces->size; i++)
			dumpInterface(pDexFile, dexGetTypeItem(pInterfaces, i), i);
	}

	if (gOptions.outputFormat == OUTPUT_PLAIN)
		OAT_LOGI("  Static fields     -\n");
	for (i = 0; i < (Int) pClassData->header.staticFieldsSize; i++) {
		dumpSField(pDexFile, &pClassData->staticFields[i], i);
	}

	if (gOptions.outputFormat == OUTPUT_PLAIN)
		OAT_LOGI("  Instance fields   -\n");
	for (i = 0; i < (Int) pClassData->header.instanceFieldsSize; i++) {
		dumpIField(pDexFile, &pClassData->instanceFields[i], i);
	}

	if (gOptions.outputFormat == OUTPUT_PLAIN)
		OAT_LOGI("  Direct methods    -\n");
	for (i = 0; i < (Int) pClassData->header.directMethodsSize; i++) {
		dumpMethod(pDexFile, &pClassData->directMethods[i], i);
	}

	if (gOptions.outputFormat == OUTPUT_PLAIN)
		OAT_LOGI("  Virtual methods   -\n");
	for (i = 0; i < (Int) pClassData->header.virtualMethodsSize; i++) {
		dumpMethod(pDexFile, &pClassData->virtualMethods[i], i);
	}

	// TODO: Annotations.

	if (pClassDef->sourceFileIdx != kDexNoIndex)
		fileName = dexStringById(pDexFile, pClassDef->sourceFileIdx);
	else
		fileName = "unknown";

	if (gOptions.outputFormat == OUTPUT_PLAIN) {
		OAT_LOGI("  source_file_idx   : %d (%s)\n",
				pClassDef->sourceFileIdx, fileName);
		OAT_LOGI("\n");
	}

	if (gOptions.outputFormat == OUTPUT_XML) {
		OAT_LOGI("</class>\n");
	}

bail:
	VG_(free)(pClassData);
	VG_(free)(accessStr);
}


/*
 * Advance "ptr" to ensure 32-bit alignment.
 */
static inline const UChar* align32(const UChar* ptr)
{
	return (UChar*) (((uintptr_t) ptr + 3) & ~0x03);
}


/*
 * Dump a map in the "differential" format.
 *
 * TODO: show a hex dump of the compressed data.  (We can show the
 * uncompressed data if we move the compression code to libdex; otherwise
 * it's too complex to merit a fast & fragile implementation here.)
 */
void dumpDifferentialCompressedMap(const UChar** pData)
{
	const UChar* data = *pData;
	const UChar* dataStart = data -1;      // format byte already removed
	UChar regWidth;
	UShort numEntries;

	/* standard header */
	regWidth = *data++;
	numEntries = *data++;
	numEntries |= (*data++) << 8;

	/* compressed data begins with the compressed data length */
	Int compressedLen = readUnsignedLeb128(&data);
	Int addrWidth = 1;
	if ((*data & 0x80) != 0)
		addrWidth++;

	Int origLen = 4 + (addrWidth + regWidth) * numEntries;
	Int compLen = (data - dataStart) + compressedLen;

	OAT_LOGI("        (differential compression %d -> %d [%d -> %d])\n",
			origLen, compLen,
			(addrWidth + regWidth) * numEntries, compressedLen);

	/* skip past end of entry */
	data += compressedLen;

	*pData = data;
}

/*
 * Dump register map contents of the current method.
 *
 * "*pData" should poInt to the start of the register map data.  Advances
 * "*pData" to the start of the next map.
 */
void dumpMethodMap(struct DexFile* pDexFile, const struct DexMethod* pDexMethod, Int idx,
		const UChar** pData)
{
	const UChar* data = *pData;
	const struct DexMethodId* pMethodId;
	const HChar* name;
	Int offset = data - (UChar*) pDexFile->pOptHeader;

	pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	name = dexStringById(pDexFile, pMethodId->nameIdx);
	OAT_LOGI("      #%d: 0x%08x %s\n", idx, offset, name);

	UChar format;
	Int addrWidth;

	format = *data++;
	if (format == 1) {              /* kRegMapFormatNone */
		/* no map */
		OAT_LOGI("        (no map)\n");
		addrWidth = 0;
	} else if (format == 2) {       /* kRegMapFormatCompact8 */
		addrWidth = 1;
	} else if (format == 3) {       /* kRegMapFormatCompact16 */
		addrWidth = 2;
	} else if (format == 4) {       /* kRegMapFormatDifferential */
		dumpDifferentialCompressedMap(&data);
		goto bail;
	} else {
		OAT_LOGI("        (unknown format %d!)\n", format);
		/* don't know how to skip data; failure will cascade to end of class */
		goto bail;
	}

	if (addrWidth > 0) {
		UChar regWidth;
		UShort numEntries;
		Int idx, addr, byte;

		regWidth = *data++;
		numEntries = *data++;
		numEntries |= (*data++) << 8;

		for (idx = 0; idx < numEntries; idx++) {
			addr = *data++;
			if (addrWidth > 1)
				addr |= (*data++) << 8;

			OAT_LOGI("        %4x:", addr);
			for (byte = 0; byte < regWidth; byte++) {
				OAT_LOGI(" %02x", *data++);
			}
			OAT_LOGI("\n");
		}
	}

bail:
	//if (addrWidth >= 0)
	//    *pData = align32(data);
	*pData = data;
}

/*
 * Dump the contents of the register map area.
 *
 * These are only present in optimized DEX files, and the structure is
 * not really exposed to other parts of the VM itself.  We're going to
 * dig through them here, but this is pretty fragile.  DO NOT rely on
 * this or derive other code from it.
 */
void dumpRegisterMaps( struct DexFile* pDexFile)
{
	const UChar* pClassPool = (const UChar*)pDexFile->pRegisterMapPool;
	const UInt* classOffsets;
	const UChar* ptr;
	UInt numClasses;
	Int baseFileOffset = (UChar*) pClassPool - (UChar*) pDexFile->pOptHeader;
	Int idx;

	if (pClassPool == NULL) {
		OAT_LOGI("No register maps found\n");
		return;
	}

	ptr = pClassPool;
	numClasses = get4LE(ptr);
	ptr += sizeof(UInt);
	classOffsets = (const UInt*) ptr;

	OAT_LOGI("RMAP begins at offset 0x%07x\n", baseFileOffset);
	OAT_LOGI("Maps for %d classes\n", numClasses);
	for (idx = 0; idx < (Int) numClasses; idx++) {
		const struct DexClassDef* pClassDef;
		const HChar* classDescriptor;

		pClassDef = dexGetClassDef(pDexFile, idx);
		classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

		OAT_LOGI("%4d: +%d (0x%08x) %s\n", idx, classOffsets[idx],
				baseFileOffset + classOffsets[idx], classDescriptor);

		if (classOffsets[idx] == 0)
			continue;

		/*
		 * What follows is a series of RegisterMap entries, one for every
		 * direct method, then one for every virtual method.
		 */
		struct DexClassData* pClassData;
		const UChar* pEncodedData;
		const UChar* data = (UChar*) pClassPool + classOffsets[idx];
		UShort methodCount;
		Int i;

		pEncodedData = dexGetClassData(pDexFile, pClassDef);
		pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
		if (pClassData == NULL) {
			fOAT_LOGI(stderr, "Trouble reading class data\n");
			continue;
		}

		methodCount = *data++;
		methodCount |= (*data++) << 8;
		data += 2;      /* two pad bytes follow methodCount */
		if (methodCount != pClassData->header.directMethodsSize
				+ pClassData->header.virtualMethodsSize)
		{
			OAT_LOGI("NOTE: method count discrepancy (%d != %d + %d)\n",
					methodCount, pClassData->header.directMethodsSize,
					pClassData->header.virtualMethodsSize);
			/* this is bad, but keep going anyway */
		}

		OAT_LOGI("    direct methods: %d\n",
				pClassData->header.directMethodsSize);
		for (i = 0; i < (Int) pClassData->header.directMethodsSize; i++) {
			dumpMethodMap(pDexFile, &pClassData->directMethods[i], i, &data);
		}

		OAT_LOGI("    virtual methods: %d\n",
				pClassData->header.virtualMethodsSize);
		for (i = 0; i < (Int) pClassData->header.virtualMethodsSize; i++) {
			dumpMethodMap(pDexFile, &pClassData->virtualMethods[i], i, &data);
		}

		VG_(free)(pClassData);
	}
}

/*
 * Dump the requested sections of the file.
 */
void processDexFile(const HChar* fileName, DexFile* pDexFile)
{
	HChar* package = NULL;
	Int i;

	if (gOptions.verbose) {
		OAT_LOGI("Opened '%s', DEX version '%.3s'\n", fileName,
				pDexFile->pHeader->magic +4);
	}

	if (gOptions.dumpRegisterMaps) {
		dumpRegisterMaps(pDexFile);
		return;
	}

	if (gOptions.showFileHeaders) {
		dumpFileHeader(pDexFile);
		dumpOptDirectory(pDexFile);
	}

	if (gOptions.outputFormat == OUTPUT_XML)
		OAT_LOGI("<api>\n");

	for (i = 0; i < (Int) pDexFile->pHeader->classDefsSize; i++) {
		if (gOptions.showSectionHeaders)
			dumpClassDef(pDexFile, i);

		dumpClass(pDexFile, i, &package);
	}

	/* free the last one allocated */
	if (package != NULL) {
		OAT_LOGI("</package>\n");
		VG_(free)(package);
	}

	if (gOptions.outputFormat == OUTPUT_XML)
		OAT_LOGI("</api>\n");
}


/*
 * Process one file.
 */
Int process(const HChar* fileName)
{
	DexFile* pDexFile = NULL;
	MemMapping map;
	Bool mapped = false;
	Int result = -1;

	if (gOptions.verbose)
		OAT_LOGI("Processing '%s'...\n", fileName);

	if (dexOpenAndMap(fileName, gOptions.tempFileName, &map, false) != 0) {
		return result;
	}
	mapped = true;

	Int flags = kDexParseVerifyChecksum;
	if (gOptions.ignoreBadChecksum)
		flags |= kDexParseContinueOnError;

	pDexFile = dexFileParse((UChar*)map.addr, map.length, flags);
	if (pDexFile == NULL) {
		fOAT_LOGI(stderr, "ERROR: DEX parse failed\n");
		goto bail;
	}

	if (gOptions.checksumOnly) {
		OAT_LOGI("Checksum verified\n");
	} else {
		processDexFile(fileName, pDexFile);
	}

	result = 0;

bail:
	if (mapped)
		sysReleaseShmem(&map);
	if (pDexFile != NULL)
		dexFileFree(pDexFile);
	return result;
}


/*
 * Show usage.
 */
void usage(void)
{
	fOAT_LOGI(stderr, "Copyright (C) 2007 The Android Open Source Project\n\n");
	fOAT_LOGI(stderr,
			"%s: [-c] [-d] [-f] [-h] [-i] [-l layout] [-m] [-t tempfile] dexfile...\n",
			gProgName);
	fOAT_LOGI(stderr, "\n");
	fOAT_LOGI(stderr, " -c : verify checksum and exit\n");
	fOAT_LOGI(stderr, " -d : disassemble code sections\n");
	fOAT_LOGI(stderr, " -f : display summary information from file header\n");
	fOAT_LOGI(stderr, " -h : display file header details\n");
	fOAT_LOGI(stderr, " -i : ignore checksum failures\n");
	fOAT_LOGI(stderr, " -l : output layout, either 'plain' or 'xml'\n");
	fOAT_LOGI(stderr, " -m : dump register maps (and nothing else)\n");
	fOAT_LOGI(stderr, " -t : temp file name (defaults to /sdcard/dex-temp-*)\n");
}

/*
 * Parse args.
 *
 * I'm not using getopt_long() because we may not have it in libc.
 */
Int main(Int argc, HChar* const argv[])
{
	Bool wantUsage = false;
	Int ic;

	memset(&gOptions, 0, sizeof(gOptions));
	gOptions.verbose = true;

	while (1) {
		ic = getopt(argc, argv, "cdfhil:mt:");
		if (ic < 0)
			break;

		switch (ic) {
			case 'c':       // verify the checksum then exit
				gOptions.checksumOnly = true;
				break;
			case 'd':       // disassemble Dalvik instructions
				gOptions.disassemble = true;
				break;
			case 'f':       // dump outer file header
				gOptions.showFileHeaders = true;
				break;
			case 'h':       // dump section headers, i.e. all meta-data
				gOptions.showSectionHeaders = true;
				break;
			case 'i':       // continue even if checksum is bad
				gOptions.ignoreBadChecksum = true;
				break;
			case 'l':       // layout
				if (strcmp(optarg, "plain") == 0) {
					gOptions.outputFormat = OUTPUT_PLAIN;
				} else if (strcmp(optarg, "xml") == 0) {
					gOptions.outputFormat = OUTPUT_XML;
					gOptions.verbose = false;
					gOptions.exportsOnly = true;
				} else {
					wantUsage = true;
				}
				break;
			case 'm':       // dump register maps only
				gOptions.dumpRegisterMaps = true;
				break;
			case 't':       // temp file, used when opening compressed Jar
				gOptions.tempFileName = optarg;
				break;
			default:
				wantUsage = true;
				break;
		}
	}

	if (optind == argc) {
		fOAT_LOGI(stderr, "%s: no file specified\n", gProgName);
		wantUsage = true;
	}

	if (gOptions.checksumOnly && gOptions.ignoreBadChecksum) {
		fOAT_LOGI(stderr, "Can't specify both -c and -i\n");
		wantUsage = true;
	}

	if (wantUsage) {
		usage();
		return 2;
	}

	Int result = 0;
	while (optind < argc) {
		result |= process(argv[optind++]);
	}

	return (result != 0);
}
