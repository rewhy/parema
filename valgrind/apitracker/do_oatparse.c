// oatparse.c

#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"

//#include "dt_taint.h"
//#include "dt_debug.h"
//#include "dt_oatplus.h"
#include "do_oatdexparse.h"

#define DBG_ART_METHOD
#undef  DBG_ART_METHOD

extern HChar* do_start_clazz;
extern HChar* do_stop_clazz;
extern Int do_start_method_index;
extern HChar *do_start_method_name;
extern HChar *do_start_method_shorty;
extern Int do_stop_method_index;
extern HChar *do_stop_method_name;
extern HChar *mth_index_name[MAX_MTH_NUM];

static Addr	do_mem_start = 0;
static Addr do_mem_end	 = 0;

struct DexFile *pBootDex = NULL;

//extern Int do_sink_method_index;

Bool do_is_mem_range(Addr a, UInt len) {
	if( a + len < do_mem_start)
		return False;
	if( a > do_mem_end )
		return False;
	return True;
}

static Bool is_taint_white(Addr addr){
	//  void org.apache.http.impl.cookie.RFC2965DiscardAttributeHandler.validate(org.apache.http.cookie.Cookie, org.apache.http.cookie.CookieOrigin)
	if(addr == 0x71e7e05c)
		return True;
	// org/apache/http/impl/cookie/RFC2965VersionAttributeHandler; match() ZL
	if(addr == 0x71e91a1c)
		return True;
	return False;
}
#if 0
static Bool is_taint_source(Int dex_method_idx){
	// java.lang.String android.provider.Settings$Secure.getString(android.content.ContentResolver, java.lang.String)
	if(dex_method_idx == 47775)
		return True;
	// java.lang.String android.telephony.TelephonyManager.getDeviceId()
	if(dex_method_idx == 55547)
		return True;
	// java.lang.String android.telecom.TelecomManager.getLine1Number(android.telecom.PhoneAccountHandle)
	if(dex_method_idx == 54465) // Returns the phone number string for line 1
		return True;
	// double android.location.Location.getLatitude() (dex_method_idx=28340)
	if(dex_method_idx == 28340) // Get the latitude, in degrees
		return True;
	// double android.location.Location.getLongitude() (dex_method_idx=28341)
	if(dex_method_idx == 28341)
		return True;
	// java.lang.String android.database.Cursor.getString(int) (dex_method_idx=16235)
	if(dex_method_idx == 16235)
		return True;
	// java.lang.String 16386 Landroid/database/CursorWrapper; getString
	if(dex_method_idx == 16386)
		return True;
#if 0
	if(dex_method_idx == 28671) // sendtoBytes()
		return True;
#endif
	return False;
}

static Bool is_taint_sink(Int dex_method_idx){
	if(dex_method_idx == 47775)
		return True;
	if(dex_method_idx == 55547)
		return True;

	return False;
}
static Bool is_taint_source1(HChar *clazz, HChar* mth, HChar* shorty){
	if(VG_(strcmp)("android.telephony.TelephonyManager", clazz)==0) { // id=55547
		if(VG_(strcmp)("getDeviceId()", mth) == 0) {
			if(VG_(strcmp)("", shorty) == 0) {
				return True;
			}
		}
	}
	return False;
}
#endif

//extern VgHashTable *do_frame_mth_list;
VgHashTable* do_frame_mth_list = NULL;

static void* add_method(HChar *clazz, HChar* mth, HChar* shorty, Addr codeAddr, SizeT codeSize, Int index, Int accessFlags)
{
#if 0
	if(is_taint_white(codeAddr))
		return NULL;
#endif

	MthList *mth_list = NULL;
	MthNode *mth_node = NULL;//, *mth_node1 = NULL;
	mth_node = (MthNode *)VG_(malloc)("method.node", sizeof(MthNode));
	VG_(memset)((Addr)mth_node, 0, sizeof(MthNode));

	if(mth_node) {
		VG_(strcpy)(mth_node->clazz, clazz);
		VG_(strcpy)(mth_node->method, mth);
		VG_(strcpy)(mth_node->shorty, shorty);
		mth_node->codeAddr		= codeAddr;
		mth_node->codeSize		= codeSize;
		mth_node->mthKey			= index;
		mth_node->accessFlags = accessFlags;
#if 0
		if(is_taint_source(index)) {
			mth_node->type |= TYPE_SOURCE;
		}
		if(is_taint_sink(index)) {
			mth_node->type |= TYPE_SINK;
		}
#endif
		// VG_(printf)("0 Add Method(%d): 0x%08x %s %s() %s source=%s\n", index, codeAddr, mth_node->clazz, 
		//		mth_node->method, mth_node->shorty, mth_node->type&TYPE_SOURCE ? "True" : "False" );
		mth_list = query_method_list(codeAddr);
		if(mth_list == NULL) {
			mth_list = (MthList*)VG_(malloc)("method.list", sizeof(MthList));
			tl_assert(mth_list);
			VG_(memset)((Addr)mth_list, 0, sizeof(MthList));
			mth_list->codeAddr = codeAddr;
			VG_(HT_add_node)(do_frame_mth_list, mth_list);
		}
		if(mth_list->num < MAX_METHOD_NUM) {
			mth_list->mthNodes[mth_list->num] = (Addr)mth_node;
			mth_list->num++;
		} else {
#ifdef DBG_ART_METHOD
			VG_(printf)("1 Add Method(%d): 0x%08x-0x%08x %s %s() %s source=%s\n", index, codeAddr, codeAddr+codeSize-1, mth_node->clazz, 
					mth_node->method, mth_node->shorty, mth_node->type&TYPE_SOURCE ? "True" : "False" );
			VG_(printf)("Warning: List for addr 0x%08x is already full\n", codeAddr);
#endif
		}
		if(index < MAX_MTH_NUM) {
			/*if(mth_index_name[index] != NULL) {
				VG_(printf)("Warining(%d): %s %s\n", index, mth_index_name[index], mth_node->method);
			}*/
			mth_index_name[index] = mth_node->method;
		}
#ifdef DBG_ART_METHOD
		VG_(printf)("1 Add Method(%d): 0x%08x-0x%08x %s %s() %s isNative=%c\n",
				index, codeAddr, codeAddr+codeSize-1, mth_node->clazz, 
				mth_node->method, mth_node->shorty,
				//mth_node->type&TYPE_SOURCE ? "True" : "False" 
				(mth_node->accessFlags & ACC_NATIVE) ? 'T' : 'F'
				);
#endif
#if 0
		if (index == do_sink_method_index) {
			do_mem_start	= codeAddr & ~0x1;
			do_mem_end		= codeAddr + codeSize - 1;
			VG_(printf)("Fuzz Method(%d): 0x%08x-0x%08x %s %s() %s source=%s\n",
					index, codeAddr, codeAddr+codeSize-1, mth_node->clazz, 
					mth_node->method, mth_node->shorty, 
					mth_node->type&TYPE_SOURCE ? "True" : "False"
					//(mth_node->accessFlags & ACC_NATIVE) ? 'T' : 'F'
					);
		}
#endif
		return mth_node;
	}
	return NULL;
}

MthList* query_method_list(Addr codeAddr) {
	if(do_frame_mth_list == NULL)
		return NULL;
	MthList *mth_list = VG_(HT_lookup)( do_frame_mth_list, codeAddr);
	if(mth_list)
		return mth_list;
	return NULL;
}

MthNode* query_method_node(Addr codeAddr, Int index)
{
	MthList *mth_list = VG_(HT_lookup)( do_frame_mth_list, codeAddr);
	MthNode *mth_node = NULL;
	if(mth_list) {
		if(mth_list->num == 0)
			return NULL;
		if(index < 0)
			return (MthNode*)mth_list->mthNodes[0];
		for(Int i = 0; i < mth_list->num; i++) {
			mth_node = (MthNode *)mth_list->mthNodes[i];
			if(mth_node->mthKey == index)
				return mth_node;
		}
		return mth_node;
	}
	return NULL;
}

Bool query_method(Addr codeAddr, HChar **clazz, HChar **mth, HChar **shorty, Int *accFlags)
{
	if(do_frame_mth_list == NULL)
		return NULL;
	//DT_LOGI("Query Addr: 0x%08x\n", codeAddr);
	MthNode *mth_node = VG_(HT_lookup)( do_frame_mth_list, codeAddr);
	if(mth_node) {
		if(clazz)
			*clazz	= mth_node->clazz;
		if(mth)
			*mth		= mth_node->method;
		if(shorty)
			*shorty	= mth_node->shorty;
		if(accFlags)
			*accFlags = mth_node->accessFlags;
		return True;
	}
	return False;
}

static void remove_method(Addr codeAddr)
{
	MthNode *mth_node = VG_(HT_remove)( do_frame_mth_list, codeAddr);
	if( NULL == mth_node )
		return;
	VG_(free)( mth_node );
	mth_node = NULL;
}

/*names for the access flags*/
const HChar *ACCESS_FLAG_NAMES[20] = {
	"public",       
	"private",
	"protected",
	"static",       
	"final",      
	"synchronized",
	"super",  
	"volatile",
	"bridge",   
	"transient",
	"varargs",
	"native",
	"Interface",
	"abstract",
	"strict",
	"synthetic",
	"annotation",
	"enum",    
	"constructor",
	"declared_synchronized"};

const UInt ACCESS_FLAG_VALUES[20] = {
	0x00000001,
	0x00000002,
	0x00000004,
	0x00000008,
	0x00000010,
	0x00000020,
	0x00000020,
	0x00000040,
	0x00000040,
	0x00000080,
	0x00000080,
	0x00000100,
	0x00000200,
	0x00000400,
	0x00000800,
	0x00001000,
	0x00002000,
	0x00004000,
	0x00010000,
	0x00020000};

const HChar * OAT_CLASS_TYPE[3] = {
	"kOatClassAllCompiled",
	"kOatClassSomeCompiled",
	"kOatClassNoneCompiled"
};

/* Dex file parsing related functions */

Int readUnsignedLeb128(UChar** pStream)
{
	/* taken from dalvik's libdex/Leb128.h */
	UChar* ptr = *pStream;
	Int result = *(ptr++);

	if (result > 0x7f) {
		Int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					/*
					 * Note: We don't check to see if cur is out of
					 * range here, meaning we tolerate garbage in the
					 * high four-order bits.
					 * */
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}

	*pStream = ptr;
	return result;
}

UInt uleb128_value(UChar* pStream)
{
	UChar* ptr = pStream;
	Int result = *(ptr++);

	if (result > 0x7f) {
		Int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					/*
					 * Note: We don't check to see if cur is out of
					 * range here, meaning we tolerate garbage in the
					 * high four-order bits.
					 */
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}


UInt len_uleb128(unsigned long n)
{
	static UChar b[32];
	UInt i;

	i = 0;
	do
	{
		b[i] = n & 0x7F;
		if (n >>= 7)
			b[i] |= 0x80;
	}
	while (b[i++] & 0x80);
	return i;
}


void getUnsignedLebValue(UChar* dex, UChar* stringData,
		UInt offset) {
	UChar* uLebBuff;
	UInt uLebValue, uLebValueLength;
	uLebBuff = dex + offset;

	uLebValue = uleb128_value(uLebBuff);
	uLebValueLength = len_uleb128(uLebValue);

	VG_(memcpy)(stringData, dex+offset+uLebValueLength, uLebValue);
	stringData[uLebValue] = '\0';
}

UInt getTypeDescForClass(UChar* dex, struct DexStringId* strIdList,
		struct DexTypeId* typeIdList, struct DexClassDef* classDefItem,
		UChar* stringData) {
	UInt strIdOff = 0;
	if(classDefItem->classIdx) {
		strIdOff = strIdList[typeIdList[classDefItem->classIdx].descriptorIdx].stringDataOff;
		getUnsignedLebValue(dex, stringData, strIdOff);
	} else {
		VG_(strcpy)(stringData, "Unknown");
	}
	return strIdOff;
}

void getTypeDesc(UChar* dex, struct DexStringId *strIdList,
		struct DexTypeId* typeIdList, UInt offset_poInter,
		UChar* stringData){
	UInt strIdOff;
	if (offset_poInter){
		strIdOff = strIdList[typeIdList[offset_poInter].descriptorIdx].stringDataOff; /*get the offset to the string in the data section*/
		/*would be cool if we have a RAW mode, with only hex unparsed data, and a SYMBOLIC mode where all the data is parsed and Interpreted */
		getUnsignedLebValue(dex,stringData,strIdOff);
	}
	else{
		VG_(strcpy)(stringData, "Unknown");
	}
}

void getProtoDesc(UChar* dex, struct DexStringId *strIdList,
		struct DexTypeId* typeIdList,
		struct DexProtoId* protoIdList, UInt offset_poInter,
		UChar* returnType, UChar* shorty, UChar* params){
	UInt strIdOff, p, *tmp;
	struct DexTypeList *type_list;
	if (offset_poInter){
		strIdOff = strIdList[typeIdList[protoIdList[offset_poInter].returnTypeIdx].descriptorIdx].stringDataOff; 
		getUnsignedLebValue(dex, returnType, strIdOff);
		strIdOff = strIdList[protoIdList[offset_poInter].shortyIdx].stringDataOff;
		getUnsignedLebValue(dex, shorty, strIdOff);
		if( protoIdList[offset_poInter].parametersOff == 0)
			p = 0;
		else {
			type_list = (struct DexFileList*)(dex + protoIdList[offset_poInter].parametersOff);
			p = type_list->list->typeIdx;
		}
		strIdOff = strIdList[typeIdList[p].descriptorIdx].stringDataOff;
		getUnsignedLebValue(dex, params, strIdOff);
	}
	else{
		VG_(strcpy)(returnType, "Unknown");
		VG_(strcpy)(shorty, "Unknown");
		VG_(strcpy)(params, "Unknown");
	}
}

void getClassFileName(UChar* dex, struct DexStringId *strIdList, 
		struct DexClassDef *classDefItem, UChar *stringData) {
	UInt strIdOff;
	//OAT_LOGI("Source file ID: %d\n", classDefItem->sourceFileId);
	if(classDefItem->sourceFileIdx) {
		strIdOff = strIdList[classDefItem->sourceFileIdx].stringDataOff;
		//OAT_LOGI("String offset: 0x%x\n", strIdOff);
		getUnsignedLebValue(dex, stringData, strIdOff);
	} else {
		stringData[0] = '\0';
	}
}
/*this allows us to prInt ACC_FLAGS symbolically*/
UChar* parseAccessFlags(UInt flags){
	Int i = 0;
	if (flags){
		for (;i<20;i++){
			if (flags & ACCESS_FLAG_VALUES[i]){
				//OAT_LOGI(" %s ",ACCESS_FLAG_NAMES[i]);
				return ACCESS_FLAG_NAMES[i];
			}
		}	
	}
	return NULL;
}

/*not entirely sure how I should use these methods, as is they are only usefull for prInting values, and don't return them :/
 * though as a tradeoff I've made the methods manipulate the string data in place, so the conversion to returning them would be easy */
/*Generic methods for prInting types*/
void getStringValue(UChar* dex, struct DexStringId *strIdList,
		UInt offset_poInter,UChar* stringData){

	UInt strIdOff;
	if (offset_poInter){
		strIdOff = strIdList[offset_poInter].stringDataOff; /*get the offset to the string in the data section*/
		/*would be cool if we have a RAW mode, with only hex unparsed data, and a SYMBOLIC mode where all the data is parsed and Interpreted */
		getUnsignedLebValue(dex,stringData,strIdOff);
	}
	else{
		VG_(strcpy)(stringData, "Unknown");
	}
}

UInt getCodeOffset(UShort type, UChar* bitmap, UInt* offsets, UInt mid, UInt *nid) {
	UInt	i, j, m, n, cid = mid;
	UChar b;
	if(type == 2) // none compiled
		return 0;
	tl_assert(offsets);
	i = mid % 8;
	j = mid / 8;
	if(type == 1) {
		b = bitmap[j];
		if( (b & (0x1 << i)) == 0 )
			return 0;
		cid = 0;
		for(m = 0; m < j; m++)
		{
			for(n = 0; n < sizeof(UChar) * 8; n++)
				if(bitmap[m] & (0x1 << n))
					cid++;
		}
		for(n = 0; n < i; n++)
			if(bitmap[j] & (0x1 << n))
				cid++;
	}
	*nid = cid;
	return offsets[cid];
}
#if 0
#endif

Bool oatDexClassParse(Addr oatdata, 
		Addr dexBuf, UInt offset,
		struct OatClassHeader *oat_class_header,
		struct DexFile *pDex) {

	struct DexClassDef *class_def_item;

	HChar typeDesc[255];
	HChar classFile[255];
	HChar className[255];

	HChar returnType[255];
	HChar shorty[255];
	HChar params[255];
	HChar str[255];
	HChar buf[32];
	HChar *buffer, *ptr;

	Int len = 0;
	Int field_idx_diff;
	Int field_access_flags;

	Int method_idx_diff;
	Int method_access_flags;
	Int method_code_off;

	Int key = 0, i = 0;

	UInt  static_fields_size; 
	UInt  instance_fields_size;
	UInt  direct_methods_size;
	UInt  virtual_methods_size;

	Int size_uleb, size_uleb_value;

	UChar* bitmap = NULL;
	UInt   bitmap_size = 0;
	UInt*  methods_offsets = NULL;
	UInt   native_code_offset = 0;
	UInt   total_methods = 0;
	UInt   native_methods = 0;
	UInt   strlen = 0;

	struct OatQuickMethodHeader *oat_mth_header;
	struct DexHeader *dh = (struct DexHeader*)dexBuf;

	Bool isStartClass = False;
	Bool isStopClass = False;

	//OAT_LOGI("[] classDefOff: 0x%x\n", offset);
	class_def_item = (struct DexClassDef*)(dexBuf + offset);
	if(class_def_item->sourceFileIdx!= NO_INDEX ){
		getClassFileName(dexBuf, pDex->pStringIds, class_def_item, classFile);
		//OAT_LOGI("( %s )\n", str);
	} else {
		VG_(strcpy)(classFile, "Unknown");
	}
	/* Get the type description for the class */
	UInt idOff = getTypeDescForClass(dexBuf, pDex->pStringIds, pDex->pTypeIds, class_def_item, className);

	strlen = VG_(strlen)(className);

	for(i = 0; i < strlen; i++)
		if ((UChar)className[i] == 36)
			return False;

	if( VG_(memcmp)(className, "Landroid/icu/", 13) == 0 )
		return False;

	if( VG_(memcmp)(className, "Landroid/view", 13) == 0 )
		return False;
	
	if( VG_(memcmp)(className, "Landroid/text", 13) == 0 )
		return False;
	
	if( VG_(memcmp)(className, "Landroid/widget", 15) == 0 )
		return False;
	
	//if( VG_(memcmp)(className, "Landroid/support", 16) == 0)
	//	return False;

	if( VG_(memcmp)(className, "Landroid/graphics", 17) == 0 )
		return False;

	if( VG_(memcmp)(className, "Ljava/lang/Throwabl", 19) == 0 )
		return False;
	
	if( VG_(memcmp)(className, "Landroid/content/pm", 19) == 0 )
		return False;
	
	if( VG_(memcmp)(className, "Landroid/content/res", 20) == 0 )
		return False;

	if( VG_(memcmp)(className, "Landroid/support/graphics/", 26) == 0 )
		return False;

	if( strlen > 10 ) {
		if( VG_(strcmp)((HChar*)&className[strlen-10], "Exception;") == 0)
			return False;
	}

	if( VG_(strcmp)(do_start_clazz, className) == 0)
		isStartClass = True;
	if( VG_(strcmp)(do_stop_clazz, className) == 0)
		isStopClass = True;
	
	UChar *accessFlags = parseAccessFlags(class_def_item->accessFlags);

	/* The	bitmap field	is	a	bitmap	of	length	bitmap_size bytes	where	each	bit	indicates	whether	a	particular	
	 * method	is	compiled	or	not.		Each	bit	corresponds	to	a	method	in	the	class. If	type is	either	
	 * kOatClassAllCompiled or	kOatClassNoneCompiled,	there	will	be	no	bitmap_size and	bitmap fields	present	
	 * and	type is	immediately	followed	by	the	method_offsets.	If	type is	kOatClassSomeCompiled,	it	means	at	
	 * least	one	but	not	all	methods	are	compiled.	In	this	case,	the	method_offsets come	right	after	the	bitmap.	
	 * Each	bit	in	the	bitmap,	starting	from	the	least	significant	bit,	corresponds	to	a	method	in	this	class -
	 * direct_methods first,	followed	by	virtual_methods. They	are	in	the	same	order	as	they	appear in	the	
	 * class_data_item	of	this	class. For	every	set	bit,	there	will	be	a	corresponding	entry	in	method_offsets.
	 * 
	 * method_offsets is	a	list	of	offset	that	poInts	to	the	generated	native	code	for	each	compiled	method.	Note	
	 * that	for	OAT	files	with	OATHeader->instruction_set is kThumb2 (which	the	majority	of	the	OAT	files	you
	 * will	encounter	will	likely	be),	the	method	offsets will	have	their least	significant	bit	set.	For	instance,	
	 * if the offset is	0x00143061,	the	actual	start	of	the	native	code	is	at	offset	0x00143060.
	 */

	tl_assert(oat_class_header != NULL);
	if(oat_class_header->type==0 || oat_class_header->type==1 
			|| oat_class_header->type==2 || oat_class_header->type==3) {
	} else {
		OAT_LOGI(" type: %d\n", oat_class_header->type);
		tl_assert(0);
	}
	/* prInt oat related information */
	//OAT_LOGI("\toat class type: %s\n", OAT_CLASS_TYPE[oat_class_header->type]);
	if( oat_class_header->type == 1) {
		bitmap_size = *(UInt*)((UChar*)oat_class_header + sizeof(struct OatClassHeader));
		bitmap = (UChar*)oat_class_header + sizeof(struct OatClassHeader) + sizeof(UInt);
		methods_offsets = (UInt*)(bitmap + bitmap_size);
	} else {
		methods_offsets = (UInt*)((UChar*)oat_class_header + sizeof(struct OatClassHeader));
	}

	OAT_LOGI(": %s (%s) (type_idx=%d) (flags=%s) (%s)\n",
			className, classFile, class_def_item->classIdx,
			accessFlags, OAT_CLASS_TYPE[oat_class_header->type]);

#if 0
	/* prInt debug info */
	OAT_LOGI("\tclass_idx='0x%x':", class_def_item->classId);
	OAT_LOGI("( %s )\n", str);
	OAT_LOGI("\taccess_flags='0x%x'\n", class_def_item->accessFlags); /*need to Interpret this*/
	OAT_LOGI("\tsuperclass_idx='0x%x':", class_def_item->superClassId);
	getTypeDesc(dexBuf, string_id_list, type_id_list, class_def_item->superClassId,str);
	OAT_LOGI("( %s )\n", str);
	OAT_LOGI("\tInterfaces_off='0x%x'\n", class_def_item->InterfaceOff); /*need to look this up in the DexTypeList*/
	OAT_LOGI("\tsource_file_idx='0x%x'\n", class_def_item->sourceFileId);
	if (class_def_item->sourceFileId != NO_INDEX)
	{
		getStringValue(dexBuf, string_id_list, class_def_item->sourceFileId, str); //causes a seg fault on some dex files
		OAT_LOGI("( %s )\n", str);
	}
#endif
	OAT_LOGI("\tannotations_off=0x%08x\n", class_def_item->annotationsOff);
	OAT_LOGI("\tclass_data_off=0x%08x (%d)\n", class_def_item->classDataOff, class_def_item->classDataOff);
	OAT_LOGI("\tstatic_values_off=0x%08x (%d)\n", class_def_item->staticValuesOff, class_def_item->staticValuesOff);
	/* change position to classDataOff */
	if (class_def_item->classDataOff == 0) {
		if (OAT_DEBUG) {
			OAT_LOGI ("\t0 static fields\n");
			OAT_LOGI ("\t0 instance fields\n");
			OAT_LOGI ("\t0 direct methods\n");
		} else {
			OAT_LOGI ("0 direct methods, 0 virtual methods\n");
		}
		return False;
	} else {
		offset = class_def_item->classDataOff;
	}
	len = dh->mapOff - offset;
	if(len < 1) {
		len = dh->fileSize - offset;
		if(len < 1) {
			OAT_LOGI("ERROR: invalid file length in dex header \n");
			tl_assert(0);
		}
	}
	buffer = VG_(malloc)("Oat.Dex.Class", len);
	tl_assert(buffer != NULL);
	VG_(memcpy)(buffer, dexBuf+offset, len);
	ptr = buffer;
	static_fields_size		= readUnsignedLeb128(&buffer);
	instance_fields_size	= readUnsignedLeb128(&buffer);
	direct_methods_size		= readUnsignedLeb128(&buffer);
	virtual_methods_size	= readUnsignedLeb128(&buffer);

	if(OAT_DEBUG) OAT_LOGI("\t%d static fields\n", static_fields_size);

	key = 0;
	for(i = 0; i < static_fields_size; i++) {
		field_idx_diff = readUnsignedLeb128(&buffer);
		field_access_flags = readUnsignedLeb128(&buffer);

		/* fields */
		if (key == 0) 
			key=field_idx_diff;

		UShort class_idx = pDex->pFieldIds[key].classIdx;
		UShort type_idx	 = pDex->pFieldIds[key].typeIdx;
		UInt   name_idx  = pDex->pFieldIds[key].nameIdx;

		offset = pDex->pStringIds[name_idx].stringDataOff;
		VG_(memcpy)(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		VG_(memcpy)(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';

		if(OAT_DEBUG) {
			getTypeDesc(dexBuf, pDex->pStringIds, pDex->pTypeIds, type_idx, typeDesc);
			OAT_LOGI ("\t\t[%d]: %s %s\t|--field_idx_diff='0x%08x' |", i, typeDesc, str, field_idx_diff);
			OAT_LOGI (" |--field_access_flags='0x%08x' : %s\n",field_access_flags,
					parseAccessFlags(field_access_flags));
		}
	}
	if (OAT_DEBUG) OAT_LOGI ("\t%d instance fields\n", instance_fields_size);
	for (i=0;i<instance_fields_size;i++) {
		field_idx_diff = readUnsignedLeb128(&buffer);
		field_access_flags = readUnsignedLeb128(&buffer);
		/* fields */
		if (key == 0) key=field_idx_diff;
		UShort class_idx = pDex->pFieldIds[key].classIdx;
		UShort type_idx  = pDex->pFieldIds[key].typeIdx;
		UInt   name_idx  = pDex->pFieldIds[key].nameIdx;

		offset = pDex->pStringIds[name_idx].stringDataOff;
		VG_(memcpy)(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		VG_(memcpy)(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';

		if (OAT_DEBUG) {
			getTypeDesc(dexBuf, pDex->pStringIds, pDex->pTypeIds, type_idx, typeDesc);
			OAT_LOGI ("\t\t[%d]: %s %s |--field_idx_diff='0x%08x'", i, typeDesc, str, field_idx_diff);
			OAT_LOGI (" |--field_access_flags='0x%08x': %s\n",field_access_flags,
					parseAccessFlags(field_access_flags));
		}
	}

	if (!OAT_DEBUG) OAT_LOGI ("%d direct methods, %d virtual methods\n", direct_methods_size, virtual_methods_size);
	if (OAT_DEBUG) OAT_LOGI ("\t%d direct methods\n", direct_methods_size);

	key=0;
	for (i=0;i<direct_methods_size;i++) {
		method_idx_diff = readUnsignedLeb128(&buffer);
		method_access_flags = readUnsignedLeb128(&buffer);
		method_code_off = readUnsignedLeb128(&buffer);

		/* methods */
		if (key == 0) key=method_idx_diff;
		else key += method_idx_diff;

		UShort class_idx = pDex->pMethodIds[key].classIdx;
		UShort proto_idx = pDex->pMethodIds[key].protoIdx;
		UInt   name_idx  = pDex->pMethodIds[key].nameIdx;

		/* prInt method name ... should really do this stuff through a common function, its going to be annoying to debug this...:/ */
		offset = pDex->pStringIds[name_idx].stringDataOff;
		tl_assert(buf != NULL);
		VG_(memcpy)(buf, dexBuf+offset, 10);

		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		VG_(memcpy)(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';

		getProtoDesc(dexBuf, pDex->pStringIds, pDex->pTypeIds, pDex->pProtoIds,
				proto_idx, returnType, shorty, params);
		OAT_LOGI ("\tDirect method %d (method_id_idx=%d): %s, %s %s(%s) %s\n",i, key,
				parseAccessFlags(method_access_flags),
				returnType, str, params, shorty);

		native_code_offset = getCodeOffset(oat_class_header->type, bitmap, methods_offsets,
				total_methods, &native_methods);



		if(native_code_offset > 0)
		{
			oat_mth_header = (struct OatQuickMethodHeader*)(oatdata+(native_code_offset&~0x1)-sizeof(struct OatQuickMethodHeader));
			if (DBG_OAT_PARSE) {
				OAT_LOGI("\t\tOatMethodOffsets=0x%08x\n", (UChar*)methods_offsets-oatdata+native_methods*sizeof(UInt));
				OAT_LOGI("\t\t\tnative_code_off: 0x%08x\n", native_code_offset);
				OAT_LOGI("\t\tOatQuickMethodHeader=0x%08x\n", (UChar*)oat_mth_header - oatdata);
				OAT_LOGI("\t\t\tgcmap_table_offset: 0x%08x\n", oat_mth_header->gcMapOffset);
				OAT_LOGI("\t\t\tmapping_table_offset: 0x%08x\n", oat_mth_header->mappingTableOffset);
				OAT_LOGI("\t\t\tvmap_table_offset: 0x%08x\n", oat_mth_header->vmapTableOffset);
				OAT_LOGI("\t\t\tcode_size_offset: 0x%08x\n", (UChar*)&oat_mth_header->codeSize-oatdata);
				OAT_LOGI("\t\t\tcode_size: %d\n", oat_mth_header->codeSize);
				OAT_LOGI("\t\tQuickMethodFrameInfo: \n");
				OAT_LOGI("\t\t\tframe_size_in_bytes: 0x%08x\n", oat_mth_header->frameSizeInBytes);
				OAT_LOGI("\t\t\tcore_spill_mask: 0x%08x\n", oat_mth_header->coreSpillMask);
				OAT_LOGI("\t\t\tfp_spill_mask: 0x%08x\n", oat_mth_header->fpSpillMask);
				OAT_LOGI("\t\t[Code range: 0x%08x - 0x%08x  Size: %u (0x%x)]\n", 
						oatdata+native_code_offset&~0x1,
						oatdata+native_code_offset&~0x1+oat_mth_header->codeSize-1,
						oat_mth_header->codeSize, oat_mth_header->codeSize);
			}
			add_method(className, str, shorty, oatdata+native_code_offset&(~0x1), oat_mth_header->codeSize, key, method_access_flags);
			if(isStartClass) {
				if(VG_(strcmp)(do_start_method_name, str) == 0) {
					do_start_method_index = key;
					VG_(printf)("Start: %s %s() %d\n", className, str, key);
					addMonMap(oatdata+native_code_offset, oat_mth_header->codeSize, 0, str); //For debug
				}
			}
			if(isStopClass) {
				if(VG_(strcmp)(do_stop_method_name, str) == 0) {
					do_stop_method_index = key;
					VG_(printf)("Stop: %s %s() %d\n", className, str, key);
				}
			}
		}

		if (DBG_OAT_PARSE) {
			OAT_LOGI("\t\tmethod_code_off=0x%08x\n", method_code_off);
			OAT_LOGI("\t\tmethod_access_flags=0x%08x: %s\n", method_access_flags,
					parseAccessFlags(method_access_flags));
			OAT_LOGI("\t\tclass_idx=0x%08x\n", class_idx);
			OAT_LOGI("\t\tproto_idx=0x%08x\n", proto_idx);
		}
		total_methods++;
	}
	if (OAT_DEBUG) OAT_LOGI ("\t%d virtual methods\n", virtual_methods_size);

	key=0;
	for (i=0;i<virtual_methods_size;i++) {
		method_idx_diff = readUnsignedLeb128(&buffer);
		method_access_flags = readUnsignedLeb128(&buffer);
		method_code_off = readUnsignedLeb128(&buffer);

		/* methods */
		if (key == 0) key=method_idx_diff;
		else key += method_idx_diff;

		UShort class_idx = pDex->pMethodIds[key].classIdx;
		UShort proto_idx = pDex->pMethodIds[key].protoIdx;
		UInt    name_idx = pDex->pMethodIds[key].nameIdx;

		/* prInt method name */
		offset = pDex->pStringIds[name_idx].stringDataOff;
		//prIntStringValue(string_id_list,name_idx,input,str,"%s\n");
		VG_(memcpy)(buf, dexBuf+offset, 10);
		size_uleb_value = uleb128_value(buf);
		size_uleb=len_uleb128(size_uleb_value);
		// offset2: on esta el tamany (size_uleb_value) en uleb32 de la string, seguit de la string 
		VG_(memcpy)(str, dexBuf+offset+size_uleb, size_uleb_value);
		str[size_uleb_value]='\0';

		//getTypeDesc(dexBuf, string_id_list,type_id_list,class_idx, typeDesc);
		getProtoDesc(dexBuf, pDex->pStringIds, pDex->pTypeIds, pDex->pProtoIds,
				proto_idx, returnType, shorty, params);
		OAT_LOGI ("\tvirtual method %d (method_id_idx=%d): %s %s %s(%s) %s\n",i, key,
				parseAccessFlags(method_access_flags),
				returnType, str, params, shorty);

		native_code_offset = getCodeOffset(oat_class_header->type, bitmap, methods_offsets,
				total_methods, &native_methods);
		total_methods++;
		if(native_code_offset > 0) {
			oat_mth_header = (struct OatQuickMethodHeader*)(oatdata+(native_code_offset&~0x1)-sizeof(struct OatQuickMethodHeader));
			if (DBG_OAT_PARSE) {
				OAT_LOGI("\t\tOatMethodOffsets=0x%08x\n", (UChar*)methods_offsets-oatdata+native_methods*sizeof(UInt));
				OAT_LOGI("\t\t\tnative_code_off: 0x%08x\n", native_code_offset);
				OAT_LOGI("\t\tOatQuickMethodHeader=0x%08x\n", (UChar*)oat_mth_header - oatdata);
				OAT_LOGI("\t\t\tgcmap_table_offset: 0x%08x\n", oat_mth_header->gcMapOffset);
				OAT_LOGI("\t\t\tmapping_table_offset: 0x%08x\n", oat_mth_header->mappingTableOffset);
				OAT_LOGI("\t\t\tvmap_table_offset: 0x%08x\n", oat_mth_header->vmapTableOffset);
				OAT_LOGI("\t\t\tcode_size_offset: 0x%08x\n", (UChar*)&oat_mth_header->codeSize-oatdata);
				OAT_LOGI("\t\t\tcode_size: %d\n", oat_mth_header->codeSize);
				OAT_LOGI("\t\tQuickMethodFrameInfo: \n");
				OAT_LOGI("\t\t\tframe_size_in_bytes: 0x%08x\n", oat_mth_header->frameSizeInBytes);
				OAT_LOGI("\t\t\tcore_spill_mask: 0x%08x\n", oat_mth_header->coreSpillMask);
				OAT_LOGI("\t\t\tfp_spill_mask: 0x%08x\n", oat_mth_header->fpSpillMask);
				OAT_LOGI("\t\t[Code range: 0x%08x - 0x%08x  Size: %u (0x%x)]\n", 
						oatdata+native_code_offset&~0x1,
						oatdata+native_code_offset&~0x1+oat_mth_header->codeSize-1,
						oat_mth_header->codeSize, oat_mth_header->codeSize);
			}
			add_method(className, str, shorty, oatdata+native_code_offset&(~0x1), oat_mth_header->codeSize, key, method_access_flags);
			if(isStartClass) {
				if(VG_(strcmp)(do_start_method_name, str) == 0) {
					if(VG_(strcmp)(do_start_method_shorty, shorty) == 0) {
						do_start_method_index = key;
						VG_(printf)("Start: %s %s() %d\n", className, str, key);
					}
				}
			}
			if(isStopClass) {
				if(VG_(strcmp)(do_stop_method_name, str) == 0) {
					do_stop_method_index = key;
					VG_(printf)("Stop: %s %s() %d\n", className, str, key);
				}
			}
		}

		if (DBG_OAT_PARSE) {
			OAT_LOGI("\t\tmethod_code_off=0x%08x\n", method_code_off);
			OAT_LOGI("\t\tmethod_access_flags=0x%08x: %s\n", method_access_flags,
					parseAccessFlags(method_access_flags));	
			OAT_LOGI("\t\tclass_idx=0x%08x\n", class_idx);
			OAT_LOGI("\t\tproto_idx=0x%08x\n", proto_idx);
		}
	}
	VG_(free)(ptr);
	return True;
}

/* methods */
Bool oatDexFileParse(Addr oatdata, 
		struct OatClassOffset* oat_class_offsets, 
		Addr dexBuf, UInt size) {
	UInt j = 0;
	struct OatClassHeader *oat_class_header = NULL;
	struct DexFile *pDex = VG_(malloc)("dex.file", sizeof(struct DexFile));
	tl_assert(pDex != NULL);
#if 0
	const struct DexHeader*			  pHeader;
	const struct DexStringId*			pStringIds;
	const struct DexTypeId*				pTypeIds;
	const struct DexFieldId*			pFieldIds;
	const struct DexMethodId*			pMethodIds;
	const struct DexProtoId*			pProtoIds;
	const struct DexClassDef*			pClassDefs;
	const struct DexLink*					pLinkData;
	struct DexMethodId *method_id_list;
	struct DexFieldId	*field_id_list;
	struct DexStringId *string_id_list;
	struct DexTypeId   *type_id_list;
	struct DexProtoId  *proto_id_list;
#endif
	VG_(memset)((Addr)pDex, 0, sizeof(struct DexFile));

	UInt  offset = 0;

	struct DexHeader *dh = (struct DexHeader*)dexBuf;
	pDex->pHeader = dh;


	if(do_frame_mth_list == NULL) {
		do_frame_mth_list = VG_(HT_construct)( "do_frame_mth_list" );
	}

	//dumpR(dexOffset+dex_file_offset, dh.fileSize);
#if DBG_OAT_PARSE
	if(is_parse_oat) {
		dumpOatMem(dexBuf, size);
		dumpDexFile(dexBuf, size);
	}
#endif

	if (1) {
		OAT_LOGI("[] DEX magic: ");
		for(j=0;j<8;j++) OAT_LOGI("%02x ", dh->magic[j]);
		OAT_LOGI("\n");
		OAT_LOGI("[] DEX version: %s\n", &dh->magic[4]);
		OAT_LOGI("[] Adler32 checksum: 0x%x\n", dh->checksum);
		OAT_LOGI("[] Dex file size: %d\n", dh->fileSize);
		OAT_LOGI("[] Dex header size: %d bytes (0x%x)\n", dh->headerSize, dh->headerSize);
		OAT_LOGI("[] Endian Tag: 0x%x\n", dh->endianTag);
		OAT_LOGI("[] Link size: %d\n", dh->linkSize);
		OAT_LOGI("[] Link offset: 0x%x\n", dh->linkOff);
		OAT_LOGI("[] Map list offset: 0x%x\n", dh->mapOff);
		OAT_LOGI("[] Number of strings in string ID list: %d\n", dh->stringIdsSize);
		OAT_LOGI("[] String ID list offset: 0x%x\n", dh->stringIdsOff);
		OAT_LOGI("[] Number of types in the type ID list: %d\n", dh->typeIdsSize);
		OAT_LOGI("[] Type ID list offset: 0x%x\n", dh->typeIdsOff);
		OAT_LOGI("[] Number of items in the method prototype ID list: %d\n", dh->protoIdsSize);
		OAT_LOGI("[] Method prototype ID list offset: 0x%x\n", dh->protoIdsOff);
		OAT_LOGI("[] Number of item in the field ID list: %d\n", dh->fieldIdsSize);
		OAT_LOGI("[] Field ID list offset: 0x%x\n", dh->fieldIdsOff);
		OAT_LOGI("[] Number of items in the method ID list: %d\n", dh->methodIdsSize);
		OAT_LOGI("[] Method ID list offset: 0x%x\n", dh->methodIdsOff);
		OAT_LOGI("[] Number of items in the class definitions list: %d\n", dh->classDefsSize);
		OAT_LOGI("[] Class definitions list offset: 0x%x\n", dh->classDefsOff);
		OAT_LOGI("[] Data section size: %d bytes\n", dh->dataSize);
		OAT_LOGI("[] Data section offset: 0x%x\n", dh->dataOff);
	}
	OAT_LOGI("\n[] Number of classes in the archive: %d\n", dh->classDefsSize);

	//string_id_list	= (struct DexStringId*)(dexBuf + dh->stringIdsOff);
	pDex->pStringIds	= (struct DexStringId*)(dexBuf + dh->stringIdsOff);
	//type_id_list		= (struct DexTypeId*)(dexBuf + dh->typeIdsOff);
	pDex->pTypeIds		= (struct DexTypeId*)(dexBuf + dh->typeIdsOff);
	//proto_id_list		= (struct DexProtoId*)(dexBuf + dh->protoIdsOff);
	pDex->pProtoIds		= (struct DexProtoId*)(dexBuf + dh->protoIdsOff);
	//field_id_list   = (struct DexFieldId*)(dexBuf + dh->fieldIdsOff);
	pDex->pFieldIds   = (struct DexFieldId*)(dexBuf + dh->fieldIdsOff);
	//method_id_list	= (struct DexMethodId*)(dexBuf + dh->methodIdsOff);
	pDex->pMethodIds	= (struct DexMethodId*)(dexBuf + dh->methodIdsOff);
	/* Parse class definations */
	//for(j = 1; j <= 3138/*dh.classDefsSize*/; j++) {
	for(j = 0; j < dh->classDefsSize; j++) {
		OAT_LOGI("Class %d: (offset=0x%08x)", j, oat_class_offsets[j].offset);
		//offset = dexOffset + dh.classDefsOff + j*sizeof(struct DexClassDef);
		oat_class_header = (struct OatClassHeader*)(oatdata + oat_class_offsets[j].offset);
		offset = dh->classDefsOff + j*sizeof(struct DexClassDef);
		tl_assert((UChar*)oat_class_header+sizeof(struct OatClassHeader) < oatdata+size);
		if(oatDexClassParse(oatdata, dexBuf, offset, oat_class_header, pDex) == False)
			OAT_LOGI("\n");
	}
	OAT_LOGI("Finished.\n");
	return True;
}
#if 0
/* Used for dump the dex files */
Bool dump(UChar* buf, UInt size) {
	tl_assert(buf != NULL);
	Int fout = open("./dump.dex", O_WRONLY | O_CREAT | O_SYNC);
	write(fout, buf, size);
	close(fout);
	return True;
}
#endif


static void printOatHeader(struct OatHeader* oheader) {
	VG_(printf)("\n\nOAT header: \n");
	VG_(printf)("\tadler32Checksum:\t0x%08x\n", oheader->adler32Checksum);
	VG_(printf)("\tdexFileCount:\t\t%d\n", oheader->dexFileCount);
	VG_(printf)("\texecutableOffset:\t0x%08x\n", oheader->executableOffset);
	VG_(printf)("\tinterpreterToInterpreterBridgeOffset:\t0x%08x\n", oheader->interpreterToInterpreterBridgeOffset);
	VG_(printf)("\tinterpreterToCompiledCodeBridgeOffset:\t0x%08x\n", oheader->interpreterToCompiledCodeBridgeOffset);
	VG_(printf)("\tjniDlsymLookupOffset:\t\t\t0x%08x\n", oheader->jniDlsymLookupOffset);
	VG_(printf)("\tquickGenericJniTrampolineOffset:\t0x%08x\n", oheader->quickGenericJniTrampolineOffset);
	VG_(printf)("\tquickImtConflictTrampolineOffset:\t0x%08x\n", oheader->quickImtConflictTrampolineOffset);
	VG_(printf)("\tquickResolutionTrampolineOffset:\t0x%08x\n", oheader->quickResolutionTrampolineOffset);
	VG_(printf)("\tquickToInterpreterBridgeOffset:\t\t0x%08x\n", oheader->quickToInterpreterBridgeOffset);
	VG_(printf)("\timageFileLocationOatDataBegin:\t\t0x%08x\n", oheader->imageFileLocationOatDataBegin);
	VG_(printf)("\n");
}

Bool oatDexParse(Addr oatdata, UInt oatdata_size,
		Addr oatexec, UInt oatexec_size) {
	UInt i = 0;
	UInt dex_file_location_size; // Length of the original input DEX path
	UInt dex_file_checksum;			 // CRC32 checksum of classes.dex 
	UInt dex_file_offset;				 
	struct OatClassOffset* classes_offsets;      // List of offsets to OATClassHeaders
	HChar dex_file_location_data[255]; // Original path of input DEX file
	struct DexHeader *dh;
	UInt offset = 0;
	UChar *key_value_store;
	struct OatHeader *oh = (struct OatHeader *)oatdata;
	if(VG_(memcmp)(oh->magic, "oat", 3) != 0) {
		VG_(printf)("Error: %s\n", oh->magic);
		return False;//		tl_assert(0);
	}
	
	VG_(printf)("oatdata: 0x%08x - 0x%08x\noatexec: 0x%08x - 0x%08x\n", 
			oatdata, oatdata+oatdata_size-1,
			oatexec, oatexec+oatexec_size-1);

	offset += sizeof(struct OatHeader);
	key_value_store = (UChar*)(oatdata + offset);

#if 0
	for(i=0;i<oh->keyValueStoreSize;i++) 
		VG_(printf)("%c", key_value_store[i]);
#endif 

	offset += oh->keyValueStoreSize;
	printOatHeader(oh);

	/* Parse DexFile meta */
	for(i = 0; i < oh->dexFileCount; i++) {
		/* Get dex_file_location_size */
		dex_file_location_size = *(UInt*)(oatdata + offset);
		OAT_LOGI("location size: %d\n", dex_file_location_size);
		offset += sizeof(UInt);
		if(dex_file_location_size == 0)
			return False;

		OAT_LOGI("\nDex file info: \n");
		/* Get dex_file_location_data */
		VG_(memcpy)(dex_file_location_data, (UChar*)(oatdata+offset), dex_file_location_size);
		offset += dex_file_location_size;
		dex_file_location_data[dex_file_location_size] = '\0';
		OAT_LOGI("\tFile data: %s\n", dex_file_location_data);

		/* Get dex_file_checksum */
		dex_file_checksum = *(UInt*)(oatdata + offset);
		offset += sizeof(UInt);
		OAT_LOGI("\tDex file checksum: 0x%08x\n", dex_file_checksum);

		/* Get dex_file_offset */
		dex_file_offset = *(UInt*)(oatdata + offset);
		offset += sizeof(UInt);
		OAT_LOGI("\tDex file offset: 0x%08x\n", dex_file_offset);

		classes_offsets = (struct OatClassOffset*)(oatdata + offset);

		/* Get DexFileHeader */
		dh = (struct DexHeader*)(oatdata + dex_file_offset);
		OAT_LOGI("\tDex file size: %d\n\n", dh->fileSize);
#if 1
		oatDexFileParse(oatdata, classes_offsets, (Addr)dh, oatdata_size);
#else
		dumpDexFile((Addr)dh, dh->fileSize);
#endif
		
		offset += (sizeof(UInt) * dh->classDefsSize);

	}
	return True;
}
