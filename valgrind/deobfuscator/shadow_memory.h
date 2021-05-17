#ifndef _SHADOW_MEMORY_H
#define _SHADOW_MEMORY_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"

#include "util.h"

void init_shadow_memory(void);
void destroy_shadow_memory(void);

/* SHADOW DATA STRUCTURE */

#define DEP_MAX_LEN     65536
#define DEP_MAX_SIZE    256

typedef struct {
    UChar tainted;
    // dependency
    HChar* buffer;
    UInt size;
} Shadow;

/* MEMORY */

#define MMAP_SIZE	65536
#define CHUNK_SIZE	65536

typedef struct {
    Shadow* bytes[CHUNK_SIZE];
} Chunk;

Chunk* MemoryMap[MMAP_SIZE]; // designed for a 32-bit (4GB) address space (4Go = 4194304Ko = 64Ko*65536 = 65536o*65536)

Chunk* get_chunk_for_reading(UInt addr);
Chunk* get_chunk_for_writing(UInt addr);

/* REGISTERS */

#define TOTAL_SHADOW_REGISTERS  1024

/*typedef
    enum {
        host_EvC_FAILADDR,
        host_EvC_COUNTER,
        guest_EAX,
        guest_ECX,
        guest_EDX,
        guest_EBX,
        guest_ESP,
        guest_EBP,
        guest_ESI,
        guest_EDI,
        guest_CC_OP,
        guest_CC_DEP1,
        guest_CC_DEP2,
        guest_CC_NDEP,
        guest_DFLAG,
        guest_IDFLAG,
        guest_ACFLAG,
        guest_EIP,
        guest_FPREG0,
        guest_FPREG1,
        guest_FPREG2,
        guest_FPREG3,
        guest_FPREG4,
        guest_FPREG5,
        guest_FPREG6,
        guest_FPREG7,
        guest_FPTAG0,
        guest_FPTAG1,
        guest_FPTAG2,
        guest_FPTAG3,
        guest_FPTAG4,
        guest_FPTAG5,
        guest_FPTAG6,
        guest_FPTAG7,
        guest_FPROUND,
        guest_FC3210,
        guest_FTOP,
        guest_SSEROUND,
        guest_XMM0,
        guest_XMM1,
        guest_XMM2,
        guest_XMM3,
        guest_XMM4,
        guest_XMM5,
        guest_XMM6,
        guest_XMM7,
        guest_CS,
        guest_DS,
        guest_ES,
        guest_FS,
        guest_GS,
        guest_SS,
        guest_INVALID
    } guest_register; */

#define guest_INVALID 0xffffffff

Shadow registers[TOTAL_SHADOW_REGISTERS];

UInt get_reg_from_offset(UInt offset);

/* TEMPORARIES */

#define MAX_TEMPORARIES 2048

Shadow shadowTempArray[MAX_TEMPORARIES]; // a temporary is assigned before being used

/* MEMORY RANGE MANAGER */

#define BG_WHITE_LIST		1
//Stack of strings---------------------------------------
#define MAX_LEN 256
#define STACK_SIZE 102400

typedef
enum { Orig=1, VSh=2 } //, BSh=3 }  Not doing origin tracking
TempKind;

typedef
struct {
	TempKind kind;
	IRTemp   shadowV;
	//      IRTemp   shadowB;      Not doing origin tracking
}
TempMapEnt;

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
	HChar			info[255];
	Addr			begin;
	Addr      end;
	struct FilterList* next;
};


Bool getMemMapInfo(Addr addr, Int prot, HChar **pinfo);

//void addFilterList(struct FilterList** ppfl, const HChar* info, Addr avma, SizeT size );
//void delFilterList(struct FilterList** ppfl, const HChar* info, Addr avma, SizeT size );
//Addr isInFilterList(struct FilterList* ppfl, Addr a, HChar **pinfo);
//void releaseFilterlist(struct FilterList** ppfl);
void freeAllList();

void initSysLib();
void addFilterLib(const HChar* libname);

void addMonMap(Addr addr, Int size, Int prot, HChar *info);
void delMonMap(Addr addr, Int size);
Addr isMonMap(Addr addr, HChar **libName);
//Addr isMonLib(Addr addr, HChar **libName);
Addr isSysLib(Addr addr, HChar **libName);
UInt getMonMapSize(Addr a);
void dumpMemMap(Addr a);

#endif // SHADOW_MEMORY_H
