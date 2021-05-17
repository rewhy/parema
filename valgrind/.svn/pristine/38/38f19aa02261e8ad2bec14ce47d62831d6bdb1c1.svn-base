#include "shadow_memory.h"
#include "pub_tool_libcprint.h"     // VG_(printf)
#include "pub_tool_libcbase.h"      // VG_(memset)
#include "pub_tool_mallocfree.h"    // VG_(malloc) VG_(free)
#include "pub_tool_libcassert.h"    // VG_(tool_panic)

void init_shadow_memory(void)
{
    VG_(memset)(MemoryMap, 0, sizeof(Chunk*)*MMAP_SIZE);

    VG_(memset)(registers, 0, sizeof(Shadow)*TOTAL_SHADOW_REGISTERS);

    VG_(memset)(shadowTempArray, 0, sizeof(Shadow)*MAX_TEMPORARIES);
}

void destroy_shadow_memory(void)
{
    Chunk* chunk;
    Shadow* shadow;
    unsigned int i, j;

    for (i = 0; i < MMAP_SIZE; i++)
    {
        chunk = MemoryMap[i];
        if (chunk != NULL)
        {
            for (j = 0; j < CHUNK_SIZE; j++)
            {
                shadow = chunk->bytes[j];
                if (shadow != NULL)
                {
                    if (shadow->buffer != NULL) {
                        VG_(free)(shadow->buffer);
                    }

                    VG_(free)(shadow);
                }
            }

            VG_(free)(chunk);
        }
    }
}

//
//  MEMORY
//

Chunk* get_chunk_for_reading(UInt addr)
{
    return MemoryMap[(addr >> 16) & 0xffff];
}

Chunk* get_chunk_for_writing(UInt addr)
{
    UInt x = (addr >> 16) & 0xffff;

    if (MemoryMap[x] == NULL)
    {
        MemoryMap[x] = VG_(malloc)("", sizeof(Chunk));
        VG_(memset)(MemoryMap[x], 0, sizeof(Chunk));
    }

    return MemoryMap[x];
}

//
//  REGISTERS
//

guest_register VexGuestState[] = {
    host_EvC_FAILADDR,
    host_EvC_FAILADDR,
    host_EvC_FAILADDR,
    host_EvC_FAILADDR,
    host_EvC_COUNTER,
    host_EvC_COUNTER,
    host_EvC_COUNTER,
    host_EvC_COUNTER,
    guest_EAX,
    guest_EAX,
    guest_EAX,
    guest_EAX,
    guest_ECX,
    guest_ECX,
    guest_ECX,
    guest_ECX,
    guest_EDX,
    guest_EDX,
    guest_EDX,
    guest_EDX,
    guest_EBX,
    guest_EBX,
    guest_EBX,
    guest_EBX,
    guest_ESP,
    guest_ESP,
    guest_ESP,
    guest_ESP,
    guest_EBP,
    guest_EBP,
    guest_EBP,
    guest_EBP,
    guest_ESI,
    guest_ESI,
    guest_ESI,
    guest_ESI,
    guest_EDI,
    guest_EDI,
    guest_EDI,
    guest_EDI,
    guest_CC_OP,
    guest_CC_OP,
    guest_CC_OP,
    guest_CC_OP,
    guest_CC_DEP1,
    guest_CC_DEP1,
    guest_CC_DEP1,
    guest_CC_DEP1,
    guest_CC_DEP2,
    guest_CC_DEP2,
    guest_CC_DEP2,
    guest_CC_DEP2,
    guest_CC_NDEP,
    guest_CC_NDEP,
    guest_CC_NDEP,
    guest_CC_NDEP,
    guest_DFLAG,
    guest_DFLAG,
    guest_DFLAG,
    guest_DFLAG,
    guest_IDFLAG,
    guest_IDFLAG,
    guest_IDFLAG,
    guest_IDFLAG,
    guest_ACFLAG,
    guest_ACFLAG,
    guest_ACFLAG,
    guest_ACFLAG,
    guest_EIP,
    guest_EIP,
    guest_EIP,
    guest_EIP,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG0,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG1,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG2,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG3,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG4,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG5,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG6,
    guest_FPREG7,
    guest_FPREG7,
    guest_FPREG7,
    guest_FPREG7,
    guest_FPREG7,
    guest_FPREG7,
    guest_FPREG7,
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
    guest_FPROUND,
    guest_FPROUND,
    guest_FPROUND,
    guest_FC3210,
    guest_FC3210,
    guest_FC3210,
    guest_FC3210,
    guest_FTOP,
    guest_FTOP,
    guest_FTOP,
    guest_FTOP,
    guest_SSEROUND,
    guest_SSEROUND,
    guest_SSEROUND,
    guest_SSEROUND,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM0,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM1,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM2,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM3,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM4,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM5,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM6,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_XMM7,
    guest_CS,
    guest_CS,
    guest_DS,
    guest_DS,
    guest_ES,
    guest_ES,
    guest_FS,
    guest_FS,
    guest_GS,
    guest_GS,
    guest_SS,
    guest_SS
};

guest_register get_reg_from_offset(UInt offset)
{
    if (offset >= 300)
        return guest_INVALID;

    return VexGuestState[offset];
}
