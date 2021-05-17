// fz_path_explorer.c
#include "pub_tool_guest.h"
#include "pub_tool_debuginfo.h"
#include "pub_core_threadstate.h"

#include "fz_path_explorer.h"

#include "util.h"
#include "shadow_memory.h"

static UInt inFd = 0;
static UInt outFd = 0;

static
void printArchState(VexGuestArchState *state) {
	MY_LOGI("Arch State:\n"); 
#if defined(VGPV_arm_linux_android)
	MY_LOGI(" -- r0 =%#lx\n", state->guest_R0);
	MY_LOGI(" -- r1 =%#lx\n", state->guest_R1);
	MY_LOGI(" -- r2 =%#lx\n", state->guest_R2);
	MY_LOGI(" -- r3 =%#lx\n", state->guest_R3);
	MY_LOGI(" -- r4 =%#lx\n", state->guest_R4);
	MY_LOGI(" -- r5 =%#lx\n", state->guest_R5);
	MY_LOGI(" -- r6 =%#lx\n", state->guest_R6);
	MY_LOGI(" -- r7 =%#lx\n", state->guest_R7);
	MY_LOGI(" -- r8 =%#lx\n", state->guest_R8);
	MY_LOGI(" -- r9 =%#lx\n", state->guest_R9);
	MY_LOGI(" -- r10=%#lx\n", state->guest_R10);
	MY_LOGI(" -- r11=%#lx\n", state->guest_R11);
	MY_LOGI(" -- r12=%#lx\n", state->guest_R12);
	MY_LOGI(" -- sp =%#lx\n", state->guest_R13);
	MY_LOGI(" -- lr =%#lx\n", state->guest_R14);
	MY_LOGI(" -- pc =%#lx\n", state->guest_R15T);
#endif
} 


void saveState(struct inMemInfo *stateInfo) {
	ThreadId tid = VG_(get_running_tid)();
	UInt stackSize = stateInfo->stackTop - stateInfo->stackBottom;
	EXP_LOGI("saveStack() 0x%08x - 0x%08x size=%d\n", stateInfo->stackBottom, stateInfo->stackTop, stackSize);

	VG_(get_shadow_regs_area) (tid, 
			(UChar*)&stateInfo->orig_archState0,
			0,
			0,
			sizeof(VexGuestArchState));
	VG_(memcpy)((Addr)stateInfo->orig_stack, stateInfo->stackBottom, stackSize);
	//VG_(memcpy)((Addr)&stateInfo->threadStateBackup, (Addr)tst, sizeof(ThreadState));
	//VG_(memcpy)((Addr)&stateInfo->archStateBackup, (Addr)arch_state, sizeof(VexGuestArchState));
	ThreadState *tst = VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	printArchState(arch_state);
}

void recoverState(struct inMemInfo *stateInfo) {
	ThreadId tid = VG_(get_running_tid)();
	UInt stackSize = stateInfo->stackTop - stateInfo->stackBottom;
	EXP_LOGI("recoverStack() 0x%08x - 0x%08x size=%d\n", stateInfo->stackBottom, stateInfo->stackTop, stackSize);

	VG_(set_shadow_regs_area) (tid, 
			0,
			8,
			sizeof(VexGuestArchState)-8,
			(UChar*)&stateInfo->orig_archState0+8);
	/*VG_(set_shadow_regs_area) (tid, 
			0,
			72,
			sizeof(VexGuestArchState)-72,
			(UChar*)&stateInfo->orig_archState0+72);*/
	//VG_(memcpy)((Addr)arch_state, (Addr)&stateInfo->archStateBackup, sizeof(VexGuestArchState));
	//VG_(memcpy)((Addr)tst, (Addr)&stateInfo->threadStateBackup, sizeof(ThreadState));
	VG_(memcpy)(stateInfo->stackBottom, stateInfo->orig_stack, stackSize);
	ThreadState *tst = VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	printArchState(arch_state);
}
void setInput(const struct inMemInfo *stateInfo, const UChar* newInput) {
}
void setRegValue(UInt offset, UInt value) {
	EXP_LOGI("setRegValue() offset=%d value=%d\n", offset, value);
	ThreadId tid = VG_(get_running_tid)();
	ThreadState *tst = VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	*((Int*)((Addr)arch_state + offset)) = value;
}

void initPathExploring(UInt index) {
	UChar filename[256];
	VG_(sprintf)(filename, "/data/local/tmp/fuzz/output_%d.txt", index);
	init_shadow_memory();
	outFd = VG_(fd_open)(filename, VKI_O_WRONLY | VKI_O_CREAT | VKI_O_TRUNC, 0);
	EXP_LOGI("initPathExploring()\n");
}
void outputConstraint(UChar *log, Bool isTaken) {
	HChar buf[DEP_MAX_LEN];
	if(outFd > 0) {
		if(isTaken)
				VG_(sprintf)(buf, "branch: TAKEN(%s)\n", log);
		else
				VG_(sprintf)(buf, "branch: NOT_TAKEN(%s)\n", log);
		VG_(write)(outFd, buf, VG_(strlen)(buf));
	}
}
void finiPathExploring() {
	if(outFd > 0) {
		VG_(close)(outFd);
		outFd = 0;
	}
	clear_shadow_memory();
	EXP_LOGI("finiPathExploring()\n");
}
Bool getInput(UChar *buf, UInt len, UInt index) {
	UInt tries = 0, res = 0;
	UChar filename[256];
	VG_(sprintf)(filename, "/data/local/tmp/fuzz/input_%d.txt", index);
	while(tries < 0x8) {
		if(VG_(access)(filename, True, False, False) == 0)
			break;
		VG_(system)("/system/bin/sleep 1");
		tries++;
	}
	if(VG_(access)(filename, True, False, False) == 0) {
		inFd = VG_(fd_open)(filename, VKI_O_RDONLY, VKI_S_IRUSR);
		if(inFd > 0) {
			res = VG_(read)(inFd, buf, len);
			//EXP_LOGI("0x%02x 0x%02x 0x%02x 0x%02x\n",
			//		buf[0], buf[1], buf[2], buf[3]);
			VG_(close)(inFd);
		}
	}
	return (res > 0 ? True : False);
}

