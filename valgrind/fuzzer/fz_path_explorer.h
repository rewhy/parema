#ifndef FZ_PATH_EXPLORER_H
#define FZ_PATH_EXPLORER_H

#include "fz_oatdexparse.h"

#define MAX_STACK_SIZE	1024 * 1024
#define MAX_INPUT_SIZE	256

struct inMemInfo{
	MthNode *mNode;

	Int pathIndex;
	Int branchIndex;

	UInt	 tid;
	UInt	 mthStackSize;

	Int    begIndex;
	HChar* begMth;
	Int    endIndex;
	HChar* engMth;

	UChar inputBuf[MAX_INPUT_SIZE];
	UInt  inputSize;

	Addr codeAddr;
	Addr codeEnd;

	Addr begAddr;
	Addr retAddr;
	Addr stackTop;
	Addr stackBottom;
	UChar orig_stack[MAX_STACK_SIZE];
	ThreadState orig_threadState;
	VexGuestArchState orig_archState0;
};

void saveState(struct inMemInfo *stateInfo);
void recoverState(struct inMemInfo *stateInfo);
void setInput(const struct inMemInfo *stateInfo, const UChar* newInput);

void initPathExploring(UInt index);
void outputConstraint(UChar *log, Bool isTaken);
void finiPathExploring();
Bool getInput(UChar *buf, UInt len, UInt index);

void setRegValue(UInt offset, UInt value);
#endif // FZ_PATH_EXPLORER_H
