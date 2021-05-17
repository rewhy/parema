#ifndef _DT_INSTRUMENT_H
#define _DT_INSTRUMENT_H

#include "dt_taint.h"

extern Bool trace_obj_taint;
extern Bool trace_ins_taint;
extern Bool trace_art_method;

typedef enum { Orig=1, VSh=2 }
TempKind;

typedef struct {
	TempKind	kind;
	IRTemp		shadowV;
} TempMapEnt;

/* Carries around state during instrumentation */
typedef struct _MCEnv {
	IRSB*		sb;
	Bool		trace;
	/* A table [0 .. #temps_in_sb-1] which gives the current kind
	 * and possibly shadow temps for each temp in the IRSB being
	 * constructed.
	 */
	XArray* tmpMap;
	Bool		bogusLiterals;
	/* Defult True on MacOS and False else */
	Bool		useLLVMworkarounds;
	const		VexGuestLayout*	layout;
	IRType	hWordTy;
} MCEnv;

/* implement in file dt_instrument.c */
IRSB* DT_(instrument)( VgCallbackClosure* closure, 
		IRSB* sbIn,
		const VexGuestLayout*		guestlayout,
		const VexGuestExtents*	vge,
		const VexArchInfo*			archinfo_host,
		IRType	gWordTy, IRType	hWordTy );

/*-- Defined in dt_stmt2.c --*/
extern void DT_(smt2_preamble) (void);


#endif // _DT_INSTRUMENT_h
