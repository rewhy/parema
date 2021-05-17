/*  This file is part of Fuzzgrind.
 *  Copyright (C) 2009 Gabriel Campana
 *  
 *  Based heavily on Flayer by redpig@dataspill.org
 *  Copyright (C) 2006,2007 Will Drewry <redpig@dataspill.org>
 *  Some portions copyright (C) 2007 Google Inc.
 * 
 *  Based heavily on MemCheck by jseward@acm.org
 *  MemCheck: Copyright (C) 2000-2007 Julian Seward
 *  jseward@acm.org
 * 
 * 
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307, USA.
 *  
 *  The GNU General Public License is contained in the file LICENCE.
 */


#include "pub_tool_basics.h"
#include "pub_core_threadstate.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_machine.h"
#include "pub_tool_aspacemgr.h"
//#include "pub_tool_threadstate.h"
#include "pub_tool_vkiscnums.h"
#include "valgrind.h"

/* Pulled in to get the threadstate */
//#include "../coregrind/pub_core_basics.h"
//#include "../coregrind/pub_core_vki.h"
//#include "../coregrind/pub_core_vkiscnums.h"
//#include "../coregrind/pub_core_threadstate.h"
#include "fz.h"

#if defined(VGA_x86) || defined(VGA_arm)
#  define GP_COUNT 8
#elif defined(VGA_amd64) || defined(VGA_arm64)
#  define GP_COUNT 16
#elif defined(VGA_ppc32) || defined(VGA_ppc64)
#  define GP_COUNT 34
#else
#  error Unknown arch
#endif




typedef struct {
	UWord args[GP_COUNT];
	UInt used;
} GuestArgs;

// VG_(N_THREADS) - do threads actually run concurrently here too?
#ifdef T341
static GuestArgs guest_args[VG_N_THREADS];
// Set up GuestArgs prior to arg_collector
static void populate_guest_args(ThreadId tid) {
	/* This is legacy.  I was using apply_GPs callback,
	 * but it isn't threadsafe.  So for now, we bind to 
	 * the ThreadState functions for the specific x86 arch
	 */
	ThreadState *tst =  VG_(get_ThreadState) (tid);
	VexGuestArchState *arch_state = &tst->arch.vex;
	//guest_args[tid].args[1] = arch_state->guest_R0;
  guest_args[tid].args[1] = ts->arch.vex.guest_ECX;
	//guest_args[tid].args[2] = arch_state->guest_R1;
	guest_args[tid].args[2] = ts->arch.vex.guest_EDX;
	//guest_args[tid].args[3] = arch_state->guest_R2;
	guest_args[tid].args[3] = ts->arch.vex.guest_EBX;
	//guest_args[tid].args[4] = arch_state->guest_R3;
	guest_args[tid].args[4] = ts->arch.vex.guest_ESI;
	//guest_args[tid].args[5] = arch_state->guest_R4;
	guest_args[tid].args[5] = ts->arch.vex.guest_EDI;
	//guest_args[tid].args[6] = arch_state->guest_R5;
	guest_args[tid].args[6] = ts->arch.vex.guest_EBP;
	//guest_args[tid].args[7] = arch_state->guest_R6;
	guest_args[tid].args[7] = ts->arch.vex.guest_EAX;
	guest_args[tid].used = 8;
}
#endif


#define MAX_PATH    256
static void resolve_fd(Int fd, Char *path, Int max) {
	Char src[MAX_PATH]; // be lazy and use their max
	Int len = 0;
	// TODO: Cache resolved fds by also catching open()s and close()s
	VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), fd);
	len = VG_(readlink)(src, path, max);
	// Just give emptiness on error.
	if (len == -1) {
		len = 0;
	}
	path[len] = '\0';
}


// TODO: copy linked list setup for allocated_fds in clo_track_fds.
//       or see if they will patch it to allow tools to access it.
/* enforce an arbitrary maximum */
#define MAXIMUM_FDS 256
Bool tainted_fds[NTHREADS][MAXIMUM_FDS];
//static Bool tainted_fds[VG_N_THREADS][MAXIMUM_FDS];
UInt position_fds[NTHREADS][MAXIMUM_FDS];
//static UInt position_fds[VG_N_THREADS][MAXIMUM_FDS];

void FZ_(setup_tainted_map)(void) {
	ThreadId t = 0;

	VG_(memset)(tainted_fds, False, sizeof(tainted_fds));
	VG_(memset)(position_fds, 0, sizeof(position_fds));

	/* Taint stdin if specified */
	if (FZ_(clo_taint_stdin)) {
		for(t = 0; t < NTHREADS; t++) {
			tainted_fds[t][0] = True;
		}
	}
}

//  int open (const char *filename, int flags[, mode_t mode])
void FZ_(syscall_open)(ThreadId tid, UWord *args, UInt nArgs, SysRes res) {
	Char fdpath[MAX_PATH];
	Int fd = sr_Res(res);

	// Nothing to do if no file tainting
	// But, if stdin tainting, always taint fd 0...
	VG_(printf)("FZ_(clo_taint_file)=%d\n", FZ_(clo_taint_file) ? 1 : 0);
	if (!FZ_(clo_taint_file)/* && (fd != 0 || !FL_(clo_taint_stdin))*/) {
		return;
	}

	if (fd > -1 && fd < MAXIMUM_FDS) {
		resolve_fd(fd, fdpath, MAX_PATH-1);
		VG_(printf)("%s %s\n", fdpath, FZ_(clo_file_filter));
		tainted_fds[tid][fd] = (VG_(strncmp)(fdpath, FZ_(clo_file_filter), VG_(strlen)(FZ_(clo_file_filter))) == 0);
		if (tainted_fds[tid][fd]) {
			position_fds[tid][fd] = 0;
		}
#ifdef FZ_DEBUG
		if (tainted_fds[tid][res.res]) {
			VG_(printf)("tainting file %d\n", res.res);
		}
		else {
			VG_(printf)("not tainting file %d\n", res.res);
		}
#endif
	}
}

// ssize_t  read(int fildes, void *buf, size_t nbyte);
void FZ_(syscall_read)(ThreadId tid, UWord *args, UInt nArgs, SysRes res) {
	UInt i, j, k;
	Int fd = -1;
	Char *data = NULL;
	//fd = guest_args[tid].args[3];
	fd = args[0];
	//data = (Char *)(guest_args[tid].args[1]);
	data = (Char*)args[1];

	if (fd < 0 || sr_Res(res) <= 0 || !tainted_fds[tid][fd]) {
		return;
	}

	k = position_fds[tid][fd];
	for (i = 0; i < sr_Res(res); i++) {
		j = add_dependency_addr((Addr)((UInt)data + i), 8);
		VG_(printf)("[+] read() tainting byte %d (0x%08x)\n", k + i, (UInt)(data + i));
		VG_(snprintf)(depaddr8[j].cons, XXX_MAX_BUF, "input(%d)", k + i);
	}
	position_fds[tid][fd] += sr_Res(res);
}

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void FZ_(syscall_mmap2)(ThreadId tid, UWord *args, UInt nArgs, SysRes res) {
	UInt i, j, length, offset;
	Int fd = -1;
	Char *data = NULL;
	//fd = guest_args[tid].args[5];
	fd = args[4];
	//length = guest_args[tid].args[1];
	length = args[1];
	data = (Char *)sr_Res(res);
	//offset = guest_args[tid].args[6];
	offset = args[5];

	//VG_(printf)("[+] mmap2(0x%08x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = 0x%08x\n", guest_args[tid].args[3], length, guest_args[tid].args[2], guest_args[tid].args[4], fd, offset, data);

	if (fd < 0 || sr_Res(res) == -1 || !tainted_fds[tid][fd]) {
		return;
	}

	for (i = 0; i < length; i++) {
		j = add_dependency_addr((Addr)((UInt)data + i), 8);
		VG_(printf)("[+] mmap2() tainting byte %d (0x%08x)\n", offset + i, (UInt)(data + i));
		VG_(snprintf)(depaddr8[j].cons, XXX_MAX_BUF, "input(%d)", offset + i);
	}
}

// int munmap(void *addr, size_t len);
void FZ_(syscall_munmap)(ThreadId tid, UWord *args, UInt nArgs, SysRes res) {
	UInt i, start, length;
	//length = guest_args[tid].args[1];
	length = args[1];
	//start = guest_args[tid].args[2];
	start = args[0];

	//VG_(printf)("[+] munmap(0x%08x, 0x%x)\n", start, length);

	if (sr_Res(res) != 0) {
		return;
	}

	for (i = 0; i < depaddr8_number; i++) {
		if (depaddr8[i].value.addr == start) {
			break;
		}
	}

	if (i == depaddr8_number) {
		return;
	}

	for (i = 0; i < length; i++) {
		del_dependency_addr(start + i, 8);
	}
}

// off_t lseek(int fd, off_t offset, int whence);
void FZ_(syscall_lseek)(ThreadId tid, UWord *args, UInt nArgs, SysRes res) {
	Int fd;
	//fd = guest_args[tid].args[3];
	fd = args[0];

	if (fd < 0 || sr_Res(res) == -1 || !tainted_fds[tid][fd]) {
		return;
	}

	position_fds[tid][fd] = sr_Res(res);
}

//   int close (int filedes) 
void FZ_(syscall_close)(ThreadId tid, UWord *args, UInt nArgs, SysRes res) {
	Int fd = -1;
	fd = args[0];
	if (fd > -1 && fd < MAXIMUM_FDS) {
		tainted_fds[tid][fd] = False;
	}
}
