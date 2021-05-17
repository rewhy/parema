// dt_syswrap.c
#include "pub_tool_basics.h"
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
#include "pub_tool_threadstate.h"
#include "pub_tool_stacktrace.h"   // for VG_(get_and_pp_StackTrace)
#include "pub_tool_debuginfo.h"	   // VG_(describe_IP), VG_(get_fnname)

#include "pub_core_threadstate.h"

#include "valgrind.h"

#include "util.h"
#include "do_wrappers.h"

extern Bool do_is_start;
extern HChar* loadingAppLib;
extern UInt is_trace_irst;
extern UInt is_in_vm;

struct fd_info fds[TG_N_THREADS][FD_MAX];


Addr printExecContext()
{
	ThreadId tid			= VG_(get_running_tid)();
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState	*arch_state = &tst->arch.vex;
	UWord r0, r1, r2, r3, r4, r8, r9, r10, r11, r12, sp, lr, pc;
#if defined(VGPV_arm_linux_android)
	r0  = arch_state->guest_R0;
	r1  = arch_state->guest_R1;
	r2  = arch_state->guest_R2;
	r3  = arch_state->guest_R3;
	r4  = arch_state->guest_R4;
	r8  = arch_state->guest_R8;
	r9  = arch_state->guest_R9;
	r10 = arch_state->guest_R10;
	r11 = arch_state->guest_R11;
	r12 = arch_state->guest_R12;
	sp  = arch_state->guest_R13;
	lr  = arch_state->guest_R14;
	pc  = arch_state->guest_R15T;
#endif
	VG_(printf)("Context status: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
			r0, r1, r2, r3, r4, r8, r9, r10, r11, r12, sp, lr, pc);
	return pc;
}

	static 
Bool identifyFdType(ThreadId tid, Int fd, HChar *path) 
{
	Int len = VG_(strlen)(path);

	if( (len > 8) && (VG_(memcmp)(path, "/system/", 8) == 0) ) {
		fds[tid][fd].type = FdSystemLib;
	} else if(VG_(memcmp)(path, "/proc/", 6) == 0) {
		fds[tid][fd].type = FdProcMap;
	} else if( (VG_(memcmp)(path, "/dev/", 5) == 0)
			|| (VG_(memcmp)(path, "/sys/devices/", 13) == 0)) {
		fds[tid][fd].type = FdDevice;
	}	else {
		if( VG_(memcmp)((HChar*)&path[len-3], ".so", 3) == 0) {
			fds[tid][fd].type = FdAppLib;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".apk", 4) == 0) {
			fds[tid][fd].type = FdAppApk;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".jar", 4) == 0) {
			fds[tid][fd].type = FdAppJar;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".dex", 4) == 0) {
			if( len > 40 && VG_(memcmp)(path, "/data/dalvik-cache/system@framework@", 36) == 0) {
				fds[tid][fd].type = FdFrameworkDex;
			} else {
				fds[tid][fd].type = FdAppDex;
			}
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".oat", 4) == 0) {
			if( len > 40 && VG_(memcmp)(path, "/data/dalvik-cache/", 19) == 0) {
				fds[tid][fd].type = FdFrameworkOat;
			} else {
				fds[tid][fd].type = FdAppOat;
			}
		} else if( VG_(memcmp)((HChar*)&path[len-5], ".odex", 4) == 0) {
			fds[tid][fd].type = FdAppOdex;
		}
	}
	VG_(strcpy)(fds[tid][fd].name, path);
	if(fds[tid][fd].type > 0) {
		return True;
	} else {
		fds[tid][fd].type = FdUnknown;
		return False;
	}
}

static
INLINE Bool isThirdFd( Int tid, Int fd) {
	if (fd <= 0)
		return False;

	/*if(VG_(memcmp)("/data/", fds[tid][fd].name, 6) == 0)
		return True;
	else
		return False;*/
	if ( (fds[tid][fd].type == FdAppDex)
			|| (fds[tid][fd].type == FdAppOdex)
			|| (fds[tid][fd].type == FdAppApk)
			|| (fds[tid][fd].type == FdAppLib)
			|| (fds[tid][fd].type == FdAppJar)
			|| (fds[tid][fd].type == FdAppOat)
			|| (fds[tid][fd].type == FdUnknown) ) {
		return True;
	}
	return False;
}


	static
void resolve_filename(UWord fd, HChar *path, Int max)
{
	HChar src[FD_MAX_PATH];
	Int len = 0;

	// TODO: Cache resolved fds by also catching open()s and close()s
	VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), (int)fd);
	len = VG_(readlink)(src, path, max);

	// Just give emptiness on error.
	if (len == -1) len = 0;
	path[len] = '\0';
}

void DO_(syscall_madvise)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UInt addr	= args[0];
	UInt size = args[1];
	Int  devi = args[2];
	if(do_is_start == False)
		return;

#ifdef DBG_SYSCALL
	SYS_LOGI("%d madvise() addr=0x%08x length=%d device=%d\n", tid, addr, size, devi);
#endif
}
void DO_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	// off_t lseek(int fd, off_t offset, int whence);
	Int   fd      = args[0];
	ULong offset  = args[1];
	UInt  whence  = args[2];

	if (fd >= FD_MAX || fd <= 0)
		return;

	Int retval = sr_Res(res);

#ifdef DBG_SYSCALL
	VG_(printf)("syscall _lseek %d %d ", tid, fd);
	VG_(printf)("offset: 0x%x whence: 0x%x ", (UInt)offset, whence);
	VG_(printf)("retval: 0x%x read_offset: 0x%x\n", retval, fds[tid][fd].offset);
#endif
	if( whence == 0/*SEEK_SET*/ )
		fds[tid][fd].offset = 0 + (UInt)offset;
	else if( whence == 1/*SEEK_CUR*/ )
		fds[tid][fd].offset += (UInt)offset;
	if( whence == 2/*SEEK_END*/ )
		fds[tid][fd].offset = retval;
	else {
		VG_(printf)("whence %x\n", whence);
		tl_assert(0);
	}

}

// int  _llseek(int fildes, ulong offset_high, ulong offset_low, loff_t *result,, uint whence);
void DO_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	Int   fd           = args[0];
	ULong offset_high  = args[1];
	ULong offset_low   = args[2];
	UInt  result       = args[3];
	UInt  whence       = args[4];
	ULong offset;

	if (fd >= FD_MAX || fd <= 0)
		return;
	Int retval = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("syscall _llseek %d %d ", tid, fd);
	VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", (UInt)offset_high, (UInt)offset_low, result, whence);
	VG_(printf)("0x%x\n", retval);
#endif
	offset = (offset_high<<32) | offset_low;
	if( whence == 0)
		fds[tid][fd].offset = 0 + (UInt)offset;
	else if (whence == 1) 
		fds[tid][fd].offset += (UInt)offset;
	else {
		VG_(printf)("whence %x\n", whence);
		tl_assert(0);
	}
}

// ssize_t  read(int fildes, void *buf, size_t nbyte);
void DO_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	Int   fd           = args[0];
	HChar *data        = (HChar *)args[1];		// Memery buffer
	UInt  curr_offset  = fds[tid][fd].offset;
	Int   curr_len     = sr_Res(res);					// Data length

	DO_(check_fd_access)(tid, fd, FD_READ);
	if (curr_len == 0) return;

	if (do_is_start == False)
		return;
	if (fd < 0 || fd >= FD_MAX ) {
	} else {
		fds[tid][fd].offset += curr_len;
	}

#if 0
	if ( isThirdFd(tid, fd) ) {
		//addFilterList(&dlibl, fds[tid][fd].name, (Addr)data, curr_len);
	} else {
		return;
	}
#endif
#ifdef DBG_SYSCALL
	//if( (fd > 0) && (fds[tid][fd].type == FdProcMap))
	//	return;
	SYS_LOGI("%d read(%d) offset:0x%08x 0x%08x-0x%08x %d %s\n", 
			tid, fd, fds[tid][fd].offset-curr_len, (Int)data, (Int)data+curr_len-1, curr_len, fds[tid][fd].name);
#endif
}

// ssize_t pread(int fildes, void *buf, size_t nbyte, size_t offset);
void DO_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	Int   fd           = args[0];
	HChar *data        = (HChar *)args[1];
	UInt  curr_offset  = (Int)args[3];
	Int   curr_len     = sr_Res(res);

	if (curr_len == 0) return;

	if (fd < 0 || fd >= FD_MAX )
		return;
	fds[tid][fd].offset = curr_offset + curr_len;
	
	if (do_is_start == False)
		return;
#if 0
	//if (fds[tid][fd].type == FdAppLib ) {
	if ( isThirdFd(tid, fd)  && curr_len > 0) {
		//addFilterList(&dlibl, fds[tid][fd].name, (Addr)data, curr_len);
	} else {
		return;
	}
#endif
#ifdef DBG_SYSCALL
	SYS_LOGI("%d pread(%d) offset:0x%08x 0x%08x-0x%08x %d %s\n", 
			tid, fd, curr_offset, (Int)data, (Int)data+curr_len-1, curr_len, fds[tid][fd].name);
#endif
}

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
void DO_(syscall_readv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int	re			= sr_Res(res);
	if (do_is_start == False)
		return;
#if 0
	if ( isThirdFd(tid, fd) && re > 0 ) {
		//addFilterList(&dlibl, fds[tid][fd].name, (Addr)iov->iov_base, iov->iov_len);
	} else {
		return;
	}
#endif
#ifdef DBG_SYSCALL
	SYS_LOGI("%d readv(%d) 0x%x %d %s\n", 
			tid, fd, (Int)iov->iov_base, iov->iov_len,
			(fd > 0) ? fds[tid][fd].name : ""
			);
#endif
}
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
void DO_(syscall_preadv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int   offset  = args[3];
	int		re			= sr_Res(res);
	if (do_is_start == False)
		return;
#if 0
	if ( isThirdFd(tid, fd) && re > 0) {
		//addFilterList(&dlibl, fds[tid][fd].name, (Addr)iov->iov_base, iov->iov_len);
	} else {
		return;
	}
#endif
#ifdef DBG_SYSCALL
	SYS_LOGI("%d preadv(%d) offset=0x%x 0x%x %d\n", 
			tid, fd, offset, (Int)iov->iov_base, iov->iov_len);
#endif
}
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
void DO_(syscall_writev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	Int	re			= sr_Res(res);
	//if (do_is_start == False || re < 0)
	if (re < 0)
		return;
#ifdef DBG_SYSCALL
	SYS_LOGI("%d writev(%d) offset=0x%x 0x%x %d\n", 
			tid, fd, (Int)iov->iov_base, iov->iov_len, re);
#endif
}
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
void DO_(syscall_pwritev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int		  offset  = args[3];
	int			re			= sr_Res(res);
	if (do_is_start == False || re < 0)
		return;
#ifdef DBG_SYSCALL
	SYS_LOGI("%d pwritev(%d) offset=0x%x 0x%x %d\n", 
			tid, fd, offset, (Int)iov->iov_base, iov->iov_len);
#endif
}
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void DO_(syscall_mmap)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int begin_addr = sr_Res(res);
	Int size  = (Int)args[1];
	Int prot = (Int)args[2];
	Int flags = (Int)args[3];
	Int  fd = (Int)args[4];
	UInt offset = (Int)args[5];
	//if( begin_addr <= 0 || prot == PROT_NONE )
	if( begin_addr <= 0)
		return;
#ifdef DBG_SYSCALL
	SYS_LOGI("%d mmap(%2d) off_0x%08x -> 0x%08x-0x%08x %6d %c%c%c 0x%x %s\n", 
			tid, fd, offset, begin_addr, begin_addr+size, size, 
			(prot & PROT_READ) ? 'r' : '-',
			(prot & PROT_WRITE) ? 'w' : '-',
			(prot & PROT_EXEC) ? 'x' : '-',
			flags,
			fd > 0 ? fds[tid][fd].name : "");
#endif
	if ( isThirdFd(tid, fd) ) {
		if(fds[tid][fd].type == FdAppDex) {
			SYS_LOGI("Third party app's dex(%d) file is mmaped 0x%08x-0x%08x\n", 
					fd, begin_addr, begin_addr+size-1);
			//DexMemParse((UChar*)begin_addr, size);
		} else if(fds[tid][fd].type == FdAppOat) {
			SYS_LOGI("Third party app's oat(%d) file is mmaped 0x%08x-0x%08x\n", 
					fd, begin_addr, begin_addr+size-1);
			//oatDexParse((UChar*)begin_addr, size);
		} else if(fds[tid][fd].type == FdAppLib) {
			if((prot & PROT_EXEC) && /*loadingAppLib*/do_is_start)/* Executable */
				addMonMap(begin_addr, size, prot, fds[tid][fd].name);
		}
	} else if ( fd == -1 && do_is_start) {
		if(prot & PROT_EXEC)
		{
			addMonMap(begin_addr, size, prot, "mmap.allocation.x");
		} /*else if(prot & PROT_WRITE) {
			addMonMap(begin_addr, size, prot, "mmap.allocation.w");
		}*/
	}
}

// int mprotect(void *addr, size_t len, int prot);
void DO_(syscall_mprotect) ( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  size = (Int)args[1];
	Int  prot = (Int)args[2];
	Int  re  = sr_Res(res);
	HChar *memInfo = NULL;
	if (do_is_start == False)
		return;
	if( prot == PROT_NONE )
		return;
#if 1 //DBG_SYSCALL
	Addr lib_addr = isSysLib(begin_addr, &memInfo);
	if(lib_addr > 0) {
		SYS_LOGI("%d mprotect() 0x%08x-0x%08x %c%c%c %s 0x%08x\n",
				tid, begin_addr, begin_addr+size,
				(prot & PROT_READ) ? 'r' : '-',
				(prot & PROT_WRITE) ? 'w' : '-',
				(prot & PROT_EXEC) ? 'x' : '-',
				memInfo == NULL ? "lib???" : memInfo,
				lib_addr);
		return;
	} else {
		if( re >= 0) {
			SYS_LOGI("%d mprotect() 0x%08x-0x%08x %c%c%c %s\n",
					tid, begin_addr, begin_addr+size,
					(prot & PROT_READ) ? 'r' : '-',
					(prot & PROT_WRITE) ? 'w' : '-',
					(prot & PROT_EXEC) ? 'x' : '-',
					memInfo == NULL ? "???" : memInfo);
		}
	}
#endif
	if((prot & PROT_EXEC) && do_is_start && re >= 0) { /* Executable */
		memInfo = VG_(describe_IP)(begin_addr, NULL);
		//addMonMap(begin_addr, size, prot, "mprotect.to.x");
		addMonMap(begin_addr, size, prot, memInfo == NULL ? "mprotect.to.x" : memInfo);
	} else {
		delMonMap(begin_addr, size);
	}
}

// int msync(void *addr, size_t length, int flags);
void DO_(syscall_msync)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  length		  = (Int)args[1];
	Int	 flags			= (Int)args[2];
	Int  re				= sr_Res(res);
#ifdef DBG_SYSCALL
	if(re == 0) {
		SYS_LOGI("%d msync() 0x%08x-0x%08x %d\n",
				tid, begin_addr, begin_addr+length, flags);
	}
#endif
}

// int munmap(void *addr, size_t len); 
void DO_(syscall_munmap)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  size = (Int)args[1];
	if (do_is_start == False)
		return;
	if( begin_addr > 0) {
#ifdef DBG_SYSCALL
		SYS_LOGI("%d munmap() 0x%08x-0x%08x\n", 
				tid, begin_addr, begin_addr+size);
#endif
		delMonMap(begin_addr, size);
	}
}

// void exit(int status)
void DO_(syscall_pre_exit)( ThreadId tid, UWord* args, UInt nArgs) {
#ifdef DBG_SYSCALL
	SYS_LOGI("%d exit() status=%d\n", tid, args[0]);
#endif
}

// pid_t fork(void)
void DO_(syscall_pre_fork)( ThreadId tid, UWord* args, UInt nArgs) {
#ifdef DBG_SYSCALL
	SYS_LOGI("%d fork()\n", tid);
#endif
}
// pid_t fork(void)
void DO_(syscall_fork)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int pid = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d fork() pid=%d\n", tid, pid);
#endif
}

// int ptrace(int request, pid_t pid, caddr_t addr, int data); 
void DO_(syscall_pre_ptrace)( ThreadId tid, UWord* args, UInt nArgs) {
	Int request = (Int)args[0];
	Int pid = (Int)args[1];
	Int data = (Int)args[3];
#ifdef DBG_SYSCALL
	SYS_LOGI("%d ptrace() req=0x%x pid=%d data=%d\n", 
			tid, request, pid, data);
#endif
}

// int ptrace(int request, pid_t pid, caddr_t addr, int data); 
void DO_(syscall_ptrace)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int r = sr_Res(res);
	Int request = (Int)args[0];
	Int pid = (Int)args[1];
	Int data = (Int)args[3];
#ifdef DBG_SYSCALL
	SYS_LOGI("%d ptrace() req=0x%x pid=%d data=%d res=%d\n", 
			tid, request, pid, data, r);
#endif
}

//  int open (const char *filename, int flags[, mode_t mode])
void DO_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	HChar fdpath[FD_MAX_PATH];
	Int fd = sr_Res(res);
	if (fd > -1 && fd < FD_MAX) {
		resolve_filename(fd, fdpath, FD_MAX_PATH-1);
		identifyFdType(tid, fd, fdpath);
		fds[tid][fd].offset = 0;
#ifdef DBG_SYSCALL
		//if(isThirdFd(tid, fd)) {
			SYS_LOGI("%d open(%d) 0x%08x(%s) flag=0x%08x\n", tid, fd, fdpath, (HChar*)fdpath,  args[1]);
		//}
#endif
	}
}

//   int close (int filedes)
void DO_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int fd = args[0];
	if (fd > -1 && fd < FD_MAX)
	{
	} else {
		return;
	}
#ifdef DBG_SYSCALL
		//if(isThirdFd(tid, fd))
		SYS_LOGI("%d close(%d) offset=%d type=%d %s\n", 
				tid, fd, fds[tid][fd].offset, fds[tid][fd].type, fds[tid][fd].name);
#endif
		if( fds[tid][fd].type > 0) {
			fds[tid][fd].type = 0;
			fds[tid][fd].offset = 0;
		}
}

void DO_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t write(int fd, const void *buf, size_t nbytes);
	Int fd = args[0];
	HChar *data        = (HChar *)args[1];		// Memery buffer
	Int   curr_len     = sr_Res(res);					// Data length

	DO_(check_fd_access)(tid, fd, FD_WRITE);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d write(%d) offset:0x%08x 0x%x %d %s\n", 
			tid, fd, 
			fds[tid][fd].offset,
			(Int)data, curr_len,
			fd > 0 ? fds[tid][fd].name : "");
#endif
	fds[tid][fd].offset += curr_len;
}

void DO_(get_fnname)(ThreadId tid, const HChar** buf) {
	UInt pc = VG_(get_IP)(tid);
	VG_(get_fnname)(pc, buf);
}

void DO_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request) {
}

void DO_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t recv(int sockfd, void *buf, size_t len, int flags)
	Int msglen  = sr_Res(res);
	Int sk = (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	SYS_LOGI("%d recv(%d)  0x%x(%s) %d\n", 
			tid, sk, (Int)data, (HChar*)data, msglen);
#endif
}

void DO_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
	//                 struct sockaddr *src_addr, socklen_t *addrlen)
	// TODO: #include <arpa/inet.h> inet_ntop to pretty print IP address
	Int msglen  = sr_Res(res);
	Int sk = (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	SYS_LOGI("%d recvfrom(%d) 0x%x(%s) %d\n", 
			tid, sk, (Int)data, (HChar*)data, msglen);
#endif
	//VG_(printf)("syscall recvfrom %d 0x%x 0x%02x\n", tid, msglen, data[0]);
}

// int execve(const char *filename, char *const argv[], char *const envp[])
void DO_(syscall_pre_execve)(ThreadId tid, UWord* args, UInt nArgs) {
	UChar *cmd = (HChar *)args[0];
	SYS_LOGI("%d execv() 0x%x(%s)\n", 
			tid, (Int)cmd, (HChar*)cmd);
#ifdef DBG_SYSCALL
	UInt i = 0;
	UChar **argv = (UChar**)args[1];
	HChar *arg = argv[0];
	while(arg) {
		VG_(printf)("     %s\n", arg);
		arg = argv[++i];
	}
#endif
}
void DO_(syscall_execve)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	HChar *cmd = (HChar *)args[0];
	Int result    = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d execv() 0x%x(%s) res=%d\n", 
			tid, (Int)cmd, (HChar*)cmd, result);
	if(((VG_(strcmp)("/system/bin/dex2oat", (HChar*)cmd) == 0)
		|| (VG_(strcmp)("dex2oat", (HChar*)cmd) == 0)) && (result != -1)) {
		UChar **argv = (UChar**)args[1];
		UInt  i = 0;
		HChar *arg = argv[0];
		HChar *cmd = "/system/bin/cp";
		HChar *targs[2];
		while(arg) {
			VG_(printf)("     %s\n", arg);
			if(VG_(memcmp)("--oat-file", arg, 10) == 0) {
				targs[0] = arg+11;
				targs[1] = "/data/local/tmp/fuzz/";
				VG_(execv)(cmd, targs);
			}
			arg = argv[++i];
		}
	}	
#endif
}

// int unlink(const char *path)
void DO_(syscall_unlink)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UChar *path = (HChar *)args[0];
	Int r = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d unlink() 0x%x(%s) %s\n", 
			tid, (Int)path, (HChar*)path, r==0 ? "Successfull" : "Failure");
#endif
}

// int unlinkat(int dirfd, const char *pathname, int flags)
void DO_(syscall_pre_unlinkat)(ThreadId tid, UWord* args, UInt nArgs) {
	const HChar *path = (HChar *)args[1];
#ifdef DBG_SYSCALL
	SYS_LOGI("%d unlinkat() 0x%x(%s)\n", tid, (Int)path, path);
	HChar *cmd = "/system/bin/cp";
	HChar *targs[2];
	targs[0] = path;
	targs[1] = "/data/local/tmp/fuzz/";
	VG_(execv)(cmd, targs);
	//targs[1] = VG_(sprintf)("%s.bak", path);
	//VG_(execv)(cmd, targs);
#endif
}

// int unlinkat(int dirfd, const char *pathname, int flags)
void DO_(syscall_unlinkat)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	HChar *path = (HChar *)args[1];
	Int r = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d unlinkat() 0x%x(%s) %s\n", 
			tid, (Int)path, path, r==0 ? "Successfull" : "Failure");
	/*HChar *cmd = "/system/bin/cp";
	HChar *targs[2];
	targs[0] = VG_(sprintf)("%s.bak", path);
	targs[1] = path;
	VG_(execv)(cmd, targs);*/
#endif
}

// int setuid(uid_t uid)
void DO_(syscall_setuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int uid = (Int)args[0];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d setuid() uid=%d res=%d\n", 
			tid, uid, re);
#endif
}
// int setreuid(uid_t ruid, uid_t euid)
void DO_(syscall_setreuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int ruid = (Int)args[0];
	Int euid = (Int)args[1];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d setreuid() ruid=%d euid=%d res=%d\n", 
			tid, ruid, euid, re);
#endif
}
// int setgid(uid_t uid)
void DO_(syscall_setgid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int gid = (Int)args[0];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d setgid() gid=%d res=%d\n", 
			tid, gid, re);
#endif
}
// int setreuid(uid_t ruid, uid_t euid)
void DO_(syscall_setregid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int rgid = (Int)args[0];
	Int egid = (Int)args[1];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d setregid() rgid=%d egid=%d res=%d\n", 
			tid, rgid, egid, re);
#endif
}
// int futex(int *uaddr, int futex_op, int val,
//           const struct timespec *timeout,   /* or: uint32_t val2 */
//           int *uaddr2, int val3);
void DO_(syscall_futex)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr uaddr		= (Addr)args[0];
	Int  futex_op = (Int)args[1];
	Int  val			= (Int)args[2];
	struct vki_timespec *tp = (struct vki_timespec*)args[3];
	Addr uaddr2		= (Addr)args[4];
	Int	 val3			= (Int)args[5];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	/*if(tp)
		SYS_LOGI("%d futex() for uaddr=0x%08x futex_op=%d val=%d tp=%d.%09d uaddr2=0x%08x val3=%d res=%d\n",
				tid, uaddr, futex_op, val, tp->tv_sec, tp->tv_nsec, uaddr2, val3, re);
	else*/
	SYS_LOGI("%d futex() for uaddr=0x%08x futex_op=%d val=%3d val2=%08d uaddr2=0x%08x val3=%3d res=%d\n", 
			tid, uaddr, futex_op, val, (Addr)tp, uaddr2, val3, re);
#endif
}

//long sys_flock (	unsigned int fd,	unsigned int cmd);
void DO_(syscall_flock)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UInt fd  = (UInt)args[0];
	UInt cmd = (UInt)args[1];
	ULong re = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d flock() fd=%d cmd=%d res=%d\n", tid, fd, cmd, re);
#endif
}

void DO_(syscall_action)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int sigNum = (Int)args[0];
#ifdef DBG_SYSCALL
	SYS_LOGI("%d sigaction() for sigNo=%d\n", tid, sigNum);
#endif
}
// long clone(unsigned long flags, void *child_stack,
//                  void *ptid, void *ctid,
//                                   struct pt_regs *regs);
void DO_(syscall_clone)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	ULong flag	= (ULong)args[0];
	Addr ptid		= (Int)args[2];
	Addr ctid		= (Int)args[3];
	ULong r   = sr_Res(res);
#ifdef DBG_SYSCALL
	SYS_LOGI("%d clone() flag=0x%lx ptid=0x%08x, ctid=0x%08x, res=0x%lx\n", 
			tid, flag, ptid, ctid, r);
#endif
}
// int inotify_add_watch (int __fd, const char * __name, uint32_t __mask)
void DO_(inotify_add_watch)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int fd = (Int)args[0];
	HChar *path = (HChar*)args[1];
	UInt mask = (UInt)args[2];
	Int r = sr_Res(res);
	SYS_LOGI("%d inotify_add_watch() fd=%d path=%s mask=0x%x res=%d\n",
			tid, fd, path, mask, r);
}
// int fstatat64(int dirfd, const char *pathname, struct stat *buf, int flags);
void DO_(fstatat)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int dirfd = (Int)args[0];
	HChar *path = (HChar*)args[1];
	UChar *buf  = (UChar*)args[2];
	Int r = sr_Res(res);
	SYS_LOGI("%d fstatat64() dirfd=%d path=%s r=%d\n",
			tid, dirfd, path, r);
}

void DO_(syscall_pre_rt_sigreturn)( ThreadId tid, UWord* args, UInt nArgs) {
	UInt unused = (UInt)args[0];
	SYS_LOGI("%d sigreturn() unused=0x%08x\n", tid, unused);
}

void DO_(syscall_rt_sigreturn)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int r = sr_Res(res);
	UInt unused = (UInt)args[0];
	UInt dst = printExecContext();
	SYS_LOGI("%d sigreturn() unused=0x%08x ret=%d\n", tid, unused, r);
	if(isMonMap(dst, NULL) > 0)
		is_trace_irst = tid;
}

void DO_(syscall_pre_action)(ThreadId tid, UWord* args, UInt nArgs) {
	Int sigNum = (Int)args[0];
	if(is_in_vm == 1 && sigNum == 11) {
		args[0] = 0;
		SYS_LOGI("%d sigaction() for sigNo=%d changed to 0\n", tid, sigNum);
	}
#ifdef DBG_SYSCALL
	SYS_LOGI("%d sigaction() for sigNo=%d\n", tid, sigNum);
#endif
}
/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
