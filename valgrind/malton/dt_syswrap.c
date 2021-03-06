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

#include "valgrind.h"

#include "malton.h"
#include "dt_debug.h"
#include "dt_taint.h"
#include "dt_wrappers.h"


	static 
Bool identifyFdType(ThreadId tid, Int fd, HChar *path) 
{
	Int len = VG_(strlen)(path);

	fds[tid][fd].type = FdUnknown;
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
		} else if( VG_(memcmp)((HChar*)&path[len-3], "dex", 3) == 0) {
			if( len > 40 && VG_(memcmp)(path, "/data/dalvik-cache/system@framework@", 36) == 0) {
				fds[tid][fd].type = FdFrameworkDex;
			} else {
				fds[tid][fd].type = FdAppDex;
			}
		}
	}
	VG_(strcpy)(fds[tid][fd].name, path);
#ifdef DBG_SYSCALL
	DT_LOGI("IDENTIFY: %d %d %s\n",
			fd, fds[tid][fd].type, path);
#endif
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
	if ( (fds[tid][fd].type == FdAppDex)
			/*|| (fds[tid][fd].type == FdAppLib)*/
			|| (fds[tid][fd].type == FdAppJar)
			|| (fds[tid][fd].type == FdProcMap)
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

void DT_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	// off_t lseek(int fd, off_t offset, int whence);
	Int   fd      = args[0];
	ULong offset  = args[1];
	UInt  whence  = args[2];

	Int   retval       = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("_lseek() tid=%d fd=%d ", tid, fd);
	DT_LOGI("offset: 0x%x whence: 0x%x ", (UInt)offset, whence);
	DT_LOGI("retval: 0x%x read_offset: 0x%x\n", retval, fds[tid][fd].offset);
#endif
	if( whence == 0/*SEEK_SET*/ )
		fds[tid][fd].offset = (UInt)offset;
	else if( whence == 1/*SEEK_CUR*/ )
		fds[tid][fd].offset += (UInt)offset;
	else if( whence == 2/*SEEK_END*/ )
		fds[tid][fd].offset = retval;
	else {
		DT_LOGI("whence %x\n", whence);
		tl_assert(0);
	}
}

void DT_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	// int  _llseek(int fildes, ulong offset_high, ulong offset_low, loff_t *result,, uint whence);
	Int   fd           = args[0];
	ULong offset_high  = args[1];
	ULong offset_low   = args[2];
	UInt  result       = args[3];
	UInt  whence       = args[4];
	ULong offset;

	Int   retval       = sr_Res(res);

#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("_llseek() tid=%d fd=%d ", tid, fd);
	DT_LOGI("0x%x 0x%x 0x%x 0x%x\n", (UInt)offset_high, (UInt)offset_low, result, whence);
	DT_LOGI("0x%x\n", retval);
#endif

	offset = (offset_high<<32) | offset_low;

	if( whence == 0/*SEEK_SET*/ )
		fds[tid][fd].offset = 0 + (UInt)offset;
	else if( whence == 1/*SEEK_CUR*/ )
		fds[tid][fd].offset += (UInt)offset;
	else {//if( whence == 2/*SEEK_END*/ )
		DT_LOGI("whence %x\n", whence);
		tl_assert(0);
	}
}

void DT_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	// ssize_t  read(int fildes, void *buf, size_t nbyte);
	Int   fd           = args[0];
	HChar *data        = (HChar *)args[1];		// Memery buffer
	UInt  curr_offset  = fds[tid][fd].offset;
	Int   curr_len     = sr_Res(res);					// Data length

	DT_(check_fd_access)(tid, fd, FD_READ);

#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("read() tid=%d, fd=%d offset=0x%08x len=%d data(0x%8x)=%s\n", tid, fd, curr_offset, curr_len, (Int)data, data);
#endif

	if (curr_len == 0) return;

	DT_(make_mem_untainted)( (UWord)data, curr_len );

	// Update file position
	fds[tid][fd].offset += curr_len;
}

void DT_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	// ssize_t pread(int fildes, void *buf, size_t nbyte, size_t offset);
	Int   fd           = args[0];
	HChar *data        = (HChar *)args[1];
	UInt  curr_offset  = (Int)args[3];
	Int   curr_len     = sr_Res(res);

	if (curr_len == 0) return;

	DT_(make_mem_untainted)( (UWord)data, curr_len );

#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("pread() tid=%d fd=%d offset=0x%8x len=0x%x data(0x%8x)=%s\n", tid, fd, curr_offset, curr_len, (UInt)data, data);
#endif

}

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
void DT_(syscall_readv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int	re			= sr_Res(res);
	if (DT_(clo_taint_begin) == False)
		return;
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("readv() tid=%d fd=%d base=0x%08x len=%d\n", 
			tid, fd, (Int)iov->iov_base, iov->iov_len);
#endif
}
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
void DT_(syscall_preadv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int   offset  = args[3];
	int		re			= sr_Res(res);
	if (DT_(clo_taint_begin) == False)
		return;
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("preadv %d fd=%d offset=0x%x 0x%x %d\n", 
			tid, fd, offset, (Int)iov->iov_base, iov->iov_len);
#endif
}

void DT_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	//  int open (const char *filename, int flags[, mode_t mode])
	HChar fdpath[FD_MAX_PATH];
	Int fd = sr_Res(res);
	if (fd > -1 && fd < FD_MAX) {
		resolve_filename(fd, fdpath, FD_MAX_PATH-1);
		identifyFdType(tid, fd, fdpath);
		fds[tid][fd].offset = 0;
#ifdef DBG_SYSCALL
		DBG_SYSCALL_INFO("open() tid=%d path=%s flogs=%lx fd=%d\n", tid, fdpath, args[1], fd);
#endif
		if(fds[tid][fd].type == FdAppDex)
			DT_(dex_is_open) = True;
	} 
}

void DT_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	//   int close (int filedes)
	Int fd = args[0];

	if (fd > -1 && fd < FD_MAX){
		//shared_fds[fd] = 0;
		if( fds[tid][fd].type > 0) {
			fds[tid][fd].type = 0;
			fds[tid][fd].offset = 0;
		}
#ifdef DBG_SYSCALL
		DBG_SYSCALL_INFO("close() tid=%d path=%s fd=%d\n", tid, fds[tid][fd].name, fd);
#endif
	}
}

void DT_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t write(int fd, const void *buf, size_t nbytes);
	Int fd = args[0];
	HChar *data        = (HChar *)args[1];		// Memery buffer
	Int   curr_len     = sr_Res(res);					// Data length

	DT_(check_fd_access)(tid, fd, FD_WRITE);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("write() tid=%d, fd=%d, len=%d data(0x%08x)=%s\n", 
			tid, fd, curr_len, (Int)data , data);
#endif
	if(trace_ins_taint) {
		Bool isT = DT_(check_mem_tainted)( data, curr_len);
		if(isT) {
			TNT_LOGI("[T] %d sys_write(fd=%d) curr_len=%d data(0x%x)=%s\n", 
					tid, fd, curr_len, (Int)data , data);
		}
	}
}

// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
void DT_(syscall_writev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	Int	re			= sr_Res(res);
	if (DT_(clo_taint_begin) == False || re < 0)
		return;
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("writev() tid=%d fd=%d base=0x%x len=%d\n", 
			tid, fd, (Int)iov->iov_base, iov->iov_len);
#endif
}
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
void DT_(syscall_pwritev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int		  offset  = args[3];
	int			re			= sr_Res(res);
	if (DT_(clo_taint_begin) == False || re < 0)
		return;
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("pwritev() tid=%d fd=%d offset=0x%08x base=0x%08x len=%d\n", 
			tid, fd, offset, (Int)iov->iov_base, iov->iov_len);
#endif
}

void DT_(get_fnname)(ThreadId tid, const HChar** buf) {
	UInt pc = VG_(get_IP)(tid);
	VG_(get_fnname)(pc, buf);
}

void DT_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request) {
#if 0
	if (IN_SANDBOX) {
		Bool allowed = shared_fds[fd] & fd_request;
		//		VG_(printf)("checking if allowed to %s from fd %d ... %d\n", (fd_request == FD_READ ? "read" : "write"), fd, allowed);
		if (!allowed) {
			const HChar* access_str;
			switch (fd_request) {
				case FD_READ: {
												access_str = "read from";
												break;
											}
				case FD_WRITE: {
												 access_str = "wrote to";
												 break;
											 }
				default: {
									 tl_assert(0);
									 break;
								 }
			}
			HChar fdpath[FD_MAX_PATH];
#ifdef VGO_freebsd
			VG_(resolve_filename)(fd, fdpath, FD_MAX_PATH-1);
#elif defined VGO_linux
			resolve_filename(fd, fdpath, FD_MAX_PATH-1);
#else
#error OS unknown
#endif
			const HChar *fnname;
			DT_(get_fnname)(tid, &fnname);
			VG_(printf)("*** Sandbox %s %s (fd: %d) in method %s, but it is not allowed to. ***\n", access_str, fdpath, fd, fnname);
			VG_(get_and_pp_StackTrace)(tid, STACK_TRACE_SIZE);
			VG_(printf)("\n");
		}
	}
#endif
}
// ssize_t send(int socket, const void *buffer, size_t length, int flags);
void DT_(syscall_send)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int len     = sr_Res(res);
	Int sd      = (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("send() tid=%d sd=%d len=%d data(%08x)=%s\n", tid, sd, len, data, data);
#endif
}

// ssize_t sendto(int socket, const void *message, size_t length,
//		       int flags, const struct sockaddr *dest_addr,
//					        socklen_t dest_len);
void DT_(syscall_sendto)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int msglen	= sr_Res(res);
	Int sd			= (Int)args[0];
	HChar *data	= (HChar *)args[1];
#ifdef DBG_SYSCALL
	//DBG_SYSCALL_INFO("recvfrom %d 0x%x %d %s\n", tid, data, msglen, data);
	DBG_SYSCALL_INFO("sendto() tid=%d sd=%d len=%d data(0x%08x)=%s\n", tid, sd, msglen, data, data);
#endif
}

void DT_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t recv(int sockfd, void *buf, size_t len, int flags)
	Int msglen  = sr_Res(res);
	Int sd			= (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("recv() tid=%d sd=%d len=%d data(%08x)=%s\n", tid, sd, msglen, data, data);
#endif
}

void DT_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
	//                 struct sockaddr *src_addr, socklen_t *addrlen)
	// TODO: #include <arpa/inet.h> inet_ntop to pretty print IP address
	Int msglen  = sr_Res(res);
	Int sd			= (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	//DBG_SYSCALL_INFO("recvfrom %d 0x%x %d %s\n", tid, data, msglen, data);
	DBG_SYSCALL_INFO("recvfrom() tid=%d sd=%d len=%d data(0x%08x)=%s\n", tid, sd, msglen, data, data);
#endif
}
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void DT_(syscall_mmap)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int begin_addr = sr_Res(res);
	Int size  = (Int)args[1];
	Int prot = (Int)args[2];
	Int flags = (Int)args[3];
	Int  fd = (Int)args[4];
	UInt offset = (Int)args[5];
	if( begin_addr <= 0 || prot == PROT_NONE )
		return;
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("mmap() tid=%d fd=%d off=0x%08x -> mem=0x%08x-0x%08x size=%d prot=%c%c%c flags=0x%x\n", 
			tid, fd, offset, begin_addr, begin_addr+size, size, 
			(prot & PROT_READ) ? 'r' : '-',
			(prot & PROT_WRITE) ? 'w' : '-',
			(prot & PROT_EXEC) ? 'x' : '-',
			flags);
#endif
}

// int mprotect(void *addr, size_t len, int prot);
void DT_(syscall_mprotect) ( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  size = (Int)args[1];
	Int  prot = (Int)args[2];
	Int  re  = sr_Res(res);
	if( prot == PROT_NONE )
		return;
#ifdef DBG_SYSCALL
	if( re >= 0)
		DBG_SYSCALL_INFO("mprotect() tid=%d mem=0x%08x-0x%08x prot=%c%c%c\n",
				tid, begin_addr, begin_addr+size,
				(prot & PROT_READ) ? 'r' : '-',
				(prot & PROT_WRITE) ? 'w' : '-',
				(prot & PROT_EXEC) ? 'x' : '-');
#endif
}

// int msync(void *addr, size_t length, int flags);
void DT_(syscall_msync)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  length		  = (Int)args[1];
	Int	 flags			= (Int)args[2];
	Int  re				= sr_Res(res);
#ifdef DBG_SYSCALL
	if(re == 0) {
		DBG_SYSCALL_INFO("msync() tid=%d mem=0x%08x-0x%08x flags=0x%x\n",
				tid, begin_addr, begin_addr+length, flags);
	}
#endif
}

// int munmap(void *addr, size_t len); 
void DT_(syscall_munmap)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  size = (Int)args[1];
	if (DT_(clo_taint_begin) == False)
		return;
	if( begin_addr > 0) {
#ifdef DBG_SYSCALL
		DBG_SYSCALL_INFO("munmap() tid=%d mem=0x%08x-0x%08x\n", 
				tid, begin_addr, begin_addr+size);
#endif
	}
}

// int ptrace(int request, pid_t pid, caddr_t addr, int data); 
void DT_(syscall_ptrace)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int request = (Int)args[0];
	Int pid = (Int)args[1];
	Int data = (Int)args[3];
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("ptrace() tid=%d req=0x%x pid=%d data=%d\n", 
			tid, request, pid, data);
#endif
}

// int execve(const char *filename, char *const argv[], char *const envp[])
void DT_(syscall_execve)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UChar *cmd = (HChar *)args[0];
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("execv() tid=%d cmd(0x%08x)=%s\n", 
			tid, (Int)cmd, (HChar*)cmd);
#endif
}

// int unlink(const char *path)
void DT_(syscall_unlink)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UChar *path = (HChar *)args[0];
	Int r = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("unlink() tid=%d path=%s res=%d\n", tid, (HChar*)path, r);
#endif
}

// int setuid(uid_t uid)
void DT_(syscall_setuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int uid = (Int)args[0];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("setuid() tid=%d uid=%d res=%d\n", 
			tid, uid, re);
#endif
}
// int setreuid(uid_t ruid, uid_t euid)
void DT_(syscall_setreuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int ruid = (Int)args[0];
	Int euid = (Int)args[1];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("setreuid() tid=%d ruid=%d euid=%d res=%d\n", 
			tid, ruid, euid, re);
#endif
}
// int setgid(uid_t uid)
void DT_(syscall_setgid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int gid = (Int)args[0];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("setgid() tid=%d gid=%d res=%d\n", tid, gid, re);
#endif
}
// int setreuid(uid_t ruid, uid_t euid)
void DT_(syscall_setregid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int rgid = (Int)args[0];
	Int egid = (Int)args[1];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("setregid() tid=%d rgid=%d egid=%d res=%d\n", 
			tid, rgid, egid, re);
#endif
}
void DT_(syscall_action)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int sigNum = (Int)args[0];
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("sigaction() tid=%d for sigNo=%d\n", 
			tid, sigNum);
#endif
}
// long clone(unsigned long flags, void *child_stack,
//                  void *ptid, void *ctid,
//                                   struct pt_regs *regs);
void DT_(syscall_clone)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	ULong flag	= (ULong)args[0];
	Addr ptid		= (Int)args[2];
	Addr ctid		= (Int)args[3];
	ULong r   = sr_Res(res);
#ifdef DBG_SYSCALL
	DBG_SYSCALL_INFO("clone() tid=%d flag=0x%lx ptid=0x%08x, ctid=0x%08x, res=0x%lx\n", 
			tid, flag, ptid, ctid, r);
#endif
}
/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
