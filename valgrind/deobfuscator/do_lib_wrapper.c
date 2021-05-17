//do_libart_wrapper.c

#include "pub_tool_basics.h"
#include "pub_tool_poolalloc.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_redir.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_clreq.h"

#include "util.h"

#ifdef LIBM_FUNC
#undef LIBM_FUNC
#endif

#define  VG_Z_LIBM_SONAME  libmZdsoZa              // libm.so*
#define LIBM_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(VG_Z_LIBM_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(VG_Z_LIBM_SONAME,f)(args)

#ifdef LIBC_FUNC
#undef LIBC_FUNC
#endif

#define LIBC_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(VG_Z_LIBC_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(VG_Z_LIBC_SONAME,f)(args)


#ifdef REPLACE_GETTIMEOFDAY
// int gettimeofday(struct  timeval*tv,struct  timezone *tz )
int gettimeofday_wrapper(void* tv, void* tz) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, tv, tz);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_GETTIMEOFDAY, void*, tv, void*, tz);
	return res;
}
LIBC_FUNC(int, gettimeofday, void *tv, void *tz) {
	return gettimeofday_wrapper(tv, tz);
}

// int clock_gettime(clockid_t clk_id, struct timespec *tp);
int clock_gettime_wrapper(UInt clk_id, void *tp) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, clk_id, tp);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_CLOCK_GETTIME, UInt, clk_id, void*, tp);
	return res;
}
LIBC_FUNC(int, clock_gettime, UInt clk_id, void *tp) {
	return clock_gettime_wrapper(clk_id, tp);
}
#if 0
// int inotify_add_watch(int fd, const char * path, uint32_t mask);
Int inotify_add_watch_wrapper(int fd, const Char *path, UInt mask) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	// CALL_FN_W_WWW(res, fn, fd, path, mask);
	CALL_FN_W_WWW(res, fn, fd, path, 0);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_LIBC_INOTIFY_ADD_WATCH, Int, fd, Addr, path, UInt, mask);
	return res;
}
LIBC_FUNC(int, inotify_add_watch, Int  fd, const Char *path, UInt mask) {
	return inotify_add_watch_wrapper(fd, path, mask);
}
#endif
#endif
#if 1
#if 0
long ptrace_wrapper(int request, int pid, int addr, int data) {
	OrigFn fn;
	long res;
	VALGRIND_GET_ORIG_FN(fn);
	res = -1;
	//CALL_FN_W_WWWW(res, fn, request, pid, addr, data);
	res = DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_PTRACE,  int, pid, int, addr, int, data, int, res);
	return res;
}
LIBC_FUNC(long, ptrace, int r, int p, int a, int d) {
	return ptrace_wrapper(r, p, a, d);
	//return 0;
}
#endif
#ifdef DE_VMP_TRACE
// int kill(pid_t pid, int sig)
int kill_wrapper(int pid, int sig)
{
	OrigFn fn;
	Int res = 0;
	VALGRIND_GET_ORIG_FN(fn);
	//CALL_FN_v_WW( res, fn, pid, sig);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_LIBC_KILL, int, pid, int, sig, int, res);
	return res;
}
LIBC_FUNC(int, kill, 
		int pid, int sig)
{
	int res = kill_wrapper(pid, sig);
	return 0;
}
#if 0
//int unlinkat(int dirfd, const char *pathname, int flags);
int unlinkat_wrapper(int dirfd, const char *pathname, int flags)
{
	return 0;
}
LIBC_FUNC(int, unlinkat,
		int dirfd, const char *pathname, int flags)
{
	return unlinkat_wrapper(dirfd, pathname, flags);
}
#endif
// void exit(int status)
void exit_wrapper(int status)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_LIBC_EXIT, int, status);
	CALL_FN_v_W(fn, status);
}
LIBC_FUNC(void, exit, int status)
{
	exit_wrapper(status);
}
// void exit_group(int status)
void exit_group_wrapper(int status)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_LIBC_EXIT_GROUP, int, status);
	CALL_FN_v_W(fn, status);
}
LIBC_FUNC(void, exit_group, int status)
{
	exit_group_wrapper(status);
}
// void abort()
void abort_wrapper(void)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn); 
	CALL_FN_v_v(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_LIBC_ABORT, Int, 0);
}
LIBC_FUNC(void, abort, void)
{
	abort_wrapper();
}

/* Socket related operation wrappers */
//  int socket (int namespace, int style, int protocol)
int socket_wrapper(int namespace, int style, int protocol)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, namespace, style, protocol);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_LIBC_SOCKET, int, namespace, int, style, int, protocol, 
			int, res);
	return res;
}
LIBC_FUNC(int, socket,
		int namespace, int style, int protocol)
{
	return socket_wrapper(namespace, style, protocol);
}

// int bind (int socket, struct sockaddr *addr, socklen_t length)
int bind_wrapper(int socket, struct sockaddr *addr, socklen_t length)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, socket, addr, length);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_BIND, int, socket, struct sockaddr *, addr);
	return res;
}
LIBC_FUNC(int, bind,
		int socket, struct sockaddr *addr, socklen_t length)
{
	return bind_wrapper(socket, addr, length);
}
// int shutdown (int socket, int how)
// int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
int connect_wrapper(int socket, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_LIBC_CONNECT_PRE, int, socket, struct sockaddr *, serv_addr, int*, &res);
	CALL_FN_W_WWW(res, fn, socket, serv_addr, addrlen);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_LIBC_CONNECT, int, socket, struct sockaddr *, serv_addr, int*, &res);
	return res;
}
LIBC_FUNC(int, connect, 
		int socket, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	return connect_wrapper(socket, serv_addr, addrlen);
}

// int listen(int s, int backlog)
int listen_wrapper(int s, int backlog) 
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_LISTEN, int, s, int, backlog);
	CALL_FN_W_WW(res, fn, s, backlog);
	return res;
}
LIBC_FUNC(int, listen,
		int s, int backlog)
{
	return listen_wrapper(s, backlog);
}

// int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
int accept_wrapper(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, s, addr, addrlen);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_LIBC_ACCEPT, int, s, struct sockaddr*, addr, int, res);
	return res;
}
LIBC_FUNC(int, accept,
		int s, struct sockaddr *addr, socklen_t *addrlen)
{
	return accept_wrapper(s, addr, addrlen);
}

// int send(int s, const void *buf, int len, unsigned int flags)
int send_wrapper(int s, const void *buf, int len, unsigned int flags) 
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, s, buf, len, flags);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_LIBC_SEND, int, s, void*, buf, unsigned int, flags, int*, &res);
	return res;
} 
LIBC_FUNC(int, send,
		int s, const void *buf, int len, unsigned int flags)
{ 
	return send_wrapper(s, buf, len, flags);
}

// int sendto(int s, const void *buf, int len, int flags, const struct sockaddr *to, socklen_t tolen)
int sendto_wrapper(int s, const void *buf, int len, unsigned int flags, const struct sockaddr *to, int tolen)
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_6W(res, fn, s, buf, len, flags, to, tolen);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_LIBC_SENDTO, int, s, void*, buf, unsigned int, flags,
			struct sockaddr*, to, int*, &res); 
	return res;
} 
LIBC_FUNC(int, sendto,
		int s, const void *buf, int len, unsigned int flags, const struct sockaddr *to, int tolen)
{ 
	return sendto_wrapper(s, buf, len, flags, to, tolen);
}

// int recv(int s, void *buf, int len, unsigned int flags)
int recv_wrapper(int s, void *buf, int len, unsigned int flags)
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_LIBC_RECV_PRE,	int, s, void*, buf, unsigned int, flags, int*, &len);
	CALL_FN_W_WWWW(res, fn, s, buf, len, flags);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_LIBC_RECV,	int, s, void*, buf, unsigned int, flags, int*, &res);
	return res;
} 
LIBC_FUNC(int, recv,
		int s, void *buf, int len, unsigned int flags)
{ 
	return recv_wrapper(s, buf, len, flags);
} 

// ssize_t recvfrom (int socket, void *buffer, size_t size, int flags, struct sockaddr *addr, socklen_t *length-ptr)
// int recvfrom(int s, void *buf, int len, int flags, struct sockaddr *from, socklen_t *len)
int recvfrom_wrapper(int s, void *buf, int len, int flags, struct sockaddr *from, socklen_t *slen)
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_LIBC_RECVFROM_PRE, int, s, void*, buf, unsigned int, flags,
			struct sockaddr*, from, int*, &len);
	CALL_FN_W_6W(res, fn, s, buf, len, flags, from, slen);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_LIBC_RECVFROM, int, s, void*, buf, unsigned int, flags,
			struct sockaddr*, from, int*, &res);
	//printf("post: recvfrom: 0x%08x(%s), res=%d\n", (int)buf, (char*)buf, res);
	return res;
} 
LIBC_FUNC(int, recvfrom, 
		int s, void *buf, int len, int flags, struct sockaddr *from, socklen_t *slen)
{ 
	return recvfrom_wrapper(s, buf, len, flags, from, slen);
} 

// char *strdup(const char *s1)
void* strdup_wrapper(const void* s1)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, s1);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_STRDUP, void*, s1, void*, res);
	return res;
}
LIBC_FUNC(void*, strdup,
		const void* s1)
{
	return strdup_wrapper(s1);
}
// char *strcpy(char* dest, const char* src)
void* strcpy_wrapper(char* dest, const char* src)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, dest, src);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_STRCPY, void*, src, void*, dest);
	return res;
}
LIBC_FUNC(void*, strcpy,
		void* dest, const void* src)
{
	return strcpy_wrapper(dest, src);
}

// char *memcpy(char* dest, const char* src)
void* memcpy_wrapper(char* dest, const char* src, int size)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, dest, src, size);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_LIBC_MEMCPY, void*, src, void*, dest, int, size);
	return res;
}

LIBC_FUNC(void*, memcpy,
		void* dest, const void* src, int size)
{
	return memcpy_wrapper(dest, src, size);
}

// int strlen(const char* src)
int strlen_wrapper(const char* src)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, src);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LIBC_STRLEN, void*, src, int, res);
	return res;
}

LIBC_FUNC(void*, strlen,
		const void* src)
{
	return strlen_wrapper(src);
}
#endif


#ifdef NONE_FUNC
#undef NONE_FUNC
#endif

#define  BG_Z_LIBLINKER  linker              // linker
#define NONE_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(NONE,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(NONE,f)(args)


// void *dlopen(const char *filename, int flags)
void* dlopen_wrapper(const char *file, int flags)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_DLOPEN_PRE, const char*, file, int, flags);
	CALL_FN_W_WW(res, fn, file, flags);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DLOPEN, const char*, file, int, flags, void*, res);
	return res;
}
NONE_FUNC(void*, __dl_dlopen,
		const char *file, int flags)
{
	return dlopen_wrapper(file, flags);
}

// void *dlsym(void *restrict handle, const char *restrict name)
void *dlsym_wrapper(void* handle, const char* name)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_DLSYM_PRE, void*, handle, const char*, name);
	CALL_FN_W_WW(res, fn, handle, name);
	DO_CREQ_W_WWW(res, VG_USERREQ__WRAPPER_DLSYM, void*, handle, const char*, name, void*, res);
	return res;
}
NONE_FUNC(void*, __dl_dlsym,
		void *handle, const char *name)
{
	return dlsym_wrapper(handle, name);
}

// art_jni_dlsym_lookup_stub(JNIEnv*, jobject)
//

#ifdef LIBART_FUNC
#undef LIBART_FUNC
#endif

#define  FZ_Z_LIBART_SONAME  libartZdsoZa              // libart.so*
#define LIBART_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(FZ_Z_LIBART_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(FZ_Z_LIBART_SONAME,f)(args)


#if 1
// bool JavaVMExt::LoadNativeLibrary(JNIEnv* env, const std::string& path, jobject class_loader,
//                                 std::string* error_msg);
Bool JavaVMExt_LoadNativeLibrary(void *this, void *env, char* path, void* class_loader, char* error_msg)
{
	OrigFn fn;
	Bool res;
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE, char*, path, void*, class_loader);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_5W(res, fn, this, env, path, class_loader, error_msg);
	if(res)
		DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY, void*, this, char*, path, void*, class_loader);
	return res;
}
// _ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectPS9
LIBART_FUNC(Bool, _ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectPS9_,
		void *this, void *env, char* path, void* class_loader, char* error_msg)
{
	return JavaVMExt_LoadNativeLibrary(this, env, path, class_loader, error_msg);
}
#endif
// std::unique_ptr<const DexFile> DexFile::OpenMemory(const uint8_t* base,
//                                                    size_t size,
//                                                    const std::string& location,
//                                                    uint32_t location_checksum,
//                                                    MemMap* mem_map,
//                                                    const OatDexFile* oat_dex_file,
//                                                    std::string* error_msg)
void* DexFile_OpenMemory(void *this, const unsigned char* base, int size, void* location, int location_checksum, void *mem_map, void* oat_dex_file, void* error_msg)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_OPENMEMORY_PRE, void*, location, void*, mem_map);
	CALL_FN_W_8W(res, fn, this, base, size, location, location_checksum, mem_map, oat_dex_file, error_msg);
	if(res)
		DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_OPENMEMORY, void*, res, void*, location, void*, mem_map);
	return res;
}
LIBART_FUNC(void*, _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_,
		void* this, const unsigned char* base, int size, void* location, int location_checksum, void *mem_map, void *oat_dex_file, void *error_msg)
{
	return DexFile_OpenMemory(this, base, size, location, location_checksum, mem_map, oat_dex_file, error_msg);
}

// DexFile::DexFile(const uint8_t* base, size_t size,
//                 const std::string& location,
//                  uint32_t location_checksum,
//                  MemMap* mem_map,
//                 const OatDexFile* oat_dex_file)
// 
void* DexFile_DexFile(void *this, void *base, int size, void* location, int checksum, void* mem_map, void* oat_dex_file)
{
	OrigFn fn;
	void* res = NULL;
	//DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_DEXFILE_PRE, void*, mem_map, char*, base, int, size, char*, (char*)(*((unsigned int*)location+2)));
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_7W(res, fn, this, base, size, location, checksum, mem_map, oat_dex_file);
	if(res)
		DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_DEXFILE, Addr, (Addr)this, char*, base, int, size, void*, location,	void*, mem_map);
	return res;
}

// _ZN3art7DexFileC2EPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE
LIBART_FUNC(void*, _ZN3art7DexFileC2EPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE,
		void* this, void* base, int size, void* location, int checksum, void* mem_map, void* oat_dex_file)
{
	return DexFile_DexFile(this, base, size, location, checksum, mem_map, oat_dex_file);
}
// void ClassLinker::LoadClass(Thread* self, const DexFile& dex_file,
//                             const DexFile::ClassDef& dex_class_def,
//                             Handle<mirror::Class> klass)

void ClassLinker_LoadClass(void* this, void* thread, void* dex_file, void* dex_class_def, void* klass)
{
	OrigFn fn;
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_LOADCLASS_PRE, void*, dex_file, void*, dex_class_def, void*, klass);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_5W(fn, this, thread, dex_file, dex_class_def, klass);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_LOADCLASS, void*, dex_file, void*, dex_class_def, void*, klass);
}

LIBART_FUNC(void, _ZN3art11ClassLinker9LoadClassEPNS_6ThreadERKNS_7DexFileERKNS3_8ClassDefENS_6HandleINS_6mirror5ClassEEE, 
		void* this, void* thread, void* dex_file, void* dex_class_def, void* klass)
{
	ClassLinker_LoadClass(this, thread, dex_file, dex_class_def, klass);
}

// void ClassLinker::LoadClassMembers(Thread* self, const DexFile& dex_file,
//		const uint8_t* class_data,
//		Handle<mirror::Class> klass,
//		const OatFile::OatClass* oat_class);
void ClassLinker_LoadClassMembers(void* this, void* thread, void* dex_file, UChar* class_data, void* klass, void* oat_class)
{
	OrigFn fn;
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS_PRE, void*, dex_file, void*, class_data, void*, klass, void*, oat_class);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_6W(fn, this, thread, dex_file, class_data, klass, oat_class);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_LOADCLASSMEMBERS, void*, dex_file, void*, class_data, void*, klass, void*, oat_class);
}
LIBART_FUNC(void, _ZN3art11ClassLinker16LoadClassMembersEPNS_6ThreadERKNS_7DexFileEPKhNS_6HandleINS_6mirror5ClassEEEPKNS_7OatFile8OatClassE,
		void* this, void* thread, void* dex_file, UChar* class_data, void* klass, void* oat_class)
{
	return ClassLinker_LoadClassMembers(this, thread, dex_file, class_data, klass, oat_class);
}
// mirror::Class* ClassLinker::DefineClass(Thread* self, const char* descriptor, size_t hash,
//       Handle<mirror::ClassLoader> class_loader,
//       const DexFile& dex_file,
//       const DexFile::ClassDef& dex_class_def);
void* ClassLinker_DefineClass(void* this, void* thread,void* descriptor, int hash, void* class_loader, void* dex_file, void* dex_class_def)
{
	OrigFn fn;
	void* res;
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE, char*, descriptor, void*, dex_file, void*, dex_class_def);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_7W(res, fn, this, thread, descriptor, hash, class_loader, dex_file, dex_class_def);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_DEFINECLASS, char*, descriptor, void*, dex_file, void*, dex_class_def);
	return res;
}
// _ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
LIBART_FUNC(void*,  _ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE,
		void* this, void *thread, void* descriptor, int hash, void* class_loader, void* dex_file, void* dex_class_def)
{
	return ClassLinker_DefineClass(this, thread, descriptor, hash, class_loader, dex_file, dex_class_def);
}

#if 0
// void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,
//                       const char* shorty)
void ArtMethod_Invoke(void* this, void* thread, unsigned int* args, unsigned int args_size, void* result, HChar* shorty)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	//DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_INVOKE_PRE, void*, this, void*, thread, unsigned int*, args, unsigned int, args_size, char*, shorty);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_ART_INVOKE_PRE, Addr, (Addr)this);
	CALL_FN_v_6W(fn, this, thread, args, args_size, result, shorty);
	//DO_CREQ_v_W(VG_USERREQ__WRAPPER_ART_INVOKE, Addr, (Addr)this);
	//DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_INVOKE, void*, this, void*, thread, void*, result, char*, shorty);
}
LIBART_FUNC(void,  _ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc,
		void* this, void* thread, unsigned int* args, unsigned int args_size, void* result, HChar* shorty)
{
	ArtMethod_Invoke(this, thread, args, args_size, result, shorty);
}
// static JniValueType CallMethodV(const char* function_name, JNIEnv* env, jobject obj, jclass c,
// 	                                  jmethodID mid, va_list vargs, Primitive::Type type,
//	                                  InvokeType invoke)
void CheckJNI_CallMethodV(const HChar* function_name, void* env, void* obj, void* c, void* mid, void* vargs, 
		int type,	int invoke)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_8W(fn, function_name, env, obj, c, mid, vargs, type, invoke);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_CALLMETHODV, HChar*, function_name, void*, mid, int, type, int, invoke);
}
// _ZN3art8CheckJNI11CallMethodVEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDSt9__va_listNS_9Primitive4TypeENS_10InvokeTypeE
// _ZN3art8CheckJNI11CallMethodVEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDSt9__va_listNS_9Primitive4TypeENS_10InvokeTypeE
LIBART_FUNC(void, _ZN3art8CheckJNI11CallMethodVEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDSt9__va_listNS_9Primitive4TypeENS_10InvokeTypeE,
		HChar* function_name, void* env, void* obj, void* c, void* mid, void* vargs, int type, int invoke)
{
	CheckJNI_CallMethodV(function_name, env, obj, c, mid, vargs, type, invoke);
}

// static JniValueType CallMethodA(const char* function_name, JNIEnv* env, jobject obj, jclass c,
//                                    jmethodID mid, jvalue* vargs, Primitive::Type type,
//                                    InvokeType invoke) {
void CheckJNI_CallMethodA(const HChar* function_name, void* env, void* obj, void* c, void* mid, void* vargs, 
		int type,	int invoke)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_8W(fn, function_name, env, obj, c, mid, vargs, type, invoke);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_CALLMETHODA, HChar*, function_name, void*, mid, int, type, int, invoke);
}
// _ZN3art8CheckJNI11CallMethodAEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDP6jvalueNS_9Primitive4TypeENS_10InvokeTypeE
// _ZN3art8CheckJNI11CallMethodAEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDP6jvalueNS_9Primitive4TypeENS_10InvokeTypeE
LIBART_FUNC(void,	_ZN3art8CheckJNI11CallMethodAEPKcP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDP6jvalueNS_9Primitive4TypeENS_10InvokeTypeE,
		HChar* function_name, void* env, void* obj, void* c, void* mid, void* vargs, int type, int invoke)
{
	CheckJNI_CallMethodA(function_name, env, obj, c, mid, vargs, type, invoke);
}
#endif
/*
	 3497		CheckJNI::CallStaticObjectMethod,
	 3498   CheckJNI::CallStaticObjectMethodV,
	 3499   CheckJNI::CallStaticObjectMethodA,
	 3500   CheckJNI::CallStaticBooleanMethod,
	 3501   CheckJNI::CallStaticBooleanMethodV,
	 3502   CheckJNI::CallStaticBooleanMethodA,
	 3503   CheckJNI::CallStaticByteMethod,
	 3504   CheckJNI::CallStaticByteMethodV,
	 3505   CheckJNI::CallStaticByteMethodA,
	 3506   CheckJNI::CallStaticCharMethod,
	 3507   CheckJNI::CallStaticCharMethodV,
	 3508   CheckJNI::CallStaticCharMethodA,
	 3509   CheckJNI::CallStaticShortMethod,
	 3510   CheckJNI::CallStaticShortMethodV,
	 3511   CheckJNI::CallStaticShortMethodA,
	 3512   CheckJNI::CallStaticIntMethod,
	 3513   CheckJNI::CallStaticIntMethodV,
	 3514   CheckJNI::CallStaticIntMethodA,
	 3515   CheckJNI::CallStaticLongMethod,
	 3516   CheckJNI::CallStaticLongMethodV,
	 3517   CheckJNI::CallStaticLongMethodA,
	 3518   CheckJNI::CallStaticFloatMethod,
	 3519   CheckJNI::CallStaticFloatMethodV,
	 3520   CheckJNI::CallStaticFloatMethodA,
	 3521   CheckJNI::CallStaticDoubleMethod,
	 3522   CheckJNI::CallStaticDoubleMethodV,
	 3523   CheckJNI::CallStaticDoubleMethodA,
	 3524   CheckJNI::CallStaticVoidMethod,
	 3525   CheckJNI::CallStaticVoidMethodV,
	 3526   CheckJNI::CallStaticVoidMethodA,
	 */
//
//jobject InvokeMethod(const ScopedObjectAccessAlreadyRunnable& soa, jobject javaMethod, jobject javaReceiver, jobject javaArgs, size_t num_frames)
void* art_InvokeMethod(const void* soa, void* javaMethod, void* javaReceiver, void* javaArgs, int num_frames)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_5W(res, fn, soa, javaMethod, javaReceiver, javaArgs, num_frames);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_INVOKEMETHOD, void*, soa, void*, javaMethod, void*, javaReceiver, void*, javaArgs, int, num_frames);
	return res;
}
LIBART_FUNC(void*, _ZN3art12InvokeMethodERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectS4_S4_j,
		void* soa, void* javaMethod, void* javaReceiver, void* javaArgs, int num_frames)
{
	return art_InvokeMethod(soa, javaMethod, javaReceiver, javaArgs, num_frames);
}

//void InvokeWithArgArray(const ScopedObjectAccessAlreadyRunnable& soa,
//	ArtMethod* method, ArgArray* arg_array, JValue* result, const char* shorty)
void art_InvokeWithArgArray(const void* soa, void* method, void* arg_array, void* result, const char* shorty)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_5W(fn, soa, method, arg_array, result, shorty);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_INVOKEWITHARGARRAY, void*, method, void*, result, void*, shorty);
}
// _ZN3art18InvokeWithArgArrayERKNS_33ScopedObjectAccessAlreadyRunnableEPNS_9ArtMethodEPNS_8ArgArrayEPNS_6JValueEPKc
LIBART_FUNC(void, _ZN3art18InvokeWithArgArrayERKNS_33ScopedObjectAccessAlreadyRunnableEPNS_9ArtMethodEPNS_8ArgArrayEPNS_6JValueEPKc,
		void* soa, void* method, void* arg_array, void* result, char* shorty)
{
	art_InvokeWithArgArray(soa, method, arg_array, result, shorty);
}

// static jobject CallStaticObjectMethodV(JNIEnv* env, jclass, jmethodID mid, va_list args)
void* jni_CallStaticObjectMethodV(void* env, void* jclass, int mid, void* args)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_CALLSTATICOBJECTMETHODV_PRE, void*, env, void*, jclass, int, mid, void*, args);
	CALL_FN_W_WWWW(res, fn, env, jclass, mid, args);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_CALLSTATICOBJECTMETHODV, void*, env, void*, jclass, int, mid, void*, args, void*, res);
	return res;
}
LIBART_FUNC(void*,  _ZN3art3JNI23CallStaticObjectMethodVEP7_JNIEnvP7_jclassP10_jmethodIDSt9__va_list,
		void* env, void* jclass, int mid, void* args)
{
	return jni_CallStaticObjectMethodV(env, jclass, mid, args);
}

#if 0
//JValue InvokeWithVarArgs(const ScopedObjectAccessAlreadyRunnable& soa, jobject obj, jmethodID mid, va_list args);
void* art_InvokeWithVarArgs(const void* soa, void* obj, void* mid, void* args)
{
	OrigFn fn;
	ULong res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, soa, obj, mid, args);
	//DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_INVOKEWITHVARARGS, void*, soa, void*, obj, void*, mid, void*, args);
	return res;
}
LIBART_FUNC(void*, _ZN3art17InvokeWithVarArgsERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectP10_jmethodIDSt9__va_list,
		void* soa, void* obj, void* mid, void* args)
{
	return art_InvokeWithVarArgs(soa, obj, mid, args);
}
//
//JValue InvokeWithJValues(const ScopedObjectAccessAlreadyRunnable& soa, jobject obj, jmethodID mid, jvalue* args);
void* art_InvokeWithJValues(const void* soa, void* obj, void* mid, void* args)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, soa, obj, mid, args);
	//DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_INVOKEWITHJVALUES, void*, soa, void*, obj, void*, mid, void*, args);
	return res;
}
LIBART_FUNC(void*, _ZN3art17InvokeWithJValuesERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectP10_jmethodIDP6jvalue,
		void* soa, void* obj, void* mid, void* args)
{
	return art_InvokeWithJValues(soa, obj, mid, args);
}
//
//JValue InvokeVirtualOrInterfaceWithJValues(const ScopedObjectAccessAlreadyRunnable& soa, jobject obj, jmethodID mid, jvalue* args)
void* art_InvokeVirtualOrInterfaceWithJValues(const void* soa, void* obj, void* mid, void* args)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, soa, obj, mid, args);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHJVALUES, void*, soa, void*, obj, void*, mid, void*, args);
	return res;
}
LIBART_FUNC(void*, _ZN3art35InvokeVirtualOrInterfaceWithJValuesERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectP10_jmethodIDP6jvalue,
		void* soa, void* obj, void* mid, void* args)
{
	return art_InvokeVirtualOrInterfaceWithJValues(soa, obj, mid, args);
}
//
//JValue InvokeVirtualOrInterfaceWithVarArgs(const ScopedObjectAccessAlreadyRunnable& soa, jobject obj, jmethodID mid, va_list args)
void* art_InvokeVirtualOrInterfaceWithVarArgs(const void* soa, void* obj, void* mid, void* args)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, soa, obj, mid, args);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_INVOKEVIRTUALORINTERFACEWITHVARARGS, void*, soa, void*, obj, void*, mid, void*, args);
	return res;
}
LIBART_FUNC(void*, _ZN3art35InvokeVirtualOrInterfaceWithVarArgsERKNS_33ScopedObjectAccessAlreadyRunnableEP8_jobjectP10_jmethodIDSt9__va_list,
		void* soa, void* obj, void* mid, void* args)
{
	return art_InvokeVirtualOrInterfaceWithVarArgs(soa, obj, mid, args);
}
#endif

// static const char* GetStringUTFChars(JNIEnv* env, jstring string, jboolean* is_copy)
void* jni_GetStringUTFChars(void* env, void *string, void* is_copy)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, env, string, is_copy);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_ART_GETSTRINGUTFCHARS, char*, res);
	return res;
}
LIBART_FUNC(void*, _ZN3art3JNI17GetStringUTFCharsEP7_JNIEnvP8_jstringPh,
		void* env, void* string, void* is_copy) {
	return jni_GetStringUTFChars(env, string, is_copy);
}
// static jclass FindClass(JNIEnv* env, const char* name)
void* jni_FindClass(void* env, const char* name)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, env, name);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_JNIFINDCLASS, void*, env, char*, name, void*, res);
	return res;
}
LIBART_FUNC(void*,_ZN3art3JNI9FindClassEP7_JNIEnvPKc, 
		void* env, char* name)
{
	return jni_FindClass(env, name);
}

// static jmethodID GetMethodID(JNIEnv* env, jclass java_class, const char* name, const char* sig)
int jni_GetMethodID(void* env, void* java_class, const char* name, const char* sig)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, env, java_class, name, sig);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_JNIGETMETHODID, void*, java_class, char*, name, char*, sig, int, res);
	return res;
}
LIBART_FUNC(int, _ZN3art3JNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS6_,
		void* env, void* java_class, char* name, char* sig)
{
	return jni_GetMethodID(env, java_class, name, sig);
}

//
// static jmethodID GetStaticMethodID(JNIEnv* env, jclass java_class, const char* name, const char* sig)
int jni_GetStaticMethodID(void* env, void* java_class, const char* name, const char* sig)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, env, java_class, name, sig);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID, void*, java_class, char*, name, char*, sig, int, res);
	return res;
}
LIBART_FUNC(int, _ZN3art3JNI17GetStaticMethodIDEP7_JNIEnvP7_jclassPKcS6_,
		void* env, void* java_class, char* name, char* sig)
{
	return jni_GetMethodID(env, java_class, name, sig);
}
// void ClassLinker::LoadMethod(Thread* self, const DexFile& dex_file, const ClassDataItemIterator& it, Handle<mirror::Class> klass, ArtMethod* dst)
void ClassLinker_LoadMethod(void* this, void* thread, void* dex_file, void* it, void* klass, void* dst)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_6W(fn, this, thread, dex_file, it, klass, dst);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD, void*, dex_file, void*, klass, void*, dst);
}
LIBART_FUNC(void, _ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE,
		void* this, void* thread, void* dexfile, void* it, void* klass, void* dst)
{
	ClassLinker_LoadMethod(this, thread, dexfile, it, klass, dst);
}
#if 0
// void ClassLinker::LinkCode(ArtMethod* method, const OatFile::OatClass* oat_class,uint32_t class_def_method_index)
void ClassLinker_LinkCode(void *this, void* method, void* oat_class, int class_def_method_index)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_WWWW(fn, this, method, oat_class, class_def_method_index);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE, void*, method, void*, oat_class, int, class_def_method_index);
}
LIBART_FUNC(void, _ZN3art11ClassLinker8LinkCodeEPNS_9ArtMethodEPKNS_7OatFile8OatClassEj,
		void* this, void* method, void* oat_class, int class_def_method_index)
{
	ClassLinker_LinkCode(this, method, oat_class, class_def_method_index);
}
#endif
// extern "C" void artInterpreterToCompiledCodeBridge(Thread* self, const DexFile::CodeItem* code_item, ShadowFrame* shadow_frame, JValue* result)
// artInterpreterToInterpreterBridge

void ArtMethod_RegisterNative(const void* this, const void* native_method, Int is_fast){
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_WWW(fn, this, native_method, is_fast);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_REGISTERNATIVE, void*, this, void*, native_method, Int, is_fast);
}
//  void ArtMethod::RegisterNative(const void* native_method, bool is_fast)
LIBART_FUNC(void, _ZN3art9ArtMethod14RegisterNativeEPKvb,
		const void *this, const void *native_method, Int is_fast)
{
	ArtMethod_RegisterNative(this, native_method, is_fast);
}

// void* FindNativeMethod(ArtMethod* m, std::string& detail)
void* Library_FindNativeMethod(const void* this, const void* artMethod, void* std_string) {
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, this, artMethod, std_string);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_FINDNATIVEMETHOD, void*, this, void*, artMethod, void*, std_string, void*, res);
	return res;
}
// _ZN3art9Libraries16FindNativeMethodEPNS_9ArtMethodERNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE
LIBART_FUNC(void*,  _ZN3art9Libraries16FindNativeMethodEPNS_9ArtMethodERNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE,
		const void *this, const void* artMethod, void* std_string) 
{
	return Library_FindNativeMethod(this, artMethod, std_string);
}
#ifdef DE_VMP_TRACE
// _ZN3art21RegisterNativeMethodsEP7_JNIEnvPKcPK15JNINativeMethodi
//
//
//
// _ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib
//
// extern uint32_t JniMethodStart(Thread* self)
// _ZN3art12JniMethodEndEjPNS_6ThreadE
//
// extern void JniMethodEnd(uint32_t saved_local_ref_cookie, Thread* self)
// _ZN3art12JniMethodEndEjPNS_6ThreadE
//
// extern mirror::Object* JniMethodEndWithReference(jobject result, uint32_t saved_local_ref_cookie, Thread* self)
// _ZN3art25JniMethodEndWithReferenceEP8_jobjectjPNS_6ThreadE
//
//art::JNI::CallNonvirtualVoidMethodA(_JNIEnv*, _jobject*, _jclass*, _jmethodID*, jvalue*) (in /system/lib/libart.so)
//_ZN3art3JNI25CallNonvirtualVoidMethodAEP7_JNIEnvP8_jobjectP7_jclassP10_jmethodIDP6jvalue

//jobject NewGlobalRef(JNIEnv *env, jobject obj);
void* jni_NewGlobalRef(const void* env, const void* obj)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, env, obj);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_JNI_NEWGLOBALREF, void*, obj, void*, res);
	return res;
}
//_ZN3art3JNI12NewGlobalRefEP7_JNIEnvP8_jobject
LIBART_FUNC(void*, _ZN3art3JNI12NewGlobalRefEP7_JNIEnvP8_jobject, 
		const void* env, const void* jobject)
{
	return jni_NewGlobalRef(env, jobject);
}

//static jbooleanArray NewBooleanArray(JNIEnv* env, jsize length)
//_ZN3art3JNI15NewBooleanArrayEP7_JNIEnvi
//static jbyteArray NewByteArray(JNIEnv* env, jsize length)
void* jni_NewByteArray(void* env, int length)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, env, length);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_JNI_NEWBYTEARRAY, int, length, void*, res);
	return res;
}
//_ZN3art3JNI12NewByteArrayEP7_JNIEnvi
LIBART_FUNC(void*, _ZN3art3JNI12NewByteArrayEP7_JNIEnvi,
		void* env, int length)
{
	return jni_NewByteArray(env, length);
}
// static void SetByteArrayRegion(JNIEnv* env, jbyteArray array, jsize start, jsize length, const jbyte* buf)
// static void SetCharArrayRegion(JNIEnv* env, jcharArray array, jsize start, jsize length, const jchar* buf)

//static jcharArray NewCharArray(JNIEnv* env, jsize length) 
void* jni_NewCharArray(void* env, int length)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, env, length);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_JNI_NEWCHARARRAY, int, length, void*, res);
	return res;
}
//_ZN3art3JNI12NewCharArrayEP7_JNIEnvi
LIBART_FUNC(void*, _ZN3art3JNI12NewCharArrayEP7_JNIEnvi,
		void* env, int length)
{
	return jni_NewCharArray(env, length);
}
//static jdoubleArray NewDoubleArray(JNIEnv* env, jsize length)
//static jfloatArray NewFloatArray(JNIEnv* env, jsize length)
//static jintArray NewIntArray(JNIEnv* env, jsize length)
void* jni_NewIntArray(void* env, int length)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, env, length);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_JNI_NEWINTARRAY, int, length, void*, res);
	return res;
}
//_ZN3art3JNI11NewIntArrayEP7_JNIEnvi
LIBART_FUNC(void*, _ZN3art3JNI11NewIntArrayEP7_JNIEnvi,
		void* env, int length)
{
	return jni_NewIntArray(env, length);
}
//static jlongArray NewLongArray(JNIEnv* env, jsize length)
//static jobjectArray NewObjectArray(JNIEnv* env, jsize length, jclass element_jclass, jobject initial_element)
void* jni_NewObjectArray(void* env, int length, void* element_jclass, void* initial_element)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, env, length, element_jclass, initial_element);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_JNI_NEWOBJECTARRAY, int, length, void*, element_jclass, void*, initial_element, void*, res);
	return res;
}
//_ZN3art3JNI14NewObjectArrayEP7_JNIEnviP7_jclassP8_jobject
LIBART_FUNC(void*, _ZN3art3JNI14NewObjectArrayEP7_JNIEnviP7_jclassP8_jobject,
		void* env, int length, void* element_jclass, void* initial_element)
{
	return jni_NewObjectArray(env, length, element_jclass, initial_element);
}
#endif
#include "do_replace_strmem.c"
#endif
