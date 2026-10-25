/* Linux x86-64 syscall ABI. No libc, loader callbacks, allocator or threads.
 * Values/layouts checked against Ubuntu-6.8.0-142.142 UAPI and syscall_64.tbl.
 */
#ifndef WWW27_PERMISSION_ABI_H
#define WWW27_PERMISSION_ABI_H
#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error Linux native x86-64 only
#endif
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long usize;
typedef unsigned short u16;
#define NIL ((void *)0)
enum {
    RD = 0,
    WR = 1,
    CLOSE = 3,
    POLL = 7,
    MMAP = 9,
    MUNMAP = 11,
    DUP2 = 33,
    GETPID = 39,
    SOCKET = 41,
    CONNECT = 42,
    ACCEPT = 43,
    SENDMSG = 46,
    RECVMSG = 47,
    BIND = 49,
    LISTEN = 50,
    GETSOCKOPT = 55,
    CLONE = 56,
    EXECVE = 59,
    WAIT4 = 61,
    FCNTL = 72,
    FSYNC = 74,
    CHMOD = 90,
    UMASK = 95,
    GETRLIMIT = 97,
    GETUID = 102,
    GETGID = 104,
    GETEUID = 107,
    GETEGID = 108,
    GETPPID = 110,
    GETGROUPS = 115,
    CAPGET = 125,
    CAPSET = 126,
    PRCTL = 157,
    SETRLIMIT = 160,
    GETAFFINITY = 204,
    CLOCK_GETTIME = 228,
    EXIT_GROUP = 231,
    WAITID = 247,
    OPENAT = 257,
    MKDIRAT = 258,
    UNLINKAT = 263,
    READLINKAT = 267,
    ACCEPT4 = 288,
    PIPE2 = 293,
    SOCKETPAIR = 53,
    SECCOMP = 317,
    GETRANDOM = 318,
    STATX = 332,
    PIDFD_SIGNAL = 424,
    PIDFD_OPEN = 434,
    CLOSE_RANGE = 436
};
enum {
    AT_FDCWD = -100,
    O_RDONLY = 0,
    O_WRONLY = 1,
    O_CREAT = 64,
    O_EXCL = 128,
    O_CLOEXEC = 0x80000,
    O_NOFOLLOW = 0x20000,
    SOCK_SEQPACKET = 5,
    SOCK_NONBLOCK = 0x800,
    SOCK_CLOEXEC = 0x80000,
    AF_UNIX = 1,
    SOL_SOCKET = 1,
    SCM_RIGHTS = 1,
    SO_PEERCRED = 17,
    SO_PEERPIDFD = 77,
    MSG_DONTWAIT = 0x40,
    MSG_NOSIGNAL = 0x4000,
    MSG_CMSG_CLOEXEC = 0x40000000,
    MSG_TRUNC = 0x20,
    MSG_CTRUNC = 8,
    POLLIN = 1,
    POLLOUT = 4,
    POLLHUP = 16,
    POLLERR = 8,
    SIGCHLD = 17,
    SIGKILL = 9,
    SIGTERM = 15,
    CLONE_PIDFD = 0x1000,
    CLONE_NEWUSER = 0x10000000,
    CLONE_NEWPID = 0x20000000,
    WNOHANG = 1,
    PR_SET_PDEATHSIG = 1,
    PR_SET_DUMPABLE = 4,
    PR_CAPBSET_DROP = 24,
    PR_SET_CHILD_SUBREAPER = 36,
    PR_SET_NO_NEW_PRIVS = 38,
    PR_GET_NO_NEW_PRIVS = 39,
    PR_CAP_AMBIENT = 47,
    PR_CAP_AMBIENT_CLEAR_ALL = 4,
    RLIMIT_NPROC = 6
};
static inline long sc(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long out;
    __asm__ volatile("syscall"
                     : "=a"(out)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return out;
}
#define S0(n) sc(n, 0, 0, 0, 0, 0, 0)
#define S1(n, a) sc(n, (long)(a), 0, 0, 0, 0, 0)
#define S2(n, a, b) sc(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define S3(n, a, b, c) sc(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define S4(n, a, b, c, d) sc(n, (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)
#define S5(n, a, b, c, d, e) sc(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
struct pollfd {
    int fd;
    short events, revents;
};
struct timespec {
    long sec, nsec;
};
struct rlimit {
    u64 soft, hard;
};
struct sockaddr_un {
    u16 family;
    char path[108];
};
struct iovec {
    void *base;
    usize len;
};
struct msghdr {
    void *name;
    u32 namelen, pad;
    struct iovec *iov;
    usize iovlen;
    void *control;
    usize controllen;
    int flags, pad2;
};
struct cmsghdr {
    usize len;
    int level, type;
};
struct ucred {
    int pid;
    u32 uid, gid;
};
struct statx_time {
    long sec;
    u32 nsec;
    int reserved;
};
struct statx {
    u32 mask, blksize;
    u64 attrs;
    u32 nlink, uid, gid;
    u16 mode, spare;
    u64 ino, size, blocks, attrs_mask;
    struct statx_time atime, btime, ctime, mtime;
    u32 rdev_major, rdev_minor, dev_major, dev_minor;
    u64 mnt_id;
    u32 dio_mem, dio_offset;
    u64 spare3[12];
};
struct capheader {
    u32 version;
    int pid;
};
struct capdata {
    u32 effective, permitted, inheritable;
};
struct filter {
    u16 code;
    unsigned char jt, jf;
    u32 k;
};
struct program {
    u16 len;
    struct filter *insns;
};
_Static_assert(sizeof(long) == 8 && sizeof(struct msghdr) == 56, "x86-64 msg ABI");
_Static_assert(sizeof(struct statx) == 256 && sizeof(struct filter) == 8, "Linux UAPI ABI");
#endif
