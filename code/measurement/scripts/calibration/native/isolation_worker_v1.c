/* Persistent host-E C; fixed fixtures plus a separate candidate I/O entry.
 * Derived utilities/absolute Apptainer launch from accepted P e9c1d2e4/ABI
 * d74be03f. P bytes and its capability are not changed. Source capability is
 * W's independent I assets/R/owner gates authorize any launch. The candidate
 * entry reads only stdin and retains the private namespace/resource limits.
 * No libc, dynamic loader, thread library or arbitrary program arguments.
 */
#include "isolation_worker_abi_v1.h"
static const volatile int ISOLATION_RELEASE_ENABLED = 1;
static u64 seq, deadline, worker_end, setup_end, service_end;
static int role, case_index, trace = -1, supervisor = -1;
static u64 supervisor_seq;
static int journal_error, log_error, log_read = -1, log_output = -1;
static int runtime_expected_pid = -1, runtime_reaped, outer_wait_error;
static usize journal_count, log_bytes;
static const char *case_nonce, *worker_nonce;
static const char *case_names[] = {"", "controls", "cpu", "reuse"};
void *memset(void *p, int c, usize n) {
    unsigned char *q = p;
    while (n--)
        *q++ = (unsigned char)c;
    return p;
}
void *memcpy(void *d, const void *s, usize n) {
    unsigned char *a = d;
    const unsigned char *b = s;
    while (n--)
        *a++ = *b++;
    return d;
}
static usize len(const char *s) {
    usize n = 0;
    while (s[n])
        n++;
    return n;
}
static int eq(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}
static int copy(char *d, usize cap, const char *s) {
    usize n = len(s);
    if (n >= cap)
        return -1;
    memcpy(d, s, n + 1);
    return 0;
}
static int cat(char *d, usize cap, const char *s) {
    usize n = len(d);
    return copy(d + n, cap - n, s);
}
static void number(char *p, long v) {
    char b[32];
    usize n = 0, i = 0;
    if (v < 0) {
        p[i++] = '-';
        v = -v;
    }
    do {
        b[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n)
        p[i++] = b[--n];
    p[i] = 0;
}
static long decimal(const char *p) {
    long v = 0;
    if (*p < '0' || *p > '9')
        return -1;
    while (*p >= '0' && *p <= '9') {
        if (v > 1000000000000000L)
            return -1;
        v = v * 10 + *p++ - '0';
    }
    return (*p == 0 || *p == '\n' || *p == '\t' || *p == ' ') ? v : -1;
}
static int prefix(const char *s, const char *p) {
    while (*p)
        if (*s++ != *p++)
            return 0;
    return 1;
}
static const char *field(const char *s, const char *p) {
    while (*s) {
        if (prefix(s, p))
            return s + len(p);
        while (*s && *s != '\n')
            s++;
        if (*s)
            s++;
    }
    return NIL;
}
static u64 now(void) {
    struct timespec t = {0};
    if (S2(CLOCK_GETTIME, 1, &t) < 0)
        return 0;
    return (u64)t.sec * 1000000000UL + t.nsec;
}
static _Noreturn void end(int code) {
    S1(EXIT_GROUP, code);
    for (;;) {
    }
}
static int write_all(int fd, const void *p, usize n) {
    const char *s = p;
    while (n) {
        long r = S3(WR, fd, s, n);
        if (r == -4)
            continue;
        if (r <= 0)
            return r < 0 ? (int)r : -5;
        s += r;
        n -= (usize)r;
    }
    return 0;
}
static long read_file(const char *path, char *out, usize cap) {
    memset(out, 0, cap);
    long f = S4(OPENAT, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (f < 0)
        return f;
    long n = S3(RD, f, out, cap - 1);
    if (n >= 0) {
        char extra;
        if ((usize)n == cap - 1 && S3(RD, f, &extra, 1) > 0)
            n = -7;
    }
    S1(CLOSE, f);
    if (n >= 0)
        out[n] = 0;
    return n;
}
static int create_file(const char *p) {
    return (int)S4(OPENAT, AT_FDCWD, p, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
}
static int put_file(const char *p, const char *s) {
    long f = S4(OPENAT, AT_FDCWD, p, O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (f < 0)
        return (int)f;
    int rc = write_all((int)f, s, len(s));
    S1(CLOSE, f);
    return rc;
}
static void drain_log(void) {
    if (log_read < 0)
        return;
    char b[4096];
    for (;;) {
        long n = S3(RD, log_read, b, sizeof b);
        if (n == -4)
            continue;
        if (n == -11)
            return;
        if (n <= 0) {
            if (n < 0)
                log_error = 1;
            S1(CLOSE, log_read);
            log_read = -1;
            return;
        }
        if (log_bytes + (usize)n > 65536 || write_all(log_output, b, (usize)n) < 0) {
            log_error = 1;
            S1(CLOSE, log_read);
            log_read = -1;
            return;
        }
        log_bytes += (usize)n;
    }
}
static int ready(int fd, short wanted, u64 until) {
    for (;;) {
        drain_log();
        if (log_error)
            return -5;
        u64 t = now();
        if (!t || t >= until)
            return -110;
        struct pollfd p[2] = {{fd, wanted, 0}, {log_read, POLLIN, 0}};
        long ms = (long)((until - t + 999999) / 1000000);
        if (ms > 50)
            ms = 50;
        long rc = S3(POLL, p, log_read >= 0 ? 2 : 1, ms);
        if (rc == -4)
            continue;
        if (rc < 0)
            return (int)rc;
        if (p[0].revents & (wanted | POLLHUP | POLLERR))
            return p[0].revents;
    }
}
static int exited(int pidfd) {
    struct pollfd p = {pidfd, POLLIN, 0};
    return S3(POLL, &p, 1, 0) > 0 && (p.revents & (POLLIN | POLLHUP));
}
static int signal_fd(int fd, int sig) { return (int)S4(PIDFD_SIGNAL, fd, sig, 0, 0); }
static int wait_child(int pid, int *status, u64 until) {
    for (;;) {
        long r = S4(WAIT4, pid, status, WNOHANG, 0);
        if (r == pid)
            return 0;
        if (r < 0 && r != -4)
            return (int)r;
        u64 current = now();
        if (!current || current >= until)
            return -110;
        S3(POLL, 0, 0, 5);
    }
}
static struct frame make(int event, const char *text) {
    struct frame f;
    memset(&f, 0, sizeof f);
    f.magic = MAGIC; f.version = VERSION; f.role = (u32)role;
    f.event = (u32)event; f.seq = ++seq; f.ns = now(); f.v[0] = case_index;
    if (text && copy(f.text, sizeof f.text, text) < 0) f.event = FAILED;
    return f;
}
static int send_frame(int fd, const struct frame *f, int passed) {
    struct iovec iov = {(void *)f, sizeof *f};
    unsigned char control[24] = {0};
    struct msghdr h;
    memset(&h, 0, sizeof h);
    h.iov = &iov;
    h.iovlen = 1;
    if (passed >= 0) {
        struct cmsghdr *c = (void *)control;
        c->len = 20;
        c->level = SOL_SOCKET;
        c->type = SCM_RIGHTS;
        memcpy(control + 16, &passed, 4);
        h.control = control;
        h.controllen = 24;
    }
    return S3(SENDMSG, fd, &h, MSG_NOSIGNAL | MSG_DONTWAIT) == sizeof *f ? 0 : -1;
}
static int recv_frame(int fd, struct frame *f, int *passed, u64 until) {
    unsigned char ctl[256] = {0};
    struct iovec io = {f, sizeof *f};
    struct msghdr h;
    memset(&h, 0, sizeof h);
    h.iov = &io;
    h.iovlen = 1;
    h.control = ctl;
    h.controllen = sizeof ctl;
    *passed = -1;
    if (ready(fd, POLLIN, until) < 0)
        return -110;
    long n = S3(RECVMSG, fd, &h, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    int bad = 0, count = 0;
    for (usize o = 0; o + 16 <= h.controllen;) {
        struct cmsghdr *c = (void *)(ctl + o);
        if (c->len < 16 || o + c->len > h.controllen) {
            bad = 1;
            break;
        }
        if (c->level != SOL_SOCKET || c->type != SCM_RIGHTS || (c->len - 16) % 4) {
            bad = 1;
            break;
        }
        for (usize k = o + 16; k < o + c->len; k += 4) {
            int x;
            memcpy(&x, ctl + k, 4);
            if (++count == 1)
                *passed = x;
            else {
                S1(CLOSE, x);
                bad = 1;
            }
        }
        o += (c->len + 7) & ~7UL;
    }
    if (n == 0 && !count)
        return -32;
    int nul = 0;
    for (int j = 0; n == sizeof *f && j < 256; j++) {
        if (!f->text[j])
            nul = 1;
        else if (nul)
            bad = 1;
    }
    if (n != sizeof *f || h.flags & (MSG_TRUNC | MSG_CTRUNC) || bad || f->magic != MAGIC ||
        f->version != VERSION || f->role < 1 || f->role > 6 || !f->seq || f->text[255]) {
        if (*passed >= 0)
            S1(CLOSE, *passed);
        *passed = -1;
        return -71;
    }
    return 0;
}
static int record(const struct frame *f, int passed) {
    if (f->event == FAILED) journal_error = 1;
    if (trace < 0 || journal_count++ >= MAX_FRAMES || write_all(trace, f, sizeof *f) < 0) {
        journal_error = 1; return -1;
    }
    if (supervisor >= 0 && send_frame(supervisor, f, passed) < 0) {
        journal_error = 1; return -1;
    }
    return 0;
}
static int journal(const struct frame *f) { return record(f, -1); }
static int emit(int fd, int event, const char *text, long a, long b, long c, int passed) {
    struct frame f = make(event, text);
    f.v[1] = a; f.v[2] = b; f.v[3] = c;
    return send_frame(fd, &f, passed);
}
static int fail(int fd, const char *stage, long rc) {
    emit(fd, FAILED, stage, rc, 0, 0, -1); return 1;
}
static int socket_pair(int p[2]) {
    return (int)S4(SOCKETPAIR, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, p);
}
static int only_thread(void) {
    char b[8192];
    if (read_file("/proc/self/status", b, sizeof b) < 0)
        return 0;
    const char *p = field(b, "Threads:\t");
    return p && decimal(p) == 1;
}
static int ns_id(const char *path, char out[256]) {
    long n = S4(READLINKAT, AT_FDCWD, path, out, 255);
    if (n <= 0 || n >= 255)
        return -1;
    out[n] = 0;
    return 0;
}
static int context(int fd) {
    char b[8192], x[256];
    struct rlimit r = {0};
    if (!only_thread() || S2(GETRLIMIT, RLIMIT_NPROC, &r) < 0)
        return fail(fd, "context-thread-limit", -1);
    struct frame limits = make(CONTEXT, "uid-gid-limit");
    limits.v[1] = S0(GETUID);
    limits.v[2] = S0(GETGID);
    limits.v[3] = (long)r.soft;
    limits.v[4] = (long)r.hard;
    limits.v[5] = S2(GETGROUPS, 0, 0);
    if (send_frame(fd, &limits, -1) < 0)
        return 1;
    const char *paths[] = {"/proc/self/ns/user", "/proc/self/ns/pid"};
    for (int j = 0; j < 2; j++) {
        if (ns_id(paths[j], x) < 0)
            return fail(fd, "namespace-read", -1);
        if (emit(fd, CONTEXT, x, j, 0, 0, -1) < 0)
            return 1;
    }
    if (read_file("/proc/self/attr/current", x, sizeof x) < 0)
        return fail(fd, "lsm-label-read", -1);
    if (emit(fd, CONTEXT, x, 2, 0, 0, -1) < 0)
        return 1;
    if (read_file("/proc/self/status", b, sizeof b) < 0)
        return 1;
    const char *keys[] = {"CapEff:\t", "CapPrm:\t", "CapAmb:\t", "CapBnd:\t"};
    for (int j = 0; j < 4; j++) {
        const char *p = field(b, keys[j]);
        if (!p)
            return fail(fd, "cap-field", j);
        usize n = 0;
        while (p[n] && p[n] != '\n')
            n++;
        if (n >= sizeof x)
            return 1;
        memcpy(x, p, n);
        x[n] = 0;
        if (emit(fd, CONTEXT, x, 3 + j, 0, 0, -1) < 0)
            return 1;
    }
    return 0;
}
static int drop_caps(void) {
    for (int c = 0; c <= 40; c++)
        if (S2(PRCTL, PR_CAPBSET_DROP, c) < 0)
            return -1;
    struct capheader h = {0x20080522, 0};
    struct capdata d[2] = {{0}};
    if (S2(CAPSET, &h, d) < 0 || S2(PRCTL, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL) < 0)
        return -1;
    return 0;
}
static int active_caps_zero(void) {
    struct capheader h = {0x20080522, 0};
    struct capdata d[2];
    memset(d, 0xff, sizeof d);
    if (S2(CAPGET, &h, d) < 0)
        return 0;
    for (int j = 0; j < 2; j++)
        if (d[j].effective || d[j].permitted || d[j].inheritable)
            return 0;
    char b[8192];
    if (read_file("/proc/self/status", b, sizeof b) < 0)
        return 0;
    const char *p = field(b, "CapAmb:\t");
    if (!p)
        return 0;
    while (*p && *p != '\n') {
        if (*p != '0')
            return 0;
        p++;
    }
    return 1;
}
static int close_except(int one, int two) {
    if (one >= 64 || two >= 64)
        return -1;
    for (int n = 3; n < 64; n++)
        if (n != one && n != two)
            S1(CLOSE, n);
    return (int)S3(CLOSE_RANGE, 64, 0xffffffffU, 0);
}
static int parent_guard(int pidfd) {
    if (exited(pidfd))
        return -1;
    if (S2(PRCTL, PR_SET_PDEATHSIG, SIGKILL) < 0)
        return -1;
    return exited(pidfd) ? -1 : 0;
}
static int mapping(int control, long pid, long uid, long gid) {
    char base[128] = "/proc/", n[32], p[160], v[256];
    number(n, pid);
    cat(base, sizeof base, n);
    const char *names[] = {"/setgroups", "/uid_map", "/gid_map"};
    for (int j = 0; j < 3; j++) {
        copy(p, sizeof p, base);
        cat(p, sizeof p, names[j]);
        if (j == 0)
            copy(v, sizeof v, "deny\n");
        else {
            number(n, j == 1 ? uid : gid);
            copy(v, sizeof v, n);
            cat(v, sizeof v, " ");
            cat(v, sizeof v, n);
            cat(v, sizeof v, " 1\n");
        }
        int rc = put_file(p, v);
        emit(control, MAPPING, names[j], j, rc, 0, -1);
        if (rc < 0)
            return rc;
        long size = read_file(p, v, sizeof v);
        if (size < 0)
            return (int)size;
        if (emit(control, MAPPING, v, j, 0, 1, -1) < 0)
            return -5;
    }
    return 0;
}
static int connect_path(const char *path) {
    struct sockaddr_un s = {AF_UNIX, {0}};
    if (copy(s.path, sizeof s.path, path) < 0)
        return -1;
    int f = (int)S3(SOCKET, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (f < 0)
        return f;
    long r = S3(CONNECT, f, &s, 2 + len(path) + 1);
    if (r < 0) {
        S1(CLOSE, f);
        return (int)r;
    }
    return f;
}
/* Host controller and strict launch/identity checks follow. */
static char scratch[8192];
static int stat_path(const char *p, struct statx *s) {
    memset(s, 0, sizeof *s);
    long r = S5(STATX, AT_FDCWD, p, 0, 0x7ff, s);
    return r == 0 && (s->mask & 0x1ff) == 0x1ff ? 0 : -1;
}
static int same_frontend_stat(const struct statx *a, const struct statx *b) {
    return a->ino == b->ino && a->dev_major == b->dev_major && a->dev_minor == b->dev_minor &&
           a->size == b->size && a->uid == b->uid && a->gid == b->gid && a->mode == b->mode &&
           a->mtime.sec == b->mtime.sec && a->mtime.nsec == b->mtime.nsec &&
           a->ctime.sec == b->ctime.sec && a->ctime.nsec == b->ctime.nsec;
}
static int frontend_fd(const char *runtime, char **env, struct statx *identity) {
    long fd = S4(OPENAT, AT_FDCWD, runtime, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0)
        return -1;
    memset(identity, 0, sizeof *identity);
    long result = S5(STATX, fd, "", 0x1000, 0x7ff, identity); /* AT_EMPTY_PATH */
    struct statx path;
    if (result < 0 || (identity->mask & 0x1ff) != 0x1ff || stat_path(runtime, &path) ||
        !same_frontend_stat(identity, &path) || identity->uid != 0 ||
        (identity->mode & 0170000) != 0100000 || (identity->mode & 06022) ||
        !(identity->mode & 0111) || identity->size == 0 || identity->size > 268435456UL) {
        S1(CLOSE, fd);
        return -1;
    }
    /* Compare the native held fd to Python's final, fully hashed file pin.
     * These are input bindings, not release/authority environment switches. */
    const char *keys[] = {"WWW27_I_FRONTEND_INODE", "WWW27_I_FRONTEND_MAJOR", "WWW27_I_FRONTEND_MINOR",
                         "WWW27_I_FRONTEND_BYTES", "WWW27_I_FRONTEND_MTIME", "WWW27_I_FRONTEND_CTIME",
                         "WWW27_I_FRONTEND_GID", "WWW27_I_FRONTEND_MODE"};
    long expected[8] = {-1,-1,-1,-1,-1,-1,-1,-1};
    for (int j = 0; j < 8; j++) {
        usize n = len(keys[j]);
        int seen = 0;
        for (int k = 0; env[k]; k++)
            if (prefix(env[k], keys[j]) && env[k][n] == '=') {
                const char *value = env[k] + n + 1;
                seen++;
                expected[j] = *value ? 0 : -1;
                for (usize at = 0; value[at]; at++) {
                    int digit = value[at]-'0';
                    if (digit < 0 || digit > 9 || expected[j] < 0 ||
                        expected[j] > (0x7fffffffffffffffL-digit)/10) {
                        expected[j] = -1;
                        break;
                    }
                    expected[j] = expected[j]*10+digit;
                }
            }
        if (seen != 1)
            expected[j] = -1;
    }
    if (identity->mtime.sec < 0 || identity->ctime.sec < 0 ||
        identity->mtime.nsec >= 1000000000U || identity->ctime.nsec >= 1000000000U ||
        identity->mtime.sec > (0x7fffffffffffffffL-identity->mtime.nsec)/1000000000L ||
        identity->ctime.sec > (0x7fffffffffffffffL-identity->ctime.nsec)/1000000000L) {
        S1(CLOSE, fd);
        return -1;
    }
    long mtime = identity->mtime.sec*1000000000L+identity->mtime.nsec;
    long ctime = identity->ctime.sec*1000000000L+identity->ctime.nsec;
    if (expected[0] <= 0 || expected[1] < 0 || expected[1] > 0xffffffffL ||
        expected[2] < 0 || expected[2] > 0xffffffffL ||
        (u64)expected[0] != identity->ino || (u32)expected[1] != identity->dev_major ||
        (u32)expected[2] != identity->dev_minor || expected[3] != (long)identity->size ||
        expected[4] != mtime || expected[5] != ctime || expected[6] != identity->gid ||
        expected[7] != identity->mode) {
        S1(CLOSE, fd);
        return -1;
    }
    struct frame f = make(FRONTEND_FD, runtime);
    f.v[1] = (long)identity->ino; f.v[2] = identity->dev_major; f.v[3] = identity->dev_minor;
    f.v[4] = identity->mode; f.v[5] = identity->uid; f.v[6] = (long)identity->size;
    f.v[7] = mtime;
    struct frame t = make(FRONTEND_TIMES, "preexec-mtime-ctime-gid");
    t.v[1] = mtime; t.v[2] = ctime; t.v[3] = identity->gid;
    if (journal(&f) || journal(&t)) { S1(CLOSE, fd); return -1; }
    return (int)fd;
}

static int same_executable(int pid, const char *helper) {
    char p[128] = "/proc/", n[32];
    number(n, pid);
    cat(p, sizeof p, n);
    cat(p, sizeof p, "/exe");
    struct statx a, b, c;
    if (stat_path(p, &a) || stat_path(helper, &b) || stat_path("/proc/self/exe", &c))
        return 0;
    return a.ino == b.ino && a.dev_major == b.dev_major && a.dev_minor == b.dev_minor &&
           a.ino == c.ino && a.dev_major == c.dev_major && a.dev_minor == c.dev_minor;
}
static int descendant(int pid, int ancestor) {
    for (int j = 0; j < 128 && pid > 1; j++) {
        if (pid == ancestor)
            return 1;
        char p[96] = "/proc/", n[32];
        number(n, pid);
        cat(p, sizeof p, n);
        cat(p, sizeof p, "/status");
        if (read_file(p, scratch, sizeof scratch) < 0)
            return 0;
        const char *q = field(scratch, "PPid:\t");
        if (!q)
            return 0;
        pid = (int)decimal(q);
    }
    return 0;
}
static int fd_pid(int fd) {
    char p[96] = "/proc/self/fdinfo/", n[32];
    number(n, fd);
    cat(p, sizeof p, n);
    if (read_file(p, scratch, sizeof scratch) < 0)
        return -1;
    const char *q = field(scratch, "Pid:\t");
    return q ? (int)decimal(q) : -1;
}
static int starter_pin(char **env, struct statx *identity) {
    const char *keys[] = {"WWW27_I_STARTER_INODE", "WWW27_I_STARTER_MAJOR", "WWW27_I_STARTER_MINOR"};
    long expected[3] = {-1,-1,-1};
    for (int j = 0; j < 3; j++) {
        usize n = len(keys[j]);
        int seen = 0;
        for (int k = 0; env[k]; k++)
            if (prefix(env[k], keys[j]) && env[k][n] == '=') {
                const char *value = env[k] + n + 1;
                seen++;
                expected[j] = *value ? 0 : -1;
                for (usize at = 0; value[at]; at++) {
                    int digit = value[at]-'0';
                    if (digit < 0 || digit > 9 || expected[j] < 0 ||
                        expected[j] > (0x7fffffffffffffffL-digit)/10) {
                        expected[j] = -1;
                        break;
                    }
                    expected[j] = expected[j]*10+digit;
                }
            }
        if (seen != 1)
            expected[j] = -1;
    }
    if (expected[0] <= 0 || expected[1] < 0 || expected[1] > 0xffffffffL ||
        expected[2] < 0 || expected[2] > 0xffffffffL)
        return -1;
    memset(identity, 0, sizeof *identity);
    identity->ino = (u64)expected[0];
    identity->dev_major = (u32)expected[1];
    identity->dev_minor = (u32)expected[2];
    return 0;
}
static int observe_frontend_exec(int pid, int pidfd, const struct statx *expected,
                                 const struct statx *starter, u64 until) {
    char path[128] = "/proc/", n[32];
    number(n, pid);
    cat(path, sizeof path, n);
    cat(path, sizeof path, "/exe");
    struct statx own;
    if (stat_path("/proc/self/exe", &own))
        return -1;
    for (;;) {
        u64 current = now();
        if (!current || current >= until)
            return -1;
        if (fd_pid(pidfd) != pid || exited(pidfd))
            return -1;
        struct statx observed;
        if (!stat_path(path, &observed)) {
            const struct statx *matched = NIL;
            const char *kind = "frontend-exec-observed";
            if (observed.ino == expected->ino && observed.dev_major == expected->dev_major &&
                observed.dev_minor == expected->dev_minor)
                matched = expected;
            else if (observed.ino == starter->ino && observed.dev_major == starter->dev_major &&
                     observed.dev_minor == starter->dev_minor) {
                matched = starter;
                kind = "starter-exec-observed";
            }
            if (matched) {
                if (exited(pidfd) || fd_pid(pidfd) != pid)
                    return -1;
                struct frame f = make(FRONTEND_EXEC, kind);
                f.v[1] = pid;
                f.v[2] = (long)observed.ino;
                f.v[3] = observed.dev_major;
                f.v[4] = observed.dev_minor;
                f.v[5] = (long)matched->ino;
                f.v[6] = matched->dev_major;
                f.v[7] = matched->dev_minor;
                return journal(&f);
            }
            /* Only the just-cloned helper may precede either approved image.
             * Any other inode is a closed failure. A starter observation is
             * recorded as such, never described as a sampled frontend. */
            if (observed.ino != own.ino || observed.dev_major != own.dev_major ||
                observed.dev_minor != own.dev_minor)
                return -1;
        }
        drain_log();
        S3(POLL, 0, 0, 1);
    }
}
static int same_cgroup(int pid) {
    char own[2048], other[2048], p[96] = "/proc/", n[32];
    if (read_file("/proc/self/cgroup", own, sizeof own) < 0)
        return 0;
    number(n, pid);
    cat(p, sizeof p, n);
    cat(p, sizeof p, "/cgroup");
    return read_file(p, other, sizeof other) >= 0 && eq(own, other);
}
static int distinct_namespaces(int init, int parent) {
    char ip[96], ap[96], n[32], ix[256], ax[256];
    const char *suffix[] = {"/ns/user", "/ns/pid", "/ns/mnt", "/ns/net"};
    for (int j = 0; j < 4; j++) {
        copy(ip, sizeof ip, "/proc/");
        number(n, init);
        cat(ip, sizeof ip, n);
        cat(ip, sizeof ip, suffix[j]);
        copy(ap, sizeof ap, "/proc/");
        number(n, parent);
        cat(ap, sizeof ap, n);
        cat(ap, sizeof ap, suffix[j]);
        if (ns_id(ip, ix) < 0 || ns_id(ap, ax) < 0 || eq(ix, ax))
            return 0;
        struct frame f = make(IDENTITY, ix);
        f.v[1] = j;
        f.v[2] = init;
        f.v[3] = parent;
        if (journal(&f))
            return 0;
    }
    return 1;
}
static const char *env_value(char **env, const char *key) {
    usize n = len(key);
    for (; *env; env++)
        if (prefix(*env, key) && (*env)[n] == '=')
            return *env + n + 1;
    return "";
}
static int resources(char **env) {
    const char *job = env_value(env, "SLURM_JOB_ID");
    if (decimal(job) <= 0 || *env_value(env, "SLURM_JOB_GPUS") ||
        *env_value(env, "SLURM_STEP_GPUS") || S0(GETUID) <= 0)
        return -1;
    char cgroup[2048], base[2304], p[2400], text[512], needle[96] = "/job_";
    cat(needle, sizeof needle, job);
    cat(needle, sizeof needle, "/");
    const char *kp[] = {"/proc/sys/kernel/osrelease", "/proc/version_signature"};
    const char *kv[] = {"6.8.0-142-generic\n", "Ubuntu 6.8.0-142.142-generic 6.8.12\n"};
    for (int j = 0; j < 2; j++) {
        if (read_file(kp[j], text, sizeof text) < 0 || !eq(text, kv[j]))
            return -1;
        struct frame k = make(KERNEL, text);
        k.v[1] = j;
        if (journal(&k))
            return -1;
    }
    if (read_file("/proc/self/cgroup", cgroup, sizeof cgroup) < 0 || !prefix(cgroup, "0::/") ||
        field(cgroup + 4, "0::"))
        return -1;
    int found = 0;
    for (usize j = 3; cgroup[j]; j++)
        if (prefix(cgroup + j, needle))
            found = 1;
    if (!found)
        return -1;
    for (usize j = 3; cgroup[j]; j++) {
        if (cgroup[j] == '\n') {
            cgroup[j] = 0;
            break;
        }
        if (cgroup[j] == '.' && cgroup[j + 1] == '.')
            return -1;
    }
    copy(base, sizeof base, "/sys/fs/cgroup");
    cat(base, sizeof base, cgroup + 3);
    copy(p, sizeof p, base);
    cat(p, sizeof p, "/cpuset.cpus.effective");
    if (read_file(p, text, sizeof text) < 0)
        return -1;
    long cpu = decimal(text);
    if (cpu < 0 || cpu >= 1024)
        return -1;
    for (usize j = 0; text[j]; j++)
        if (text[j] != '\n' && (text[j] < '0' || text[j] > '9'))
            return -1;
    unsigned char mask[128] = {0};
    if (S3(GETAFFINITY, 0, sizeof mask, mask) < 0)
        return -1;
    int bits = 0;
    for (int j = 0; j < 1024; j++)
        if (mask[j / 8] & (1U << (j % 8))) {
            bits++;
            if (j != cpu)
                return -1;
        }
    if (bits != 1)
        return -1;
    struct frame cpus = make(RESOURCE_DETAIL, p);
    cpus.v[1] = 2;
    cpus.v[3] = cpu;
    if (journal(&cpus))
        return -1;
    long minimum = 0x7fffffffffffffffL;
    for (int j = 0; j < 64; j++) {
        const char *names[] = {"/memory.max", "/memory.swap.max"};
        for (int k = 0; k < 2; k++) {
            copy(p, sizeof p, base);
            cat(p, sizeof p, names[k]);
            long n = read_file(p, text, sizeof text), value = -2;
            if (n >= 0) {
                if (eq(text, "max\n") || eq(text, "max"))
                    value = -1;
                else {
                    value = decimal(text);
                    if (value < 0)
                        return -1;
                }
                if (k == 0 && value == 0)
                    return -1;
            }
            struct frame detail = make(RESOURCE_DETAIL, p);
            detail.v[1] = k;
            detail.v[2] = n < 0 ? n : 0;
            detail.v[3] = value;
            if (journal(&detail))
                return -1;
            if (k == 0 && value > 0 && value < minimum)
                minimum = value;
        }
        if (eq(base, "/sys/fs/cgroup"))
            break;
        usize n = len(base);
        while (n && base[n - 1] != '/')
            n--;
        if (n <= len("/sys/fs/cgroup"))
            copy(base, sizeof base, "/sys/fs/cgroup");
        else
            base[n - 1] = 0;
    }
    if (minimum > 1073741824L)
        return -1;
    struct frame f = make(RESOURCE, cgroup + 3);
    f.v[1] = cpu;
    f.v[2] = minimum;
    return journal(&f);
}
static int make_nonce(char out[65]) {
    unsigned char raw[32] = {0};
    if (S3(GETRANDOM, raw, 32, 0) != 32)
        return -1;
    const char *h = "0123456789abcdef";
    for (int j = 0; j < 32; j++) {
        out[j * 2] = h[raw[j] >> 4];
        out[j * 2 + 1] = h[raw[j] & 15];
    }
    out[64] = 0;
    return 0;
}

/* Trusted-fixture allowlists only; not a candidate filter implementation.
 * The second filter is self-installed by this trusted ELF AFTER exec. N must
 * install a candidate filter in J BEFORE any future candidate exec; no such
 * candidate entry or pre-exec filter is implemented in this fixture package.
 * Default EPERM; other architecture/x32 kills process.
 * clone3 is ENOSYS, ordinary fork/thread clone flags remain possible inside
 * the private 32-task budget; namespace/parent/vfork/ptrace escapes are denied.
 * Only trusted I/J retain the one fixed CLOEXEC ELF fd63 execveat transition.
 * Payload attaches the stricter second filter, which denies all execve(at),
 * sockets, mount/namespace/credential/rlimit changes, ptrace, bpf, io_uring,
 * perf, keyrings, open_by_handle, process_vm, signals and migration calls.
 */
static const struct filter supervisor_filter[] = {
    {0x20, 0, 0, 0x4U},
    {0x15, 0, 58, 0xc000003eU},
    {0x20, 0, 0, 0x0U},
    {0x45, 56, 0, 0x40000000U},
    {0x15, 0, 4, 0x38U},
    {0x20, 0, 0, 0x14U},
    {0x15, 0, 51, 0x0U},
    {0x20, 0, 0, 0x10U},
    {0x45, 49, 48, 0xfec2e000U},
    {0x15, 49, 0, 0x1b3U},
    {0x15, 0, 9, 0x9dU},
    {0x20, 0, 0, 0x10U},
    {0x15, 44, 0, 0x27U},
    {0x15, 43, 0, 0x17U},
    {0x15, 0, 2, 0x4U},
    {0x20, 0, 0, 0x18U},
    {0x15, 40, 41, 0x0U},
    {0x15, 0, 40, 0x1U},
    {0x20, 0, 0, 0x18U},
    {0x15, 37, 38, 0x9U},
    {0x15, 0, 6, 0x142U},
    {0x20, 0, 0, 0x10U},
    {0x15, 0, 35, 0x3fU},
    {0x20, 0, 0, 0x30U},
    {0x15, 0, 33, 0x1000U},
    {0x20, 0, 0, 0x34U},
    {0x15, 30, 31, 0x0U},
    {0x15, 29, 0, 0x0U},
    {0x15, 28, 0, 0x1U},
    {0x15, 27, 0, 0x3U},
    {0x15, 26, 0, 0x7U},
    {0x15, 25, 0, 0x23U},
    {0x15, 24, 0, 0x27U},
    {0x15, 23, 0, 0x3dU},
    {0x15, 22, 0, 0x61U},
    {0x15, 21, 0, 0x66U},
    {0x15, 20, 0, 0x68U},
    {0x15, 19, 0, 0x6bU},
    {0x15, 18, 0, 0x6cU},
    {0x15, 17, 0, 0x6eU},
    {0x15, 16, 0, 0x7dU},
    {0x15, 15, 0, 0xe4U},
    {0x15, 14, 0, 0xe7U},
    {0x15, 13, 0, 0x3cU},
    {0x15, 12, 0, 0xf7U},
    {0x15, 11, 0, 0x125U},
    {0x15, 10, 0, 0x2eU},
    {0x15, 9, 0, 0x2fU},
    {0x15, 8, 0, 0x35U},
    {0x15, 7, 0, 0x48U},
    {0x15, 6, 0, 0x21U},
    {0x15, 5, 0, 0x13dU},
    {0x15, 4, 0, 0x1b2U},
    {0x15, 3, 0, 0x1a8U},
    {0x15, 2, 0, 0x1b4U},
    {0x15, 1, 0, 0x101U},
    {0x6, 0, 0, 0x50001U},
    {0x6, 0, 0, 0x7fff0000U},
    {0x6, 0, 0, 0x50001U},
    {0x6, 0, 0, 0x50026U},
    {0x6, 0, 0, 0x80000000U},
};
static const struct filter payload_filter[] = {
    {0x20, 0, 0, 0x4U},
    {0x15, 0, 36, 0xc000003eU},
    {0x20, 0, 0, 0x0U},
    {0x45, 34, 0, 0x40000000U},
    {0x15, 0, 4, 0x38U},
    {0x20, 0, 0, 0x14U},
    {0x15, 0, 29, 0x0U},
    {0x20, 0, 0, 0x10U},
    {0x45, 27, 26, 0xfec2e000U},
    {0x15, 27, 0, 0x1b3U},
    {0x15, 0, 4, 0x9dU},
    {0x20, 0, 0, 0x10U},
    {0x15, 22, 0, 0x27U},
    {0x15, 21, 0, 0x17U},
    {0x6, 0, 0, 0x50001U},
    {0x15, 19, 0, 0x0U},
    {0x15, 18, 0, 0x1U},
    {0x15, 17, 0, 0x3U},
    {0x15, 16, 0, 0x7U},
    {0x15, 15, 0, 0x23U},
    {0x15, 14, 0, 0x27U},
    {0x15, 13, 0, 0x3dU},
    {0x15, 12, 0, 0x61U},
    {0x15, 11, 0, 0x66U},
    {0x15, 10, 0, 0x68U},
    {0x15, 9, 0, 0x6bU},
    {0x15, 8, 0, 0x6cU},
    {0x15, 7, 0, 0x6eU},
    {0x15, 6, 0, 0x7dU},
    {0x15, 5, 0, 0xe4U},
    {0x15, 4, 0, 0xe7U},
    {0x15, 3, 0, 0x3cU},
    {0x15, 2, 0, 0x48U},
    {0x15, 1, 0, 0x101U},
    {0x6, 0, 0, 0x50001U},
    {0x6, 0, 0, 0x7fff0000U},
    {0x6, 0, 0, 0x50001U},
    {0x6, 0, 0, 0x50026U},
    {0x6, 0, 0, 0x80000000U},
};
static int install_filter(int payload) {
    struct program p;
    p.insns = (struct filter *)(payload ? payload_filter : supervisor_filter);
    p.len = (u16)(payload ? sizeof payload_filter / sizeof payload_filter[0]
                         : sizeof supervisor_filter / sizeof supervisor_filter[0]);
    return (int)S3(SECCOMP, 1, 0, &p);
}
static int numeric_caps_zero(void) {
    struct capheader h = {0x20080522, 0};
    struct capdata d[2] = {{0}};
    if (S2(CAPGET, &h, d) < 0) return 0;
    for (int j = 0; j < 2; j++)
        if (d[j].effective || d[j].permitted || d[j].inheritable) return 0;
    for (int c = 0; c <= 40; c++)
        if (S2(PRCTL, PR_CAPBSET_READ, c) != 0) return 0;
    return 1;
}
static int rlimit_locked(int which, u64 value) {
    struct rlimit r = {value, value}, observed = {0};
    return S2(SETRLIMIT, which, &r) == 0 &&
           S2(GETRLIMIT, which, &observed) == 0 &&
           observed.soft == value && observed.hard == value ? 0 : -1;
}
static int private_root(int channel) {
    /* The proc observation is from this new PID namespace, never the
     * inherited Apptainer proc mount. Remove it before executing any payload:
     * even a private proc could expose trusted I/J argv/authentication memory. */
    long a = S5(MOUNT, 0, "/", 0, MS_REC | MS_PRIVATE, 0);
    if (a) return fail(channel, "mount-private-propagation", a);
    long b = S3(MKDIRAT, AT_FDCWD, "/tmp/iv1-root", 0700);
    if (b) return fail(channel, "fresh-root-directory", b);
    long c = S5(MOUNT, "tmpfs", "/tmp/iv1-root", "tmpfs", MS_NOSUID | MS_NODEV,
                "size=1048576,nr_inodes=64,mode=0700");
    if (c) return fail(channel, "fresh-tmpfs-root", c);
    long d = S3(MKDIRAT, AT_FDCWD, "/tmp/iv1-root/proc", 0700);
    if (d) return fail(channel, "fresh-proc-directory", d);
    long e = S5(MOUNT, "proc", "/tmp/iv1-root/proc", "proc",
                MS_NOSUID | MS_NODEV | MS_NOEXEC, 0);
    if (e) return fail(channel, "fresh-pidns-proc-mount", e);
    char status[8192], ns[256], own[256];
    if (read_file("/tmp/iv1-root/proc/self/status", status, sizeof status) < 0 ||
        !field(status, "Pid:\t") || !field(status, "PPid:\t"))
        return fail(channel, "private-proc-status", -1);
    long pid = decimal(field(status, "Pid:\t")), ppid = decimal(field(status, "PPid:\t"));
    if (pid != 1 || ppid != 0 ||
        ns_id("/tmp/iv1-root/proc/self/ns/pid", ns) < 0 ||
        ns_id("/proc/self/ns/pid", own) < 0 || !eq(ns, own))
        return fail(channel, "private-proc-identity", pid);
    if (emit(channel, CONTEXT, ns, 20, pid, ppid, -1) < 0) return -1;
    struct frame first = make(ROOT, "fresh-private-proc");
    first.v[1] = a; first.v[2] = b; first.v[3] = c; first.v[4] = d;
    first.v[5] = e; first.v[6] = S0(GETPID); first.v[7] = pid;
    if (send_frame(channel, &first, -1) < 0) return -1;
    long u = S2(UMOUNT2, "/tmp/iv1-root/proc", 0);
    long r = S3(UNLINKAT, AT_FDCWD, "/tmp/iv1-root/proc", 0x200);
    long tmp = S3(MKDIRAT, AT_FDCWD, "/tmp/iv1-root/tmp", 0700);
    if (u || r || tmp) return fail(channel, "private-proc-remove-and-tmp", u ? u : (r ? r : tmp));
    long ch = S1(CHDIR, "/tmp/iv1-root"), root = S1(CHROOT, "."), cwd = S1(CHDIR, "/");
    if (ch || root || cwd) return fail(channel, "private-chroot", ch ? ch : (root ? root : cwd));
    long probe = S4(OPENAT, AT_FDCWD, "/probe", O_RDONLY | O_NOFOLLOW, 0);
    long proc = S4(OPENAT, AT_FDCWD, "/proc", O_RDONLY | O_NOFOLLOW, 0);
    if (probe >= 0) S1(CLOSE, probe);
    if (proc >= 0) S1(CLOSE, proc);
    struct frame last = make(ROOT, "private-empty-root");
    last.v[1] = u; last.v[2] = r; last.v[3] = ch; last.v[4] = root;
    last.v[5] = cwd; last.v[6] = probe; last.v[7] = proc;
    if (send_frame(channel, &last, -1) < 0) return -1;
    return probe == -2 && proc == -2 ? 0 : -1;
}
static u32 cpu_work(void) {
    u32 value = 1;
    for (u32 i = 0; i < CPU_ITERATIONS; i++)
        value = value * 1664525U + 1013904223U;
    __asm__ volatile("" : "+r"(value));
    return value;
}
static u32 cpu_reference(void) {
    u32 count = CPU_ITERATIONS, mult = 1664525U, plus = 1013904223U;
    u32 acc_mult = 1, acc_plus = 0;
    while (count) {
        if (count & 1U) { acc_mult *= mult; acc_plus = acc_plus * mult + plus; }
        plus *= mult + 1U; mult *= mult; count >>= 1;
    }
    return acc_mult + acc_plus;
}
static long payload_fd_mask(void) {
    /* Observe inherited FDs before any payload-side cleanup. In particular,
     * fd31 must be absent because J/exec closed it, not because P erased it. */
    long mask = 0;
    for (int fd = 3; fd < 64; fd++)
        if (S3(FCNTL, fd, 1, 0) != -9) mask |= 1L << (fd - 3);
    return mask;
}
static int payload(int which) {
    /* Exec-reset address space: no C/factory nonce, host argv, control/key FD,
     * answer/comparator, writable host root or /proc survives into this mode.
     * This mode is a fixed native fixture, never a runner for supplied code. */
    role = P; seq = 0; case_index = which;
    trace = supervisor = -1;
    long fdmask = payload_fd_mask();
    if (fdmask) {
        /* Retain the original nonzero observation before failing closed.
         * Unmeasured fields stay zero, never a fabricated successful probe.
         * Do not close a leaked fd and then reset this failure mask. */
        struct frame leaked = make(PAYLOAD_RESULT, case_names[which]);
        leaked.v[2] = fdmask;
        (void)write_all(1, &leaked, sizeof leaked);
        return 1;
    }
    struct rlimit n = {0};
    if (S0(GETPID) != 3 || S0(GETPPID) != 2 || S0(GETUID) <= 0 ||
        S1(PRCTL, PR_GET_NO_NEW_PRIVS) != 1 || !numeric_caps_zero() ||
        S2(PRCTL, PR_SET_DUMPABLE, 0) < 0 ||
        S2(GETRLIMIT, RLIMIT_NPROC, &n) < 0 || n.soft != 32 || n.hard != 32 ||
        install_filter(1) < 0) return 1;
    char input[8] = {0};
    if (S3(RD, 0, input, sizeof input) != 8 || !eq(input, "fixture")) return 1;
    long missing = 0;
    const char *forbidden[] = {"/home", "/scratch", "/proc", "/probe"};
    for (int i = 0; i < 4; i++) {
        long fd = S4(OPENAT, AT_FDCWD, forbidden[i], O_RDONLY | O_NOFOLLOW, 0);
        if (fd == -2) missing |= 1L << i;
        else { if (fd >= 0) S1(CLOSE, fd); return 1; }
    }
    long network = S3(SOCKET, 2, 1, 0);
    long absent = S4(OPENAT, AT_FDCWD, "/tmp/case-marker", O_RDONLY | O_NOFOLLOW, 0);
    if (absent >= 0) { S1(CLOSE, absent); return 1; }
    long marker = S4(OPENAT, AT_FDCWD, "/tmp/case-marker",
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (marker < 3 || write_all((int)marker, case_names[which], len(case_names[which])) < 0)
        return 1;
    S1(CLOSE, marker);
    u32 value = 0;
    if (which == 2) {
        /* One bounded descendant demonstrates fork inheritance/reap, not N
         * exhaustion. No claim that the P8 field result validates N=32. */
        u64 cpu_begin = now();
        if (!cpu_begin) return 1;
        u64 cpu_until = cpu_begin + CPU_SERVICE_BUDGET_NS;
        int childfd = -1, status = -1;
        long child = S5(CLONE, CLONE_PIDFD | SIGCHLD, 0, &childfd, 0, 0);
        if (child == 0) { (void)cpu_work(); end(0); }
        if (child < 0 || wait_child((int)child, &status, cpu_until) ||
            status || !exited(childfd)) return 1;
        S1(CLOSE, childfd);
        value = cpu_work();
        if (!now() || now() >= cpu_until) return 1;
    }
    struct frame result = make(PAYLOAD_RESULT, case_names[which]);
    result.v[1] = value; result.v[2] = fdmask; result.v[3] = missing;
    result.v[4] = network; result.v[5] = absent; result.v[6] = (long)n.hard;
    result.v[7] = S1(PRCTL, PR_GET_NO_NEW_PRIVS);
    if (fdmask || missing != 15 || network != -1 || absent != -2 || result.v[7] != 1)
        return 1;
    return write_all(1, &result, sizeof result) < 0;
}
static int receive_internal(int fd, struct frame *f, int *passed, int event, u64 until) {
    int rc = recv_frame(fd, f, passed, until);
    if (rc < 0 || *passed >= 0 || f->v[0] != case_index || f->event != (u32)event)
        return -1;
    return 0;
}
static int judge_fds(int one, int two) {
    if (one < 3 || one >= 64 || two < 3 || two >= 64) return -1;
    for (int fd = 3; fd < 64; fd++)
        if (fd != one && fd != two && fd != 63 && fd != 31) S1(CLOSE, fd);
    return (int)S3(CLOSE_RANGE, 64, 0xffffffffU, 0);
}
static int judge_role(int channel, int parentfd, int nullfd) {
    role = J; seq = 0; trace = supervisor = -1;
    if (parent_guard(parentfd) < 0 || S0(GETPID) != 2 || !numeric_caps_zero() ||
        S1(PRCTL, PR_GET_NO_NEW_PRIVS) != 1 || exited(parentfd))
        return fail(channel, "judge-inherited-policy", -1);
    if (emit(channel, JUDGE_READY, case_names[case_index], S0(GETPID), S0(GETUID), 32, -1) < 0)
        return 1;
    struct frame cmd;
    int extra = -1;
    if (receive_internal(channel, &cmd, &extra, START, setup_end) < 0) return 1;
    int in[2] = {-1,-1}, out[2] = {-1,-1}, gate[2] = {-1,-1}, childfd = -1;
    if (S2(PIPE2, in, O_CLOEXEC | SOCK_NONBLOCK) < 0 ||
        S2(PIPE2, out, O_CLOEXEC | SOCK_NONBLOCK) < 0 || socket_pair(gate) < 0) return 1;
    if (write_all(in[1], "fixture", 8) < 0) return 1;
    S1(CLOSE, in[1]);
    long self = S2(PIDFD_OPEN, S0(GETPID), 0);
    long child = S5(CLONE, CLONE_PIDFD | SIGCHLD, 0, &childfd, 0, 0);
    if (child == 0) {
        if (parent_guard((int)self) < 0 || S2(DUP2, in[0], 0) < 0 ||
            S2(DUP2, out[1], 1) < 0 || S2(DUP2, nullfd, 2) < 0 ||
            judge_fds(gate[1], (int)self) < 0) end(120);
        /* This is still a trusted, dumpable pre-exec child. C and W must bind
         * its live pidfd/ancestry/namespaces before any payload instruction.
         * No CPU delay or delayed wait4 is substituted for the release ACK. */
        struct frame permit; int received = -1;
        if (receive_internal(gate[1], &permit, &received, RELEASE, service_end) < 0 ||
            permit.role != J || close_except(63, -1) < 0) end(120);
        char *argv[] = {"fixture", "--payload", (char *)case_names[case_index], NIL};
        char *empty[] = {NIL};
        S5(EXECVEAT, 63, "", argv, empty, AT_EMPTY_PATH);
        end(121);
    }
    S1(CLOSE, self); S1(CLOSE, in[0]); S1(CLOSE, out[1]); S1(CLOSE, gate[1]);
    if (child != 3 || childfd < 0) return fail(channel, "payload-clone", child);
    if (emit(channel, PAYLOAD_FD, "payload", child, 0, 0, childfd) < 0) return 1;
    struct frame released; int releasefd = -1;
    if (receive_internal(channel, &released, &releasefd, RELEASE, service_end) < 0)
        return fail(channel, "payload-identity-ACK-not-received", -1);
    u64 fixture_end = (u64)released.v[1], current = now();
    if (!current || released.v[1] <= 0 || fixture_end <= current || fixture_end > service_end ||
        (case_index == 2 && fixture_end > current + CPU_SERVICE_BUDGET_NS))
        return fail(channel, "fixed-fixture-service-budget", -1);
    released = make(RELEASE, "C-and-W-identity-bound");
    if (send_frame(gate[0], &released, -1) < 0) return 1;
    S1(CLOSE, gate[0]);
    struct frame result;
    int status = -1, ok = 0;
    if (ready(out[0], POLLIN, fixture_end) >= 0 &&
        S3(RD, out[0], &result, sizeof result) == sizeof result &&
        result.magic == MAGIC && result.version == VERSION && result.role == P &&
        result.event == PAYLOAD_RESULT && result.v[0] == case_index &&
        result.seq == 1 && result.ns > 0 && eq(result.text, case_names[case_index])) {
        if (send_frame(channel, &result, -1) == 0) ok = 1;
    }
    if (!ok && !exited(childfd)) signal_fd(childfd, SIGKILL);
    int reaped = wait_child((int)child, &status, deadline);
    char extra_byte;
    long tail = S3(RD, out[0], &extra_byte, 1);
    S1(CLOSE, out[0]);
    if (emit(channel, FD_AUDIT, "payload-stream-eof", reaped, status, tail, -1) < 0) ok = 0;
    S1(CLOSE, childfd);
    return ok && reaped == 0 && status == 0 && tail == 0 ? 0 : 1;
}
static int init_role(int channel, int parentfd, long uid, long gid) {
    role = I; seq = 0; trace = supervisor = -1;
    if (close_except(channel, parentfd) < 0 || parent_guard(parentfd) < 0)
        return fail(channel, "init-parent-fds", -1);
    struct frame cmd;
    int extra = -1;
    if (receive_internal(channel, &cmd, &extra, MAP, setup_end) < 0 ||
        S0(GETPID) != 1 || S0(GETPPID) != 0 || S0(GETUID) != uid ||
        S0(GETGID) != gid || uid <= 0 || !only_thread() || context(channel))
        return fail(channel, "init-map-context", -1);
    /* Exec target is the bound new helper, held CLOEXEC at one fixed fd.
     * chroot removes all host/control mounts before credentials are dropped. */
    long elf = S4(OPENAT, AT_FDCWD, "/probe/helper", O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    long nullfd = S4(OPENAT, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
    if (elf < 0 || nullfd < 0 || S2(DUP2, elf, 63) < 0 ||
        S3(FCNTL, 63, 2, 1) < 0) return fail(channel, "payload-fixed-exec-fd", -1);
    if (elf != 63) S1(CLOSE, elf);
    struct rlimit n = {32,32}, larger = {33,33}, observed = {0};
    long lowered = S2(SETRLIMIT, RLIMIT_NPROC, &n);
    long raised = S2(SETRLIMIT, RLIMIT_NPROC, &larger);
    if (S2(GETRLIMIT, RLIMIT_NPROC, &observed) < 0) return 1;
    struct frame lim = make(LIMIT, "private-I-J-payload-nproc");
    lim.v[1] = lowered; lim.v[2] = raised;
    lim.v[3] = (long)observed.soft; lim.v[4] = (long)observed.hard;
    lim.v[5] = 64; lim.v[6] = 268435456; lim.v[7] = 5;
    if (send_frame(channel, &lim, -1) < 0 || lowered || raised != -1 ||
        observed.soft != 32 || observed.hard != 32 ||
        rlimit_locked(RLIMIT_NOFILE, 64) || rlimit_locked(RLIMIT_CORE, 0) ||
        rlimit_locked(RLIMIT_FSIZE, 4096) || rlimit_locked(RLIMIT_AS, 268435456) ||
        rlimit_locked(RLIMIT_CPU, 5) || private_root(channel) != 0)
        return fail(channel, "private-limits-root", -1);
    /* Descriptor31 is a deliberate fixed harmless sentinel, not a host key.
     * Its absence after exec is observed with all fd3..63, not assumed. */
    if (S2(DUP2, nullfd, 31) < 0 ||
        emit(channel, FD_SENTINEL, "null-sentinel-fd31", 31, 0, 0, -1) < 0 ||
        drop_caps() < 0 || S2(PRCTL, PR_SET_DUMPABLE, 1) < 0 ||
        S2(PRCTL, PR_SET_NO_NEW_PRIVS, 1) < 0 || parent_guard(parentfd) < 0 ||
        !numeric_caps_zero()) return fail(channel, "drop-nnp", -1);
    struct capheader cap_header = {0x20080522, 0};
    struct capdata caps[2] = {{0}};
    if (S2(CAPGET, &cap_header, caps) < 0) return fail(channel, "post-drop-capget", -1);
    struct frame cap_row = make(CONTEXT, "post-drop-caps");
    cap_row.v[1] = caps[0].effective; cap_row.v[2] = caps[0].permitted;
    cap_row.v[3] = caps[0].inheritable; cap_row.v[4] = caps[1].effective;
    cap_row.v[5] = caps[1].permitted; cap_row.v[6] = caps[1].inheritable;
    cap_row.v[7] = S1(PRCTL, PR_GET_NO_NEW_PRIVS);
    if (send_frame(channel, &cap_row, -1) < 0) return 1;
    int pair[2] = {-1,-1}, judgefd = -1;
    long self = S2(PIDFD_OPEN, S0(GETPID), 0);
    if (self < 0 || socket_pair(pair) < 0 || install_filter(0) < 0)
        return fail(channel, "init-supervisor-allowlist", -1);
    if (emit(channel, FILTER, "supervisor-allowlist", sizeof supervisor_filter / sizeof supervisor_filter[0],
             0, 0, -1) < 0) return 1;
    long child = S5(CLONE, CLONE_PIDFD | SIGCHLD, 0, &judgefd, 0, 0);
    if (child == 0) {
        if (S2(DUP2, nullfd, 0) < 0 || S2(DUP2, nullfd, 1) < 0 ||
            S2(DUP2, nullfd, 2) < 0 || judge_fds(pair[1], (int)self) < 0) end(120);
        end(judge_role(pair[1], (int)self, 2));
    }
    S1(CLOSE, self); S1(CLOSE, pair[1]); S1(CLOSE, 63); S1(CLOSE, 31); S1(CLOSE, nullfd);
    if (child != 2 || judgefd < 0) return fail(channel, "judge-clone", child);
    if (emit(channel, JUDGE_FD, "judge", child, uid, gid, judgefd) < 0) return 1;
    struct frame row;
    if (receive_internal(pair[0], &row, &extra, JUDGE_READY, setup_end) < 0 ||
        send_frame(channel, &row, -1) < 0) return fail(channel, "judge-ready", -1);
    struct frame armed = make(ARMED, case_names[case_index]);
    armed.v[1] = S1(PRCTL, PR_GET_NO_NEW_PRIVS); armed.v[2] = 0;
    armed.v[3] = numeric_caps_zero(); armed.v[4] = child;
    if (send_frame(channel, &armed, -1) < 0 ||
        receive_internal(channel, &cmd, &extra, START, setup_end) < 0 ||
        send_frame(pair[0], &cmd, -1) < 0) return 1;
    int eof = 0, good = 1, status = -1, payload_released = 0;
    for (;;) {
        struct pollfd channels[2] = {{pair[0], POLLIN, 0}, {channel, POLLIN, 0}};
        if (!now() || now() >= deadline || S3(POLL, channels, 2, 5) < 0) break;
        if (channels[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            extra = -1;
            if (payload_released || receive_internal(channel, &cmd, &extra, RELEASE, service_end) < 0 ||
                cmd.role != C || send_frame(pair[0], &cmd, -1) < 0) { good = 0; break; }
            payload_released = 1;
        }
        if (!(channels[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        extra = -1;
        int rc = recv_frame(pair[0], &row, &extra, deadline);
        if (rc < 0) { eof = rc == -32; break; }
        if ((row.role != J && row.role != P) || row.v[0] != case_index ||
            send_frame(channel, &row, extra) < 0) good = 0;
        if (extra >= 0) S1(CLOSE, extra);
        if (!good || row.event == FAILED) break;
    }
    if (!eof && !exited(judgefd)) signal_fd(judgefd, SIGKILL);
    int rc = wait_child((int)child, &status, deadline);
    int orphan_status = -1;
    long no_children = S4(WAIT4, -1, &orphan_status, WNOHANG, 0);
    struct frame reaped = make(JUDGE_REAP, "judge-and-all-descendants");
    reaped.v[1] = rc; reaped.v[2] = status; reaped.v[3] = no_children;
    if (send_frame(channel, &reaped, -1) < 0) good = 0;
    S1(CLOSE, judgefd); S1(CLOSE, pair[0]);
    return good && eof && rc == 0 && status == 0 && no_children == -10 ? 0 : 1;
}
static int factory(const char *socket, const char *nonce, int index) {
    role = A; seq = 0; case_index = index; trace = supervisor = -1;
    if (S3(CLOSE_RANGE, 3, 0xffffffffU, 0) < 0 || !only_thread()) return 1;
    int control = connect_path(socket);
    if (control < 0) return 1;
    struct ucred server = {-1,0xffffffffU,0xffffffffU};
    u32 size = sizeof server;
    int controllerfd = -1, extra = -1;
    if (S5(GETSOCKOPT, control, SOL_SOCKET, SO_PEERCRED, &server, &size) < 0 ||
        size != sizeof server || server.uid != (u32)S0(GETUID) ||
        server.gid != (u32)S0(GETGID)) return fail(control, "factory-peercred", -1);
    size = sizeof controllerfd;
    if (S5(GETSOCKOPT, control, SOL_SOCKET, SO_PEERPIDFD, &controllerfd, &size) < 0 ||
        size != sizeof controllerfd || controllerfd < 0 || exited(controllerfd))
        return fail(control, "factory-peerpidfd", -1);
    if (emit(control, HELLO, nonce, S0(GETUID), S0(GETGID), S0(GETPID), -1) < 0) return 1;
    struct frame f;
    u64 initial = now() + SETUP_NS;
    if (recv_frame(control, &f, &extra, initial) < 0 || extra >= 0 ||
        f.role != C || f.event != AUTH || !eq(f.text, nonce) ||
        f.v[0] != index || f.v[1] <= 0 || f.v[2] <= 0 || f.v[3] <= 0)
        return fail(control, "factory-auth-deadlines", -1);
    deadline = (u64)f.v[1]; setup_end = (u64)f.v[2]; service_end = (u64)f.v[3];
    if (deadline > now() + CASE_TOTAL_NS || setup_end >= service_end ||
        service_end >= deadline || now() >= setup_end) return 1;
    if (emit(control, FACTORY_AUTH, nonce, server.pid, server.uid, server.gid, -1) < 0 ||
        context(control)) return 1;
    int pair[2] = {-1,-1}, initfd = -1;
    long self = S2(PIDFD_OPEN, S0(GETPID), 0);
    if (self < 0 || socket_pair(pair) < 0) return 1;
    long uid = S0(GETUID), gid = S0(GETGID);
    long child = S5(CLONE, CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET |
                   CLONE_PIDFD | SIGCHLD, 0, &initfd, 0, 0);
    if (child == 0) end(init_role(pair[1], (int)self, uid, gid));
    S1(CLOSE, self); S1(CLOSE, pair[1]);
    if (child < 0) return fail(control, "case-user-pid-mount-net-clone", child);
    int good = 1, eof = 0, status = -1, started = 0, released = 0;
    if (emit(control, CREATED, "init", child, uid, gid, initfd) < 0 ||
        receive_internal(control, &f, &extra, MAP, setup_end) < 0 ||
        mapping(control, child, uid, gid) < 0) good = 0;
    if (good) { f = make(MAP, "mapped"); if (send_frame(pair[0], &f, -1) < 0) good = 0; }
    while (good && now() < deadline && !exited(controllerfd)) {
        struct pollfd ps[2] = {{pair[0],POLLIN,0},{control,POLLIN,0}};
        if (S3(POLL, ps, 2, 5) < 0) { good = 0; break; }
        if (ps[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            extra = -1;
            int received = recv_frame(control, &f, &extra, started ? service_end : setup_end);
            if (received < 0 || extra >= 0 || f.role != C || f.v[0] != index ||
                (!started ? f.event != START : (released || f.event != RELEASE)) ||
                send_frame(pair[0], &f, -1) < 0) { good = 0; break; }
            if (!started) started = 1; else released = 1;
        }
        if (ps[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            extra = -1;
            int rc = recv_frame(pair[0], &f, &extra, deadline);
            if (rc < 0) { eof = rc == -32; break; }
            if (f.v[0] != index || f.role < I || f.role > P ||
                send_frame(control, &f, extra) < 0) good = 0;
            if (extra >= 0) S1(CLOSE, extra);
            if (f.event == FAILED) good = 0;
        }
    }
    if (!eof && !exited(initfd)) signal_fd(initfd, SIGKILL);
    int rc = wait_child((int)child, &status, deadline);
    if (emit(control, INIT_REAP, "init", rc, status, eof, -1) < 0) good = 0;
    S1(CLOSE, initfd); S1(CLOSE, pair[0]); S1(CLOSE, controllerfd); S1(CLOSE, control);
    return good && eof && rc == 0 && status == 0 ? 0 : 1;
}
static long launch(const char *runtime, const char *image, const char *helper, const char *socket,
                   const char *log, int index, char **env, int *pidfd,
                   int frontend_file, const struct statx *frontend_identity) {
    char binding1[2048], binding2[2048];
    copy(binding1, sizeof binding1, helper);
    cat(binding1, sizeof binding1, ":/probe/helper:ro");
    copy(binding2, sizeof binding2, socket);
    cat(binding2, sizeof binding2, ":/probe/control.sock:ro");
    char *argv[] = {(char *)runtime,
                    "exec",
                    "--containall",
                    "--cleanenv",
                    "--no-home",
                    "--no-eval",
                    "--userns",
                    "--no-mount",
                    "home,cwd,hostfs,bind-paths,/home,/scratch,/shares,/apps",
                    "--net",
                    "--network",
                    "none",
                    "--drop-caps",
                    "ALL",
                    "--pwd",
                    "/tmp",
                    "--bind",
                    binding1,
                    "--bind",
                    binding2,
                    (char *)image,
                    "/probe/helper",
                    "--factory",
                    "/probe/control.sock",
                    (char *)case_nonce,
                    (char *)case_names[index],
                    NIL};
    int pipes[2] = {-1, -1};
    log_output = create_file(log);
    if (log_output < 0 || S2(PIPE2, pipes, O_CLOEXEC) < 0)
        return -1;
    log_read = pipes[0];
    if (S3(FCNTL, log_read, 4, SOCK_NONBLOCK) < 0) {
        S1(CLOSE, pipes[1]);
        return -1;
    }
    long self = S2(PIDFD_OPEN, S0(GETPID), 0);
    if (self < 0) {
        S1(CLOSE, pipes[1]);
        return self;
    }
    long child = S5(CLONE, CLONE_PIDFD | SIGCHLD, 0, pidfd, 0, 0);
    if (child == 0) {
        if (parent_guard((int)self) < 0 || S2(PRCTL, PR_SET_NO_NEW_PRIVS, 1) < 0)
            end(120);
        struct statx held, named;
        memset(&held, 0, sizeof held);
        if (S5(STATX, frontend_file, "", 0x1000, 0x7ff, &held) < 0 || (held.mask & 0x1ff) != 0x1ff ||
            stat_path(runtime, &named) || !same_frontend_stat(&held, frontend_identity) ||
            !same_frontend_stat(&held, &named))
            end(120);
        long in = S4(OPENAT, AT_FDCWD, "/dev/null", O_RDONLY, 0);
        if (in < 0)
            end(120);
        S2(DUP2, in, 0);
        S2(DUP2, pipes[1], 1);
        S2(DUP2, pipes[1], 2);
        if (S3(CLOSE_RANGE, 3, 0xffffffffU, 0) < 0)
            end(120);
        S3(EXECVE, runtime, argv, env);
        end(121);
    }
    S1(CLOSE, self);
    S1(CLOSE, pipes[1]);
    return child;
}
static int all_reaped(u64 until) {
    int status = -1;
    for (;;) {
        drain_log();
        long p = S4(WAIT4, -1, &status, WNOHANG, 0);
        if (p == -10)
            return 1;
        if (p > 0) {
            if (p == runtime_expected_pid)
                runtime_reaped = 1;
            if (status != 0)
                outer_wait_error = 1;
            struct frame f = make(OUTER_REAP, "owned-descendant");
            f.v[1] = p;
            f.v[2] = status;
            journal(&f);
            continue;
        }
        if (p < 0 && p != -4)
            return 0;
        if (!now() || now() >= until)
            return 0;
        S3(POLL, 0, 0, 5);
    }
}

static int host_command(int action, int index, u64 until) {
    struct frame f; int extra = -1;
    int rc = recv_frame(supervisor, &f, &extra, until);
    if (extra >= 0) S1(CLOSE, extra);
    if (rc < 0 || extra >= 0 || f.role != H || f.ns != 0 ||
        f.seq != supervisor_seq + 1 || !eq(f.text, worker_nonce)) return -1;
    for (int j = 2; j < 8; j++) if (f.v[j]) return -1;
    supervisor_seq = f.seq;
    if (f.event == STOP && f.v[0] == 0 && f.v[1] == 0) return 1;
    return f.event == (u32)action && f.v[0] == index && f.v[1] == index ? 0 : -1;
}
static int controller_case(const char *runtime, const char *image, const char *helper,
                           const char *root, char **env) {
    u64 begin = now();
    if (!begin || begin + CASE_TOTAL_NS > worker_end) return 1;
    deadline = begin + CASE_TOTAL_NS; setup_end = begin + SETUP_NS;
    service_end = begin + SETUP_NS + SERVICE_NS;
    journal_error = log_error = runtime_reaped = outer_wait_error = 0;
    runtime_expected_pid = -1; log_bytes = 0; log_read = log_output = -1;
    struct frame prep = make(PREPARE, case_names[case_index]);
    prep.v[1] = (long)deadline; prep.v[2] = (long)setup_end; prep.v[3] = (long)service_end;
    if (journal(&prep)) return 1;
    char dir[2048], path[2304], socketpath[108], nonce[65];
    if (copy(dir, sizeof dir, root) < 0 || cat(dir, sizeof dir, "/") < 0 ||
        cat(dir, sizeof dir, case_names[case_index]) < 0 ||
        S3(MKDIRAT, AT_FDCWD, dir, 0700) < 0 || make_nonce(nonce) < 0) return 1;
    case_nonce = nonce;
    int failed = 1, server = -1, peer = -1, peerfd = -1, initfd = -1;
    int judgefd = -1, payloadfd = -1, runtimefd = -1, frontend_file = -1;
    int created = 0, limited = 0, armed = 0, result_seen = 0, init_reaped = 0, roots = 0;
    long runtimepid = -1;
    struct statx frontend_identity, starter_identity;
    frontend_file = frontend_fd(runtime, env, &frontend_identity);
    if (frontend_file < 0 || starter_pin(env, &starter_identity)) goto cleanup;
    if (copy(socketpath, sizeof socketpath, dir) < 0 ||
        cat(socketpath, sizeof socketpath, "/control.sock") < 0) goto cleanup;
    struct sockaddr_un addr = {AF_UNIX,{0}};
    if (copy(addr.path, sizeof addr.path, socketpath) < 0) goto cleanup;
    server = (int)S3(SOCKET, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (server < 0 || S3(BIND, server, &addr, 2 + len(socketpath) + 1) < 0 ||
        S2(CHMOD, socketpath, 0600) < 0 || S2(LISTEN, server, 1) < 0) goto cleanup;
    copy(path, sizeof path, dir); cat(path, sizeof path, "/runtime.log");
    runtimepid = launch(runtime, image, helper, socketpath, path, case_index, env,
                        &runtimefd, frontend_file, &frontend_identity);
    if (runtimepid < 0) goto cleanup;
    runtime_expected_pid = (int)runtimepid;
    if (observe_frontend_exec((int)runtimepid, runtimefd, &frontend_identity,
                              &starter_identity, setup_end) < 0) goto cleanup;
    S1(CLOSE, frontend_file); frontend_file = -1;
    if (ready(server, POLLIN, setup_end) < 0) goto cleanup;
    peer = (int)S4(ACCEPT4, server, 0, 0, SOCK_CLOEXEC | SOCK_NONBLOCK);
    struct ucred cred = {-1,0xffffffffU,0xffffffffU}; u32 size = sizeof cred;
    if (peer < 0 || S5(GETSOCKOPT, peer, SOL_SOCKET, SO_PEERCRED, &cred, &size) < 0 ||
        size != sizeof cred || cred.uid != (u32)S0(GETUID) || cred.gid != (u32)S0(GETGID))
        goto cleanup;
    size = sizeof peerfd;
    if (S5(GETSOCKOPT, peer, SOL_SOCKET, SO_PEERPIDFD, &peerfd, &size) < 0 ||
        size != sizeof peerfd || fd_pid(peerfd) != cred.pid || exited(peerfd) ||
        !same_executable(cred.pid, helper) || !descendant(cred.pid, (int)runtimepid) ||
        !same_cgroup(cred.pid)) goto cleanup;
    struct frame binding = make(PEER, "factory-exe-cgroup-pidfd");
    binding.v[1] = cred.pid; binding.v[2] = cred.uid; binding.v[3] = cred.gid;
    binding.v[4] = runtimepid; binding.v[5] = fd_pid(peerfd);
    if (journal(&binding)) goto cleanup;
    struct frame f; int extra = -1;
    if (recv_frame(peer, &f, &extra, setup_end) < 0 || extra >= 0 || f.role != A ||
        f.event != HELLO || f.v[0] != case_index || f.seq != 1 || !eq(f.text, nonce))
        goto cleanup;
    if (journal(&f)) goto cleanup;
    f = make(AUTH, nonce); f.v[1] = (long)deadline;
    f.v[2] = (long)setup_end; f.v[3] = (long)service_end;
    if (send_frame(peer, &f, -1) < 0) goto cleanup;
    u64 last[7] = {0}; last[A] = 1;
    int mutual = 0;
    for (;;) {
        extra = -1;
        if (recv_frame(peer, &f, &extra, armed ? deadline : setup_end) < 0) break;
        if (f.role < A || f.role > P || f.v[0] != case_index || f.seq <= last[f.role]) {
            if (extra >= 0) S1(CLOSE, extra);
            break;
        }
        last[f.role] = f.seq;
        if (f.event == CREATED && f.role == A && mutual && !created && extra >= 0) {
            initfd = extra; int pid = fd_pid(initfd);
            if (pid <= 0 || !descendant(pid, cred.pid) || !same_cgroup(pid) ||
                !distinct_namespaces(pid, cred.pid)) break;
            created = 1;
            if (record(&f, extra)) break;
            struct frame map = make(MAP, "allow-map");
            if (send_frame(peer, &map, -1) < 0) break;
        } else if (f.event == JUDGE_FD && f.role == I && created && limited && judgefd < 0 && extra >= 0) {
            judgefd = extra;
            if (!descendant(fd_pid(judgefd), fd_pid(initfd)) || !same_cgroup(fd_pid(judgefd)) ||
                record(&f, extra)) break;
        } else if (f.event == PAYLOAD_FD && f.role == J && armed && payloadfd < 0 && extra >= 0) {
            payloadfd = extra;
            if (!descendant(fd_pid(payloadfd), fd_pid(judgefd)) || !same_cgroup(fd_pid(payloadfd)) ||
                record(&f, extra)) break;
            if (host_command(PAYLOAD_ACK, case_index, service_end) != 0 ||
                exited(payloadfd) || exited(judgefd) || exited(initfd)) break;
            struct frame bound = make(PAYLOAD_BOUND, case_names[case_index]);
            bound.v[1] = fd_pid(payloadfd); bound.v[2] = fd_pid(initfd); bound.v[3] = fd_pid(judgefd);
            if (journal(&bound)) break;
            struct frame release = make(RELEASE, "C-and-W-identity-bound");
            u64 fixture_end = service_end;
            if (case_index == 2 && bound.ns + CPU_SERVICE_BUDGET_NS < fixture_end)
                fixture_end = bound.ns + CPU_SERVICE_BUDGET_NS;
            release.v[1] = (long)fixture_end;
            if (send_frame(peer, &release, -1) < 0) break;
        } else {
            if (extra >= 0) { S1(CLOSE, extra); break; }
            if (f.event == FAILED) { record(&f, -1); break; }
            if (f.event == FACTORY_AUTH && f.role == A && !mutual && !created && eq(f.text, nonce))
                mutual = 1;
            else if (f.event == LIMIT && f.role == I && created && !limited) {
                limited = f.v[1] == 0 && f.v[2] == -1 && f.v[3] == 32 && f.v[4] == 32;
                if (!limited) break;
            } else if (f.event == ROOT && f.role == I && created && !armed) {
                if (eq(f.text, "fresh-private-proc") && roots == 0 &&
                    f.v[1] == 0 && f.v[2] == 0 && f.v[3] == 0 && f.v[4] == 0 &&
                    f.v[5] == 0 && f.v[6] == 1 && f.v[7] == 1) roots = 1;
                else if (eq(f.text, "private-empty-root") && roots == 1 &&
                         f.v[1] == 0 && f.v[2] == 0 && f.v[3] == 0 && f.v[4] == 0 &&
                         f.v[5] == 0 && f.v[6] == -2 && f.v[7] == -2) roots = 2;
                else break;
            } else if (f.event == ARMED && f.role == I && limited && judgefd >= 0 && roots == 2 && !armed) {
                if (f.v[1] != 1 || f.v[2] != 0 || f.v[3] != 1 || f.v[4] != 2 ||
                    exited(initfd) || exited(judgefd) || record(&f, -1)) break;
                int command = host_command(START, case_index, setup_end);
                if (command != 0) break;
                struct frame running = make(RUNNING, case_names[case_index]);
                running.v[1] = (long)service_end;
                if (journal(&running)) break;
                struct frame start = make(START, "start-one-fixed-payload");
                if (send_frame(peer, &start, -1) < 0) break;
                armed = 1;
                continue;
            } else if (f.event == PAYLOAD_RESULT && f.role == P && armed && payloadfd >= 0 && !result_seen) {
                /* Retain failed FD/probe observations as original bytes too;
                 * reject them only after journaling/forwarding the evidence. */
                if (record(&f, -1)) break;
                u32 expected = case_index == 2 ? cpu_reference() : 0;
                if (!eq(f.text, case_names[case_index]) || f.v[1] != expected || f.v[2] != 0 ||
                    f.v[3] != 15 || f.v[4] != -1 || f.v[5] != -2 || f.v[6] != 32 || f.v[7] != 1)
                    break;
                result_seen = 1;
                continue;
            } else if (f.event == INIT_REAP && f.role == A && result_seen) {
                init_reaped = f.v[1] == 0 && f.v[2] == 0 && f.v[3] == 1;
                if (record(&f, -1)) init_reaped = 0;
                break;
            } else if ((f.event == CONTEXT && (f.role == A || f.role == I)) ||
                       (f.event == MAPPING && f.role == A && created) ||
                       (f.event == FD_SENTINEL && f.role == I) ||
                       (f.event == FILTER && f.role == I) ||
                       (f.event == JUDGE_READY && f.role == J && judgefd >= 0) ||
                       (f.event == FD_AUDIT && f.role == J && armed) ||
                       (f.event == JUDGE_REAP && f.role == I && armed)) {
            } else break;
            if (record(&f, -1)) break;
        }
    }
    failed = !created || !limited || !armed || !result_seen || !init_reaped;
cleanup:
    if (initfd >= 0 && !exited(initfd)) {
        long rc = signal_fd(initfd, SIGKILL);
        struct frame killed = make(CASE_STOP, "case-init-pidfd");
        killed.v[1] = rc; journal(&killed);
    }
    if (peer >= 0) { S1(CLOSE, peer); peer = -1; }
    if (runtimefd >= 0 && !exited(runtimefd)) {
        u64 grace = now() + 2000000000UL;
        if (grace > deadline) grace = deadline;
        ready(runtimefd, POLLIN, grace);
        if (!exited(runtimefd)) signal_fd(runtimefd, SIGTERM);
    }
    int released = all_reaped(deadline);
    if (!released && runtimefd >= 0 && !exited(runtimefd)) signal_fd(runtimefd, SIGKILL);
    /* No renewed cleanup window and no automatic case retry. */
    if (!released) released = all_reaped(deadline);
    struct frame observed = make(PIDFD_EXIT, "I-J-payload");
    observed.v[1] = initfd >= 0 && !!exited(initfd);
    observed.v[2] = judgefd >= 0 && !!exited(judgefd);
    observed.v[3] = payloadfd >= 0 && !!exited(payloadfd);
    if (journal(&observed) || !observed.v[1] || !observed.v[2] || !observed.v[3]) failed = 1;
    drain_log();
    failed = failed || !released || !runtime_reaped || outer_wait_error || journal_error ||
             log_error || log_read >= 0 || !now() || now() >= deadline;
    struct frame finish = make(CASE_FINISH, case_names[case_index]);
    finish.v[1] = released; finish.v[2] = failed; finish.v[3] = S0(GETPID);
    finish.v[4] = runtimepid;
    if (journal(&finish)) failed = 1;
    int fds[] = {server, peer, peerfd, initfd, judgefd, payloadfd, runtimefd, frontend_file};
    for (usize j = 0; j < sizeof fds / sizeof fds[0]; j++) if (fds[j] >= 0) S1(CLOSE, fds[j]);
    if (log_read >= 0) S1(CLOSE, log_read);
    log_read = -1;
    if (log_output >= 0) { if (S1(FSYNC, log_output) < 0) failed = 1; S1(CLOSE, log_output); }
    log_output = -1;
    return failed;
}
static int path_ok(const char *p) {
    if (*p != '/') return 0;
    for (usize j = 0; p[j]; j++)
        if (p[j] == ':' || p[j] == ',' || p[j] == '\n' || p[j] == '\r' ||
            (p[j] == '.' && p[j+1] == '.')) return 0;
    return len(p) < 1800;
}
static char binding_text[4096], job_env[96];
static char *runtime_env[24];
static int binding_environment(const char *root, char **original) {
    char path[2048]; copy(path, sizeof path, root);
    if (cat(path, sizeof path, "/frontend-preexec.env") < 0) return -1;
    long fd = S4(OPENAT, AT_FDCWD, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    struct statx before, after, named;
    memset(&before, 0, sizeof before); memset(&after, 0, sizeof after);
    if (fd < 0 || S5(STATX, fd, "", AT_EMPTY_PATH, 0x7ff, &before) < 0 ||
        before.uid != (u32)S0(GETUID) || (before.mode & 0177777) != 0100600 ||
        before.size == 0 || before.size >= sizeof binding_text) return -1;
    long n = S3(RD, fd, binding_text, sizeof binding_text - 1);
    char extra;
    if (n != (long)before.size || S3(RD, fd, &extra, 1) != 0 ||
        S5(STATX, fd, "", AT_EMPTY_PATH, 0x7ff, &after) < 0 ||
        stat_path(path, &named) || !same_frontend_stat(&before, &after) ||
        !same_frontend_stat(&before, &named)) { S1(CLOSE, fd); return -1; }
    S1(CLOSE, fd);
    static const char *keys[] = {
        "WWW27_I_FRONTEND_INODE", "WWW27_I_FRONTEND_MAJOR", "WWW27_I_FRONTEND_MINOR",
        "WWW27_I_FRONTEND_BYTES", "WWW27_I_FRONTEND_MTIME", "WWW27_I_FRONTEND_CTIME",
        "WWW27_I_FRONTEND_GID", "WWW27_I_FRONTEND_MODE",
        "WWW27_I_STARTER_INODE", "WWW27_I_STARTER_MAJOR", "WWW27_I_STARTER_MINOR"};
    int seen[11] = {0}, lines = 0;
    runtime_env[0] = "PATH=/usr/bin:/bin"; runtime_env[1] = "LC_ALL=C";
    runtime_env[2] = "TZ=UTC"; runtime_env[3] = "HOME=/tmp";
    runtime_env[4] = "APPTAINER_BINDPATH="; runtime_env[5] = "APPTAINER_BIND=";
    char *line = binding_text;
    for (long at = 0; at < n; at++) {
        if (binding_text[at] != '\n') continue;
        binding_text[at] = 0;
        if (++lines > 11) return -1;
        int matched = -1;
        for (int j = 0; j < 11; j++) {
            usize k = len(keys[j]);
            if (prefix(line, keys[j]) && line[k] == '=') {
                const char *v = line + k + 1;
                if (!*v || (v[0] == '0' && v[1])) return -1;
                for (usize digit = 0; v[digit]; digit++)
                    if (v[digit] < '0' || v[digit] > '9') return -1;
                if (seen[j]++) return -1;
                matched = j; break;
            }
        }
        if (matched < 0) return -1;
        runtime_env[5 + lines] = line;
        line = binding_text + at + 1;
    }
    if (line != binding_text + n || lines != 11) return -1;
    for (int j = 0; j < 11; j++) if (seen[j] != 1) return -1;
    const char *job = env_value(original, "SLURM_JOB_ID");
    if (decimal(job) <= 0 || copy(job_env, sizeof job_env, "SLURM_JOB_ID=") < 0 ||
        cat(job_env, sizeof job_env, job) < 0) return -1;
    runtime_env[17] = job_env; runtime_env[18] = NIL;
    return 0;
}
static int controller(const char *runtime, const char *image, const char *helper,
                      const char *root, const char *socket, const char *nonce, char **env) {
    role = C; seq = 0; case_index = 0; worker_nonce = nonce;
    /* Python sends AUTH only after both pairs/host-E controllers are ready.
     * Bootstrap is independently bounded; no case or service clock renews. */
    u64 bootstrap_end = now() + SETUP_NS;
    struct statx output;
    if (stat_path(root, &output) || (output.mode & 0177777) != 0040700 ||
        output.uid != (u32)S0(GETUID) || !same_executable((int)S0(GETPID), helper)) return 77;
    char path[2048]; copy(path, sizeof path, root);
    if (cat(path, sizeof path, "/worker.trace.bin") < 0 || (trace = create_file(path)) < 0) return 77;
    supervisor = connect_path(socket);
    if (supervisor < 0) return 77;
    struct ucred cred = {-1,0xffffffffU,0xffffffffU}; u32 size = sizeof cred;
    int ownerfd = -1;
    if (S5(GETSOCKOPT, supervisor, SOL_SOCKET, SO_PEERCRED, &cred, &size) < 0 ||
        size != sizeof cred || cred.uid != (u32)S0(GETUID)) return 77;
    size = sizeof ownerfd;
    if (S5(GETSOCKOPT, supervisor, SOL_SOCKET, SO_PEERPIDFD, &ownerfd, &size) < 0 ||
        size != sizeof ownerfd || ownerfd < 0 || exited(ownerfd)) return 77;
    struct frame hello = make(HELLO, nonce);
    hello.v[1] = S0(GETPID); hello.v[2] = S0(GETUID); hello.v[3] = S0(GETGID);
    if (journal(&hello) || host_command(AUTH, 0, bootstrap_end) != 0) return 1;
    worker_end = now() + WORKER_TOTAL_NS;
    struct frame begun = make(BEGIN, nonce); begun.v[1] = (long)worker_end;
    if (journal(&begun)) return 1;
    struct frame authenticated = make(AUTHENTICATED, nonce);
    if (journal(&authenticated) || binding_environment(root, env) ||
        resources(env) || !only_thread() || S2(PRCTL, PR_SET_CHILD_SUBREAPER, 1) < 0 ||
        decimal(env_value(env, "SLURM_STEP_ID")) < 0) return 1;
    for (int index = 1; index <= 3; index++) {
        struct frame idle = make(IDLE, "worker-live-not-empty"); idle.v[1] = index;
        if (journal(&idle)) return 1;
        int command = host_command(PREPARE_CMD, index, worker_end);
        if (command != 0 || exited(ownerfd)) return 1;
        case_index = index;
        if (controller_case(runtime, image, helper, root, runtime_env)) {
            struct frame failed = make(FAILED, "case-failed-no-further-dispatch");
            failed.v[1] = -1; journal(&failed); return 1;
        }
        struct frame done = make(IDLE, "case-reaped-C-still-alive"); done.v[1] = index;
        if (journal(&done)) return 1;
        case_index = 0;
    }
    int stopped = host_command(STOP, 0, worker_end);
    if (stopped != 1 || !all_reaped(worker_end) || journal_error || log_error) return 1;
    struct frame final = make(STOPPED, "worker-drained");
    final.v[1] = 1; final.v[2] = 3;
    if (journal(&final) || S1(FSYNC, trace) < 0) return 1;
    S1(CLOSE, ownerfd); S1(CLOSE, supervisor); supervisor = -1;
    S1(CLOSE, trace); trace = -1;
    return !now() || now() >= worker_end ? 1 : 0;
}
/* N entry: the existing fixture protocol above is unchanged. The container
 * supplies stdin/stdout and a read-only runner; no key or protocol FD enters
 * the candidate. I/J/P retain the same private task and CPU/memory limits. */
static void candidate_diag(const char *stage, const char *operation, long rc, int kernel_rc) {
    char message[384] = "N_DIAG stage=", value[32];
    cat(message, sizeof message, stage); cat(message, sizeof message, " syscall=");
    cat(message, sizeof message, operation); cat(message, sizeof message, " rc=");
    number(value, rc); cat(message, sizeof message, value);
    cat(message, sizeof message, " errno=");
    number(value, kernel_rc && rc < 0 && rc >= -4095 ? -rc : 0);
    cat(message, sizeof message, value); cat(message, sizeof message, " pid=");
    number(value, S0(GETPID)); cat(message, sizeof message, value);
    cat(message, sizeof message, "\n");
    /* Best effort, one short write to the already-open diagnostic stderr. */
    (void)S3(WR, 2, message, len(message));
}
static long candidate_exact(const char *stage, const char *operation, long rc, long expected) {
    if (rc != expected) candidate_diag(stage, operation, rc, 1);
    return rc;
}
static long candidate_negative(const char *stage, const char *operation, long rc) {
    if (rc < 0) candidate_diag(stage, operation, rc, 1);
    return rc;
}
static int candidate_write_all(const char *stage, int fd, const void *p, usize n) {
    const char *s = p;
    while (n) {
        long rc = S3(WR, fd, s, n);
        if (rc == -4) continue;
        if (rc <= 0) {
            candidate_diag(stage, "write", rc, 1);
            return rc < 0 ? (int)rc : -5;
        }
        s += rc; n -= (usize)rc;
    }
    return 0;
}
static int candidate_put_file(const char *stage, const char *path, const char *value) {
    long fd = candidate_negative(stage, "openat", S4(OPENAT, AT_FDCWD, path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0));
    if (fd < 0) return (int)fd;
    int rc = candidate_write_all(stage, (int)fd, value, len(value));
    S1(CLOSE, fd); return rc;
}
static int candidate_only_thread(void) {
    char b[8192]; memset(b, 0, sizeof b);
    long fd = candidate_negative("initial-thread-status", "openat",
                                 S4(OPENAT, AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return 0;
    long n = candidate_negative("initial-thread-status", "read", S3(RD, fd, b, sizeof b - 1));
    if (n >= 0) {
        char extra;
        if ((usize)n == sizeof b - 1 && S3(RD, fd, &extra, 1) > 0) {
            candidate_diag("initial-thread-status", "check-read-bound", n, 0); n = -7;
        }
    }
    S1(CLOSE, fd);
    if (n < 0) return 0;
    b[n] = 0;
    const char *p = field(b, "Threads:\t");
    int ok = p && decimal(p) == 1;
    if (!ok) candidate_diag("initial-thread-count", "check", p ? decimal(p) : -1, 0);
    return ok;
}
static int candidate_limit(const char *stage, int which, u64 value) {
    struct rlimit r = {value, value}, observed = {0};
    if (candidate_exact(stage, "setrlimit", S2(SETRLIMIT, which, &r), 0) != 0 ||
        candidate_exact(stage, "getrlimit", S2(GETRLIMIT, which, &observed), 0) != 0) return -1;
    if (observed.soft != value || observed.hard != value) {
        candidate_diag(stage, "check-soft-limit", (long)observed.soft, 0);
        candidate_diag(stage, "check-hard-limit", (long)observed.hard, 0);
        return -1;
    }
    return 0;
}
static int candidate_drop_caps(void) {
    for (int c = 0; c <= 40; c++)
        if (candidate_negative("drop-bounding-cap", "prctl", S2(PRCTL, PR_CAPBSET_DROP, c)) < 0) return -1;
    struct capheader h = {0x20080522, 0};
    struct capdata d[2] = {{0}};
    if (candidate_negative("clear-capabilities", "capset", S2(CAPSET, &h, d)) < 0 ||
        candidate_negative("clear-ambient", "prctl", S2(PRCTL, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)) < 0) return -1;
    return 0;
}
static int candidate_map(long pid, long uid, long gid) {
    char base[128] = "/proc/", n[32], path[160], value[96];
    number(n, pid); cat(base, sizeof base, n);
    const char *names[] = {"/setgroups", "/uid_map", "/gid_map"};
    for (int j = 0; j < 3; j++) {
        copy(path, sizeof path, base); cat(path, sizeof path, names[j]);
        if (!j) copy(value, sizeof value, "deny\n");
        else {
            number(n, j == 1 ? uid : gid); copy(value, sizeof value, n);
            cat(value, sizeof value, " "); cat(value, sizeof value, n); cat(value, sizeof value, " 1\n");
        }
        if (candidate_put_file(names[j], path, value) < 0) return -1;
    }
    return 0;
}
static int candidate_root(void) {
    enum { MS_RDONLY = 1, MS_REMOUNT = 32, MS_BIND = 4096 };
    if (candidate_exact("root-private", "mount", S5(MOUNT, 0, "/", 0, MS_REC | MS_PRIVATE, 0), 0) ||
        candidate_exact("root-directory", "mkdirat", S3(MKDIRAT, AT_FDCWD, "/tmp/n-root", 0700), 0) ||
        candidate_exact("root-tmpfs", "mount", S5(MOUNT, "tmpfs", "/tmp/n-root", "tmpfs", MS_NOSUID | MS_NODEV,
           "size=1048576,nr_inodes=64,mode=0700"), 0)) return -1;
    const char *dirs[] = {"usr", "lib", "lib64", "bin", "tmp"};
    for (int j = 0; j < 5; j++) {
        char target[128] = "/tmp/n-root/", src[64] = "/";
        cat(target, sizeof target, dirs[j]); cat(src, sizeof src, dirs[j]);
        if (candidate_exact(dirs[j], "mkdirat", S3(MKDIRAT, AT_FDCWD, target, 0700), 0)) return -1;
        if (j == 4) continue;
        long fd = S4(OPENAT, AT_FDCWD, src, O_RDONLY, 0);
        if (fd == -2) continue;
        if (fd < 0) { candidate_diag(dirs[j], "openat", fd, 1); return -1; }
        S1(CLOSE, fd);
        if (candidate_exact(dirs[j], "mount-bind", S5(MOUNT, src, target, 0, MS_BIND | MS_REC, 0), 0) ||
            candidate_exact(dirs[j], "mount-readonly", S5(MOUNT, 0, target, 0, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, 0), 0)) return -1;
    }
    long fd = S4(OPENAT, AT_FDCWD, "/tmp/n-root/runner.py", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { candidate_diag("runner-target", "openat", fd, 1); return -1; }
    S1(CLOSE, fd);
    if (candidate_exact("runner-bind", "mount", S5(MOUNT, "/probe/candidate_runner.py", "/tmp/n-root/runner.py", 0, MS_BIND, 0), 0) ||
        /* Apptainer's user bind is nodev; nested user namespaces lock that bit. */
        candidate_exact("runner-readonly", "mount", S5(MOUNT, 0, "/tmp/n-root/runner.py", 0, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, 0), 0) ||
        candidate_exact("root-enter", "chdir", S1(CHDIR, "/tmp/n-root"), 0) ||
        candidate_exact("root-chroot", "chroot", S1(CHROOT, "."), 0) ||
        candidate_exact("root-cwd", "chdir", S1(CHDIR, "/"), 0)) return -1;
    return 0;
}
static int candidate_filter(void) {
    /* Same namespace/NPROC boundaries as the fixture; Python needs its normal
     * loader/filesystem syscalls. No new authentication mechanism is added. */
    struct filter f[128]; unsigned k = 0;
    f[k++] = (struct filter){0x20,0,0,4};
    f[k++] = (struct filter){0x15,1,0,0xc000003eU};
    f[k++] = (struct filter){0x6,0,0,0x80000000U};
    f[k++] = (struct filter){0x20,0,0,0};
    f[k++] = (struct filter){0x45,0,1,0x40000000U};
    f[k++] = (struct filter){0x6,0,0,0x80000000U};
    f[k++] = (struct filter){0x15,0,1,435};
    f[k++] = (struct filter){0x6,0,0,0x50026U};
    f[k++] = (struct filter){0x15,0,5,56};
    f[k++] = (struct filter){0x20,0,0,20};
    f[k++] = (struct filter){0x15,0,2,0};
    f[k++] = (struct filter){0x20,0,0,16};
    f[k++] = (struct filter){0x45,0,1,0xfec2e000U};
    f[k++] = (struct filter){0x6,0,0,0x50001U};
    f[k++] = (struct filter){0x20,0,0,0};
    const u32 denied[] = {41,42,43,49,50,101,160,165,166,246,248,249,250,272,298,302,303,304,308,310,311,321,323,425,426,427};
    for (unsigned j = 0; j < sizeof denied / sizeof denied[0]; j++) {
        f[k++] = (struct filter){0x15,0,1,denied[j]};
        f[k++] = (struct filter){0x6,0,0,0x50001U};
    }
    f[k++] = (struct filter){0x6,0,0,0x7fff0000U};
    struct program p = {(u16)k,f};
    return (int)S3(SECCOMP,1,0,&p);
}
static int candidate_init(void) {
    long uid = S0(GETUID), gid = S0(GETGID);
    if (uid <= 0) { candidate_diag("initial-uid", "check", uid, 0); return 77; }
    long euid = S0(GETEUID);
    if (uid != euid) { candidate_diag("initial-euid", "check", euid, 0); return 77; }
    if (!candidate_only_thread()) return 77;
    int gate[2] = {-1,-1}, initfd = -1;
    if (candidate_exact("gate-create", "pipe2", S2(PIPE2,gate,O_CLOEXEC), 0)) return 77;
    long child = candidate_negative("init-create", "clone", S5(CLONE,CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET |
                    CLONE_PIDFD | SIGCHLD,0,&initfd,0,0));
    if (child == 0) {
        S1(CLOSE,gate[1]); char byte;
        if (candidate_exact("gate-read", "read", S3(RD,gate[0],&byte,1), 1) != 1) end(77);
        S1(CLOSE,gate[0]);
        long pid = S0(GETPID);
        if (pid != 1) { candidate_diag("init-pid", "check", pid, 0); end(77); }
        if (candidate_root() || candidate_limit("limit-nproc",RLIMIT_NPROC,32) ||
            candidate_limit("limit-nofile",RLIMIT_NOFILE,64) || candidate_limit("limit-core",RLIMIT_CORE,0) ||
            candidate_limit("limit-fsize",RLIMIT_FSIZE,4096) || candidate_limit("limit-as",RLIMIT_AS,268435456) ||
            candidate_limit("limit-cpu",RLIMIT_CPU,5) || candidate_drop_caps() < 0 ||
            candidate_exact("no-new-privs", "prctl", S2(PRCTL,PR_SET_NO_NEW_PRIVS,1), 0)) end(77);
        long judge = candidate_negative("judge-create", "clone", S5(CLONE,SIGCHLD,0,0,0,0));
        if (judge == 0) {
            long payload = candidate_negative("payload-create", "clone", S5(CLONE,SIGCHLD,0,0,0,0));
            if (payload == 0) {
                if (candidate_exact("payload-fds", "close_range", S3(CLOSE_RANGE,3,0xffffffffU,0), 0) ||
                    candidate_exact("payload-filter", "seccomp", candidate_filter(), 0)) end(77);
                /* The fixed image uses update-alternatives for python3, but
                 * this private root intentionally has no /etc. Use its real
                 * versioned interpreter path, including argv[0]. */
                char *argv[] = {"/usr/bin/python3.12","-I","-S","/runner.py",NIL};
                char *env[] = {"PYTHONHASHSEED=0",NIL};
                candidate_negative("python-system", "execve", S3(EXECVE,"/usr/bin/python3.12",argv,env));
                end(127);
            }
            if (payload < 0) end(77);
            int status = -1;
            int waited = wait_child((int)payload,&status,now()+5000000000UL);
            if (waited) { candidate_diag("payload-wait", "wait_child", waited, 0); end(124); }
            end((status & 127) ? 128+(status & 127) : ((status >> 8) & 255) ? 1 : 0);
        }
        if (judge < 0) end(77);
        int status = -1;
        int waited = wait_child((int)judge,&status,now()+7000000000UL);
        if (waited) { candidate_diag("judge-wait", "wait_child", waited, 0); end(124); }
        /* PID1 exit kills every remaining descendant in this private domain. */
        end((status & 127) ? 128+(status & 127) : (status >> 8) & 255);
    }
    S1(CLOSE,gate[0]);
    if (child < 0) { S1(CLOSE,gate[1]); return 77; }
    if (candidate_map(child,uid,gid) || candidate_write_all("gate-write",gate[1],"1",1)) {
        signal_fd(initfd,SIGKILL); S1(CLOSE,gate[1]);
        int status = -1; (void)wait_child((int)child,&status,now()+2000000000UL);
        S1(CLOSE,initfd); return 77;
    }
    S1(CLOSE,gate[1]); int status = -1;
    int waited = wait_child((int)child,&status,now()+10000000000UL);
    if (waited) {
        candidate_diag("init-wait", "wait_child", waited, 0);
        signal_fd(initfd,SIGKILL); (void)wait_child((int)child,&status,now()+2000000000UL);
        S1(CLOSE,initfd);return 124;
    }
    S1(CLOSE,initfd);
    return (status & 127) ? 128+(status & 127) : (status >> 8) & 255;
}
static int mainx(int argc, char **argv, char **env) {
    /* Fixed trusted-fixture source capability. This flag grants neither I
     * acceptance nor owner permission; the W launch adapter enforces those.
     * There is no argv/env/JSON capability override. Candidate I/O uses the
     * separately gated N path; the fixture command protocol is unchanged. */
    if (!ISOLATION_RELEASE_ENABLED) return 78;
    if (argc == 2 && eq(argv[1], "--candidate-init")) return candidate_init();
    if (argc == 3 && eq(argv[1], "--payload")) {
        for (int j = 1; j <= 3; j++) if (eq(argv[2], case_names[j])) return payload(j);
        return 64;
    }
    if (S0(GETUID) <= 0 || S0(GETUID) != S0(GETEUID) || S0(GETGID) != S0(GETEGID) ||
        !active_caps_zero()) return 77;
    if (argc == 5 && eq(argv[1], "--factory") && eq(argv[2], "/probe/control.sock") &&
        len(argv[3]) == 64) {
        for (int j = 1; j <= 3; j++) if (eq(argv[4], case_names[j])) return factory(argv[2], argv[3], j);
        return 64;
    }
    if (argc != 8 || !eq(argv[1], "--controller") || len(argv[7]) != 64) return 64;
    for (int j = 2; j <= 6; j++) if (!path_ok(argv[j])) return 64;
    for (int j = 0; j < 64; j++)
        if (!((argv[7][j] >= '0' && argv[7][j] <= '9') ||
              (argv[7][j] >= 'a' && argv[7][j] <= 'f'))) return 64;
    S1(UMASK, 0077);
    /* W/C same-UID identity sampling must remain possible for trusted C/I/J.
     * Only the fixed payload lowers dumpability after the live identity ACK. */
    if (S2(PRCTL, PR_SET_DUMPABLE, 1) < 0 || S3(CLOSE_RANGE, 3, 0xffffffffU, 0) < 0) return 77;
    return controller(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], env);
}
__attribute__((used, noreturn)) void isolation_start(unsigned long *sp) {
    int argc = (int)sp[0]; char **argv = (char **)(sp + 1);
    end(mainx(argc, argv, argv + argc + 1));
}
__asm__(".global _start\n_start:\n cld\n xor %rbp,%rbp\n mov %rsp,%rdi\n and $-16,%rsp\n call "
        "isolation_start\n ud2\n");
