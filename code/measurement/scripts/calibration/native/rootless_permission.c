/* Minimal trusted permission helper, not a candidate sandbox.
 * Build: freestanding static Linux x86-64; no libc and no library-created tasks.
 * Enabled only in the independent P source chain, never by the S release.
 * No argument or environment variable enables this build.
 */
#include "rootless_permission_abi.h"
static const volatile int RELEASE_ENABLED = 1;
enum {
    C = 1,
    A = 2,
    I = 3,
    S = 4,
    MAGIC = 0x57575031,
    VERSION = 1,
    HELLO = 1,
    CREATED = 2,
    CONTEXT = 3,
    LIMIT = 4,
    ARMED = 5,
    SENTINEL_FD = 6,
    CANARY = 7,
    SENTINEL_REAP = 8,
    INIT_REAP = 9,
    FAILED = 10,
    OUTER_REAP = 11,
    RELEASED = 12,
    RESOURCE = 13,
    MAPPING = 14,
    IDENTITY = 15,
    PEER = 16,
    BEGIN = 17,
    FACTORY_AUTH = 18,
    KERNEL = 19,
    START = 20,
    MAP = 21,
    STOP = 22,
    AUTH = 23,
    TERMINATE = 24,
    DONE = 25,
    RESOURCE_DETAIL = 26,
    PIDFD_EXIT = 27,
    FRONTEND_FD = 28,
    FRONTEND_EXEC = 29
};
struct frame {
    u32 magic, version, role, event;
    u64 seq, ns;
    long v[8];
    char text[256];
};
_Static_assert(sizeof(struct frame) == 352, "fixed little-endian protocol");
static u64 seq, deadline;
static int role, trace = -1;
static int journal_error, log_error, log_read = -1, log_output = -1;
static int runtime_expected_pid = -1, runtime_reaped, outer_wait_error;
static usize journal_count, log_bytes;
static const char *case_nonce;
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
        if (now() >= until)
            return -110;
        S3(POLL, 0, 0, 5);
    }
}
static struct frame make(int event, const char *text) {
    struct frame f;
    memset(&f, 0, sizeof f);
    f.magic = MAGIC;
    f.version = VERSION;
    f.role = (u32)role;
    f.event = (u32)event;
    f.seq = ++seq;
    f.ns = now();
    if (text && copy(f.text, sizeof f.text, text) < 0)
        f.event = FAILED;
    return f;
}
static int journal(const struct frame *f) {
    if (f->event == FAILED)
        journal_error = 1;
    if (trace < 0 || journal_count++ >= 256 || write_all(trace, f, sizeof *f) < 0) {
        journal_error = 1;
        return -1;
    }
    return journal_error ? -1 : 0;
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
        f->version != VERSION || f->role < 1 || f->role > 4 || !f->seq || f->text[255]) {
        if (*passed >= 0)
            S1(CLOSE, *passed);
        *passed = -1;
        return -71;
    }
    return 0;
}
static int emit(int fd, int event, const char *name, long a, long b, long c, int passed) {
    struct frame f = make(event, name);
    f.v[0] = a;
    f.v[1] = b;
    f.v[2] = c;
    return send_frame(fd, &f, passed);
}
static int fail(int fd, const char *stage, long rc) {
    emit(fd, FAILED, stage, rc, 0, 0, -1);
    return 1;
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
    limits.v[0] = S0(GETUID);
    limits.v[1] = S0(GETGID);
    limits.v[2] = (long)r.soft;
    limits.v[3] = (long)r.hard;
    limits.v[4] = S2(GETGROUPS, 0, 0);
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
static int caps_zero(void) {
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
    const char *keys[] = {"CapAmb:\t", "CapBnd:\t"};
    for (int j = 0; j < 2; j++) {
        const char *p = field(b, keys[j]);
        if (!p)
            return 0;
        while (*p && *p != '\n') {
            if (*p != '0')
                return 0;
            p++;
        }
    }
    return 1;
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
static int install_canary(void) {
    /* arch != x86_64 or x32 -> KILL_PROCESS; getppid -> errno 123.
       Everything else is trusted-probe code, NOT a candidate allowlist. */
    struct filter f[] = {
        {0x20, 0, 0, 4},       {0x15, 1, 0, 0xc000003e},       {0x06, 0, 0, 0x80000000},
        {0x20, 0, 0, 0},       {0x45, 0, 1, 0x40000000},       {0x06, 0, 0, 0x80000000},
        {0x15, 0, 1, GETPPID}, {0x06, 0, 0, 0x00050000 | 123}, {0x06, 0, 0, 0x7fff0000}};
    struct program p = {9, f};
    return (int)S3(SECCOMP, 1, 0, &p);
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
static int sentinel(int channel, int parentfd, int negative) {
    role = S;
    seq = 0;
    trace = -1;
    if (close_except(channel, parentfd) < 0)
        return fail(channel, "sentinel-fd-closure", -1);
    if (parent_guard(parentfd) < 0)
        return fail(channel, "sentinel-parent", -1);
    struct rlimit r = {0};
    long v = S0(GETPPID);
    if (S2(GETRLIMIT, RLIMIT_NPROC, &r) < 0 || !caps_zero() ||
        S1(PRCTL, PR_GET_NO_NEW_PRIVS) != 1 || v != -123 || r.soft != 8 || r.hard != 8)
        return fail(channel, "sentinel-inheritance", v);
    if (emit(channel, CANARY, "sentinel", v, (long)r.soft, (long)r.hard, -1) < 0)
        return 1;
    if (!negative)
        return 0;
    /* Only a bounded wait. Namespace teardown or parent EOF ends this branch. */
    struct frame f;
    int got = -1;
    recv_frame(channel, &f, &got, now() + 2000000000UL);
    if (got >= 0)
        S1(CLOSE, got);
    return 1;
}
static int init_role(int channel, int parentfd, long uid, long gid, int negative) {
    role = I;
    seq = 0;
    trace = -1;
    if (close_except(channel, parentfd) < 0)
        return fail(channel, "init-fd-closure", -1);
    if (parent_guard(parentfd) < 0)
        return fail(channel, "init-early-parent", -1);
    struct frame cmd = {0};
    int fd = -1;
    u64 setup = now() + 10000000000UL;
    if (recv_frame(channel, &cmd, &fd, setup) < 0 || fd >= 0 || cmd.event != MAP)
        return fail(channel, "map-handshake", -1);
    if (S0(GETPID) != 1 || S0(GETPPID) != 0 || S0(GETUID) != uid || S0(GETGID) != gid || uid <= 0 ||
        !only_thread())
        return fail(channel, "mapped-identity", -1);
    if (context(channel))
        return 1;
    struct rlimit r = {8, 8}, larger = {9, 9}, observed = {0};
    long lowered = S2(SETRLIMIT, RLIMIT_NPROC, &r);
    if (lowered < 0)
        return fail(channel, "nproc-lower", lowered);
    long raised = S2(SETRLIMIT, RLIMIT_NPROC, &larger);
    if (S2(GETRLIMIT, RLIMIT_NPROC, &observed) < 0)
        return fail(channel, "limit-reread", -1);
    struct frame lim = make(LIMIT, "nproc-before-filter");
    lim.v[0] = lowered;
    lim.v[1] = raised;
    lim.v[2] = (long)observed.soft;
    lim.v[3] = (long)observed.hard;
    send_frame(channel, &lim, -1);
    if (lowered || raised != -1 || observed.soft != 8 || observed.hard != 8)
        return fail(channel, "nproc-lock-or-raise", raised);
    if (drop_caps() < 0 || S2(PRCTL, PR_SET_DUMPABLE, 0) < 0 ||
        S2(PRCTL, PR_SET_NO_NEW_PRIVS, 1) < 0 || parent_guard(parentfd) < 0 || !caps_zero())
        return fail(channel, "credentials-parent", -1);
    long baseline = S0(GETPPID);
    if (baseline != 0)
        return fail(channel, "canary-baseline", baseline);
    long installed = install_canary(), checked = S0(GETPPID);
    struct frame arm = make(ARMED, "init");
    arm.v[0] = baseline;
    arm.v[1] = installed;
    arm.v[2] = checked;
    arm.v[3] = S1(PRCTL, PR_GET_NO_NEW_PRIVS);
    arm.v[4] = caps_zero();
    if (send_frame(channel, &arm, -1) < 0 || installed || checked != -123 || arm.v[3] != 1 ||
        arm.v[4] != 1)
        return 1;
    if (recv_frame(channel, &cmd, &fd, setup) < 0 || fd >= 0 || cmd.event != START ||
        exited(parentfd))
        return fail(channel, "arm-ack", -1);
    int pair[2] = {-1, -1}, childfd = -1;
    long self = S2(PIDFD_OPEN, S0(GETPID), 0);
    if (self < 0 || socket_pair(pair) < 0)
        return fail(channel, "sentinel-channel", -1);
    long child = S5(CLONE, CLONE_PIDFD | SIGCHLD, 0, &childfd, 0, 0);
    if (child == 0)
        end(sentinel(pair[1], (int)self, negative));
    S1(CLOSE, pair[1]);
    S1(CLOSE, self);
    if (child < 0) {
        S1(CLOSE, pair[0]);
        return fail(channel, "sentinel-clone", child);
    }
    emit(channel, SENTINEL_FD, "sentinel", child, 0, 0, childfd);
    struct frame result = {0};
    int extra = -1;
    u64 body = now() + 2000000000UL;
    int ok = recv_frame(pair[0], &result, &extra, body) == 0 && extra < 0 && result.role == S &&
             result.event == CANARY && result.v[0] == -123;
    if (ok)
        send_frame(channel, &result, -1);
    int status = 0, reaped;
    if (!ok || negative) {
        if (!ok)
            fail(channel, "sentinel-report", -1);
        if (negative && ok) {
            recv_frame(channel, &cmd, &extra, body);
        }
        signal_fd(childfd, SIGKILL);
    }
    reaped = wait_child((int)child, &status, now() + 10000000000UL);
    emit(channel, SENTINEL_REAP, "sentinel", reaped, status, 0, -1);
    S1(CLOSE, childfd);
    S1(CLOSE, pair[0]);
    return (!negative && ok && reaped == 0 && status == 0) ? 0 : 1;
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
static int factory(const char *socket, const char *nonce, int negative) {
    role = A;
    seq = 0;
    trace = -1;
    if (S3(CLOSE_RANGE, 3, 0xffffffffU, 0) < 0 || !only_thread())
        return 1;
    int control = connect_path(socket);
    if (control < 0)
        return 1;
    u64 setup = now() + 10000000000UL;
    if (emit(control, HELLO, nonce, S0(GETUID), S0(GETGID), S0(GETPID), -1) < 0)
        return 1;
    struct frame f;
    int controllerfd = -1, extra_auth = -1;
    struct ucred server_cred = {-1, 0xffffffffU, 0xffffffffU};
    u32 server_size = sizeof server_cred;
    if (S5(GETSOCKOPT, control, SOL_SOCKET, SO_PEERCRED, &server_cred, &server_size) < 0 ||
        server_size != sizeof server_cred || server_cred.pid < 0 ||
        server_cred.uid != (u32)S0(GETUID) || server_cred.gid != (u32)S0(GETGID))
        return fail(control, "controller-peercred", -1);
    server_size = sizeof controllerfd;
    if (S5(GETSOCKOPT, control, SOL_SOCKET, SO_PEERPIDFD, &controllerfd, &server_size) < 0 ||
        server_size != sizeof controllerfd || controllerfd < 0 || exited(controllerfd))
        return fail(control, "controller-peerpidfd", -1);
    if (recv_frame(control, &f, &extra_auth, setup) < 0 || extra_auth >= 0 || f.role != C ||
        f.event != AUTH || !eq(f.text, nonce))
        return fail(control, "controller-auth", -1);
    emit(control, FACTORY_AUTH, nonce, server_cred.pid, server_cred.uid, server_cred.gid, -1);
    if (context(control))
        return 1;
    int pair[2] = {-1, -1}, initfd = -1;
    long self = S2(PIDFD_OPEN, S0(GETPID), 0);
    if (self < 0 || socket_pair(pair) < 0)
        return fail(control, "init-channel", -1);
    long uid = S0(GETUID), gid = S0(GETGID);
    long child = S5(CLONE, CLONE_NEWUSER | CLONE_NEWPID | CLONE_PIDFD | SIGCHLD, 0, &initfd, 0, 0);
    if (child == 0)
        end(init_role(pair[1], (int)self, uid, gid, negative));
    S1(CLOSE, self);
    S1(CLOSE, pair[1]);
    if (child < 0) {
        S1(CLOSE, pair[0]);
        return fail(control, "case-namespace-clone", child);
    }
    emit(control, CREATED, "init", child, uid, gid, initfd);
    int extra = -1, good = 0, status = 0, eof = 0;
    long rc = -1;
    if (recv_frame(control, &f, &extra, setup) < 0 || extra >= 0 || f.event != MAP ||
        exited(controllerfd))
        goto cleanup;
    rc = mapping(control, child, uid, gid);
    if (rc < 0) {
        fail(control, "uid-gid-mapping", rc);
        goto cleanup;
    }
    f = make(MAP, "mapped");
    if (send_frame(pair[0], &f, -1) < 0)
        goto cleanup;
    for (;;) {
        if (exited(controllerfd) || now() >= setup)
            break;
        struct pollfd p[2] = {{pair[0], POLLIN, 0}, {control, POLLIN, 0}};
        S3(POLL, p, 2, 20);
        if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (recv_frame(control, &f, &extra, setup) < 0 || extra >= 0)
                break;
            if (f.event == START) {
                if (send_frame(pair[0], &f, -1) < 0)
                    break;
                setup = now() + 2000000000UL;
            } else
                break;
        }
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            int received = recv_frame(pair[0], &f, &extra, setup);
            if (received < 0) {
                eof = received == -32;
                break;
            }
            if ((f.role != I && f.role != S) || send_frame(control, &f, extra) < 0) {
                if (extra >= 0)
                    S1(CLOSE, extra);
                break;
            }
            if (extra >= 0)
                S1(CLOSE, extra);
            if (f.event == FAILED)
                break;
        }
        /* Drain all queued I/S events through EOF even if init already exited. */
    }
cleanup:
    if (!eof && !exited(initfd))
        signal_fd(initfd, SIGKILL);
    rc = wait_child((int)child, &status, now() + 10000000000UL);
    good = eof && rc == 0 && (negative ? status == SIGKILL : status == 0);
    emit(control, INIT_REAP, "init", rc, status, good, -1);
    S1(CLOSE, initfd);
    S1(CLOSE, pair[0]);
    S1(CLOSE, controllerfd);
    S1(CLOSE, control);
    return rc == 0 && good && (negative ? status == SIGKILL : status == 0) ? 0 : 1;
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
    const char *keys[] = {"WWW27_P_FRONTEND_INODE", "WWW27_P_FRONTEND_MAJOR", "WWW27_P_FRONTEND_MINOR",
                         "WWW27_P_FRONTEND_BYTES", "WWW27_P_FRONTEND_MTIME", "WWW27_P_FRONTEND_CTIME",
                         "WWW27_P_FRONTEND_GID", "WWW27_P_FRONTEND_MODE"};
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
    f.v[0] = (long)identity->ino;
    f.v[1] = identity->dev_major;
    f.v[2] = identity->dev_minor;
    f.v[3] = identity->mode;
    f.v[4] = identity->uid;
    f.v[5] = (long)identity->size;
    f.v[6] = mtime;
    f.v[7] = ctime;
    if (journal(&f)) {
        S1(CLOSE, fd);
        return -1;
    }
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
    const char *keys[] = {"WWW27_P_STARTER_INODE", "WWW27_P_STARTER_MAJOR", "WWW27_P_STARTER_MINOR"};
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
                f.v[0] = pid;
                f.v[1] = (long)observed.ino;
                f.v[2] = observed.dev_major;
                f.v[3] = observed.dev_minor;
                f.v[4] = (long)matched->ino;
                f.v[5] = matched->dev_major;
                f.v[6] = matched->dev_minor;
                f.v[7] = fd_pid(pidfd);
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
    const char *suffix[] = {"/ns/user", "/ns/pid"};
    for (int j = 0; j < 2; j++) {
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
        f.v[0] = j;
        f.v[1] = init;
        f.v[2] = parent;
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
        k.v[0] = j;
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
    cpus.v[0] = 2;
    cpus.v[2] = cpu;
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
            detail.v[0] = k;
            detail.v[1] = n < 0 ? n : 0;
            detail.v[2] = value;
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
    f.v[0] = cpu;
    f.v[1] = minimum;
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
static long launch(const char *runtime, const char *image, const char *helper, const char *socket,
                   const char *log, int negative, char **env, int *pidfd,
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
                    negative ? "terminate-init" : "normal",
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
            f.v[0] = p;
            f.v[1] = status;
            journal(&f);
            continue;
        }
        if (p < 0 && p != -4)
            return 0;
        if (now() >= until)
            return 0;
        S3(POLL, 0, 0, 5);
    }
}
static int controller_case(const char *runtime, const char *image, const char *helper,
                           const char *root, int negative, char **env) {
    role = C;
    seq = 0;
    journal_error = log_error = runtime_reaped = outer_wait_error = 0;
    runtime_expected_pid = -1;
    journal_count = log_bytes = 0;
    log_read = log_output = -1;
    deadline = now() + 30000000000UL;
    char dir[2048], p[2304], socketpath[108], nonce[65];
    copy(dir, sizeof dir, root);
    cat(dir, sizeof dir, negative ? "/terminate-init" : "/normal");
    if (S3(MKDIRAT, AT_FDCWD, dir, 0700) < 0)
        return 1;
    copy(p, sizeof p, dir);
    cat(p, sizeof p, "/trace.bin");
    trace = create_file(p);
    if (trace < 0)
        return 1;
    {
        struct frame begun = make(BEGIN, "case-deadline");
        begun.v[0] = (long)deadline;
        begun.v[1] = negative;
        journal(&begun);
    }
    int failed = 1, released = 0, server = -1, peer = -1, peerfd = -1, initfd = -1, sentfd = -1,
        runtimefd = -1, frontend_file = -1;
    struct statx frontend_identity, starter_identity;
    long runtimepid = -1;
    unsigned char child_info[128] = {0};
    if (resources(env) || !only_thread() ||
        S5(WAITID, 0, 0, child_info, 0x1000000 | 4 | 1, 0) != -10 ||
        S2(PRCTL, PR_SET_CHILD_SUBREAPER, 1) < 0 || make_nonce(nonce) < 0 ||
        now() >= deadline - 20000000000UL)
        goto finish;
    case_nonce = nonce;
    frontend_file = frontend_fd(runtime, env, &frontend_identity);
    if (frontend_file < 0 || starter_pin(env, &starter_identity))
        goto finish;
    if (copy(socketpath, sizeof socketpath, dir) < 0 ||
        cat(socketpath, sizeof socketpath, "/control.sock") < 0)
        goto finish;
    struct sockaddr_un addr = {AF_UNIX, {0}};
    copy(addr.path, sizeof addr.path, socketpath);
    server = (int)S3(SOCKET, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (server < 0 || S3(BIND, server, &addr, 2 + len(socketpath) + 1) < 0 ||
        S2(CHMOD, socketpath, 0600) < 0 || S2(LISTEN, server, 1) < 0)
        goto finish;
    copy(p, sizeof p, dir);
    cat(p, sizeof p, "/runtime.log");
    runtimepid = launch(runtime, image, helper, socketpath, p, negative, env, &runtimefd,
                        frontend_file, &frontend_identity);
    if (runtimepid < 0)
        goto finish;
    runtime_expected_pid = (int)runtimepid;
    u64 setup = deadline - 20000000000UL;
    if (observe_frontend_exec((int)runtimepid, runtimefd, &frontend_identity, &starter_identity, setup) < 0) {
        struct frame missing = make(FAILED, "frontend-exec-unobserved");
        missing.v[0] = runtimepid;
        journal(&missing);
        goto cleanup;
    }
    S1(CLOSE, frontend_file);
    frontend_file = -1;
    if (ready(server, POLLIN, setup) < 0)
        goto cleanup;
    peer = (int)S4(ACCEPT4, server, 0, 0, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (peer < 0)
        goto cleanup;
    struct ucred cred = {-1, 0xffffffffU, 0xffffffffU};
    u32 sz = sizeof cred;
    if (S5(GETSOCKOPT, peer, SOL_SOCKET, SO_PEERCRED, &cred, &sz) < 0 || sz != sizeof cred ||
        cred.uid != (u32)S0(GETUID) || cred.gid != (u32)S0(GETGID))
        goto cleanup;
    sz = sizeof peerfd;
    if (S5(GETSOCKOPT, peer, SOL_SOCKET, SO_PEERPIDFD, &peerfd, &sz) < 0 || sz != sizeof peerfd ||
        fd_pid(peerfd) != cred.pid || exited(peerfd) || !same_executable(cred.pid, helper) ||
        !descendant(cred.pid, (int)runtimepid) || !same_cgroup(cred.pid) || exited(peerfd))
        goto cleanup;
    {
        struct statx identity;
        if (stat_path("/proc/self/exe", &identity))
            goto cleanup;
        struct frame evidence = make(PEER, "peerpidfd-exe-cgroup");
        evidence.v[0] = cred.pid;
        evidence.v[1] = cred.uid;
        evidence.v[2] = cred.gid;
        evidence.v[3] = runtimepid;
        evidence.v[4] = (long)identity.ino;
        evidence.v[5] = identity.dev_major;
        evidence.v[6] = identity.dev_minor;
        evidence.v[7] = fd_pid(peerfd);
        if (journal(&evidence))
            goto cleanup;
    }
    struct frame f;
    int passed = -1;
    if (recv_frame(peer, &f, &passed, setup) < 0 || passed >= 0 || f.role != A ||
        f.event != HELLO || !eq(f.text, nonce))
        goto cleanup;
    if (journal(&f))
        goto cleanup;
    f = make(AUTH, nonce);
    if (journal(&f) || send_frame(peer, &f, -1) < 0)
        goto cleanup;
    int mutual = 0, created = 0, limited = 0, armed = 0, canary = 0, init_reaped = 0,
        sentinel_reaped = 0, terminated = 0, error = 0;
    u64 last[5] = {0};
    last[A] = 1;
    for (;;) {
        if (recv_frame(peer, &f, &passed, setup) < 0)
            break;
        if (f.role == C || f.seq <= last[f.role]) {
            if (passed >= 0)
                S1(CLOSE, passed);
            error = 1;
            break;
        }
        last[f.role] = f.seq;
        if (journal(&f)) {
            if (passed >= 0)
                S1(CLOSE, passed);
            error = 1;
            break;
        }
        if (f.event == FAILED) {
            error = 1;
            if (passed >= 0)
                S1(CLOSE, passed);
            break;
        }
        if (f.event == CREATED && f.role == A && mutual && !created && passed >= 0) {
            initfd = passed;
            created = 1;
            int pid = fd_pid(initfd);
            if (pid <= 0 || f.v[1] != (long)cred.uid || f.v[2] != (long)cred.gid ||
                !descendant(pid, cred.pid) || !same_cgroup(pid) ||
                !distinct_namespaces(pid, cred.pid)) {
                error = 1;
                break;
            }
            struct frame cmd = make(MAP, "allow-map");
            if (journal(&cmd) || send_frame(peer, &cmd, -1) < 0) {
                error = 1;
                break;
            }
        } else if (f.event == FACTORY_AUTH && f.role == A && !mutual && !created && passed < 0) {
            if (f.v[0] < 0 || f.v[1] != (long)cred.uid || f.v[2] != (long)cred.gid ||
                !eq(f.text, nonce)) {
                error = 1;
                break;
            }
            mutual = 1;
        } else if (f.event == CONTEXT && passed < 0 &&
                   ((f.role == A && mutual && !created) || (f.role == I && created && !limited))) {
        } else if (f.event == MAPPING && f.role == A && created && !limited && passed < 0) {
            if (f.v[1] != 0) {
                error = 1;
                break;
            }
        } else if (f.event == LIMIT && f.role == I && created && !limited && passed < 0) {
            limited = f.v[0] == 0 && f.v[1] == -1 && f.v[2] == 8 && f.v[3] == 8;
            if (!limited) {
                error = 1;
                break;
            }
        } else if (f.event == ARMED && f.role == I && limited && !armed && passed < 0) {
            armed = f.v[0] == 0 && f.v[1] == 0 && f.v[2] == -123 && f.v[3] == 1 && f.v[4] == 1;
            if (!armed) {
                error = 1;
                break;
            }
            struct frame cmd = make(START, "start-one-sentinel");
            if (journal(&cmd) || send_frame(peer, &cmd, -1) < 0) {
                error = 1;
                break;
            }
            setup = now() + 2000000000UL;
        } else if (f.event == SENTINEL_FD && f.role == I && armed && sentfd < 0 && passed >= 0) {
            sentfd = passed;
        } else if (f.event == CANARY && f.role == S && armed && sentfd >= 0 && !canary &&
                   passed < 0) {
            canary = f.v[0] == -123 && f.v[1] == 8 && f.v[2] == 8;
            if (!canary) {
                error = 1;
                break;
            }
            if (negative) {
                long r = signal_fd(initfd, SIGKILL);
                struct frame z = make(TERMINATE, "init-pidfd");
                z.v[0] = r;
                journal(&z);
                terminated = r == 0;
                if (!terminated) {
                    error = 1;
                    break;
                }
            }
        } else if (f.event == SENTINEL_REAP && f.role == I && !negative && canary && passed < 0) {
            sentinel_reaped = f.v[0] == 0 && f.v[1] == 0;
            if (!sentinel_reaped) {
                error = 1;
                break;
            }
        } else if (f.event == INIT_REAP && f.role == A && canary && passed < 0) {
            init_reaped = f.v[0] == 0 && f.v[1] == (negative ? SIGKILL : 0) && f.v[2] == 1;
            struct frame observed = make(PIDFD_EXIT, "controller-init-sentinel");
            observed.v[0] = initfd >= 0 && !!exited(initfd);
            observed.v[1] = sentfd >= 0 && !!exited(sentfd);
            observed.v[2] = initfd;
            observed.v[3] = sentfd;
            if (journal(&observed) || !observed.v[0] || !observed.v[1])
                error = 1;
            break;
        } else {
            if (passed >= 0)
                S1(CLOSE, passed);
            error = 1;
            break;
        }
    }
    failed = error || !created || !limited || !armed || !canary || !init_reaped ||
             (!negative && !sentinel_reaped) || (negative && !terminated);
cleanup: {
    u64 until = now() + 10000000000UL;
    if (until > deadline)
        until = deadline;
    if (initfd >= 0 && !exited(initfd))
        signal_fd(initfd, SIGKILL);
    if (peer >= 0) {
        struct frame stop = make(STOP, "stop");
        send_frame(peer, &stop, -1);
        journal(&stop);
        S1(CLOSE, peer);
        peer = -1;
    }
    if (runtimefd >= 0 &&
        !exited(runtimefd)) { /* Give the trusted runtime a bounded natural exit first. */
        u64 grace = now() + 2000000000UL;
        if (grace > until)
            grace = until;
        ready(runtimefd, POLLIN, grace);
        if (!exited(runtimefd))
            signal_fd(runtimefd, SIGTERM);
    }
    released = all_reaped(until);
    if (!released && runtimefd >= 0 && !exited(runtimefd))
        signal_fd(runtimefd, SIGKILL);
    if (!released)
        released = all_reaped(deadline);
}
finish:
    drain_log();
    failed = failed || journal_error || log_error || !runtime_reaped || outer_wait_error ||
             now() > deadline;
    {
        struct frame f = make(RELEASED, "case");
        f.v[0] = released;
        f.v[1] = failed;
        journal(&f);
        if (trace >= 0) {
            if (S1(FSYNC, trace) < 0)
                failed = 1;
            S1(CLOSE, trace);
            trace = -1;
        }
    }
    int fds[] = {server, peer, peerfd, initfd, sentfd, runtimefd, frontend_file};
    for (usize j = 0; j < sizeof fds / sizeof fds[0]; j++)
        if (fds[j] >= 0)
            S1(CLOSE, fds[j]);
    if (log_read >= 0)
        S1(CLOSE, log_read);
    if (log_output >= 0) {
        if (S1(FSYNC, log_output) < 0)
            failed = 1;
        S1(CLOSE, log_output);
    }
    failed = failed || journal_error || log_error;
    copy(p, sizeof p, dir);
    cat(p, sizeof p, "/result.json");
    int file = create_file(p);
    if (file >= 0) {
        const char *value = !failed && released
                                ? "{\"status\":\"permission_checks_passed_pending_review\","
                                : "{\"status\":\"failed\",";
        const char *flags =
            "\"implementation_approved\":false,\"trusted_probe_authorized\":false,\"candidate_"
            "execution_authorized\":false,\"main_matrix_authorized\":false,\"sandbox_admission\":"
            "false,\"nproc_boundary_tested\":false,\"production_filter_verified\":false,\"full_"
            "descendant_cleanup_verified\":false,\"cost_sample_eligible\":false,\"scientific_"
            "profile\":false}\n";
        if (write_all(file, value, len(value)) < 0 || write_all(file, flags, len(flags)) < 0 ||
            S1(FSYNC, file) < 0)
            failed = 1;
        S1(CLOSE, file);
    } else
        failed = 1;
    return failed || !released;
}
static int path_ok(const char *p) {
    if (*p != '/')
        return 0;
    for (usize j = 0; p[j]; j++)
        if (p[j] == ':' || p[j] == ',' || p[j] == '\n' || p[j] == '\r' ||
            (p[j] == '.' && p[j + 1] == '.'))
            return 0;
    return len(p) < 1800;
}
static int mainx(int argc, char **argv, char **env) {
    /* Compile-time P capability; Python still requires its own B/R/owner. */
    if (!RELEASE_ENABLED) {
        const char *s = "permission helper has no execution release\n";
        write_all(2, s, len(s));
        return 78;
    }
    if (S0(GETUID) <= 0 || S0(GETUID) != S0(GETEUID) || S0(GETGID) != S0(GETEGID) ||
        !active_caps_zero())
        return 77;
    if (argc == 5 && eq(argv[1], "--factory") && eq(argv[2], "/probe/control.sock") &&
        len(argv[3]) == 64 && (eq(argv[4], "normal") || eq(argv[4], "terminate-init")))
        return factory(argv[2], argv[3], eq(argv[4], "terminate-init"));
    if (argc != 6 || !eq(argv[1], "--controller"))
        return 64;
    for (int j = 2; j < 6; j++)
        if (!path_ok(argv[j]))
            return 64;
    S1(UMASK, 0077);
    if (S2(PRCTL, PR_SET_DUMPABLE, 0) < 0 || S3(CLOSE_RANGE, 3, 0xffffffffU, 0) < 0)
        return 77;
    int result = controller_case(argv[2], argv[3], argv[4], argv[5], 0, env);
    if (result)
        return result;
    return controller_case(argv[2], argv[3], argv[4], argv[5], 1, env);
}
__attribute__((used, noreturn)) void permission_start(unsigned long *sp) {
    int argc = (int)sp[0];
    char **argv = (char **)(sp + 1);
    end(mainx(argc, argv, argv + argc + 1));
}
__asm__(".global _start\n_start:\n cld\n xor %rbp,%rbp\n mov %rsp,%rdi\n and $-16,%rsp\n call "
        "permission_start\n ud2\n");
