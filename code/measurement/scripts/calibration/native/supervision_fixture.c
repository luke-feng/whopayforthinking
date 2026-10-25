/* Fixed scheduler-only fixture, Linux x86-64. No libc/exec/threads/namespaces.
 * Controller C owns exactly two descendant pidfds; at most C+I+R are live.
 * Eight serial cases maximum. This is NOT the candidate sandbox or PID-limit test.
 */
#include "rootless_permission_abi.h"

enum { MAX_CASES=8, CASE_SECONDS=25, ACK_SECONDS=10, CLEANUP_SECONDS=2 };
static int control=-1, peerfd=-1, initfd=-1, runnerfd=-1, pairfd=-1;
static long initpid=-1, runnerpid=-1;
static long lifetime_deadline;
static int created;
static unsigned sequence;
static char nonce[33], seen[MAX_CASES][64];
static const char schema[]="www27-trusted-case-control-v1";

void *memset(void *p,int value,usize n) { unsigned char *q=p; while(n--)*q++=(unsigned char)value; return p; }
void *memcpy(void *d,const void *s,usize n) { unsigned char *a=d; const unsigned char *b=s; while(n--)*a++=*b++; return d; }
static usize length(const char *s) { usize n=0; while(s[n])n++; return n; }
static int equal(const char *a,const char *b) { usize n=0; while(a[n]&&a[n]==b[n])n++; return a[n]==b[n]; }
static void copy(char *dst,const char *src) { do {*dst++=*src;} while(*src++); }
static long now(void) { struct timespec t; if(S2(CLOCK_GETTIME,1,&t)<0) return -1; return t.sec*1000000000L+t.nsec; }
static int alive(int fd) { struct pollfd p={fd,POLLIN,0}; long r=S3(POLL,&p,1,0); return r==0; }
static void closefd(int *fd) { if(*fd>=0)S1(CLOSE,*fd); *fd=-1; }
static void leave(int code) __attribute__((noreturn));
static void leave(int code) { S1(EXIT_GROUP,code); __builtin_unreachable(); }
static int wait_ready(int fd,long deadline,int watch_peer) {
    for(;;) {
        long t=now(); if(t<0||t>=deadline) return -1;
        struct pollfd p[2]={{fd,POLLIN,0},{peerfd,POLLIN,0}};
        long ms=(deadline-t)/1000000; if(ms>20)ms=20; if(ms<1)ms=1;
        long rc=S3(POLL,p,watch_peer?2:1,ms);
        if(rc<0) { if(rc==-4)continue; return -1; }
        if(watch_peer&&p[1].revents) return -1;
        if(p[0].revents&POLLERR) return -1;
        if(p[0].revents&POLLIN) return 0;
        if(p[0].revents&POLLHUP) return -1;
    }
}
static long send_packet(int fd,const void *raw,usize size) {
    struct iovec io={(void*)raw,size}; struct msghdr m={0};m.iov=&io;m.iovlen=1;
    return S3(SENDMSG,fd,&m,MSG_DONTWAIT|MSG_NOSIGNAL);
}
static long recv_packet(int fd,void *raw,usize capacity,long deadline,int watch_peer) {
    if(wait_ready(fd,deadline,watch_peer)<0)return -1;
    struct iovec io={raw,capacity};struct msghdr m={0};m.iov=&io;m.iovlen=1;
    long rc=S3(RECVMSG,fd,&m,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if(rc<=0||rc>=(long)capacity||(m.flags&(MSG_TRUNC|MSG_CTRUNC)))return -1;
    ((char*)raw)[rc]=0;return rc;
}
static int token_char(char c) { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'; }
static int case_id(const char *s) { usize n=length(s);if(n<1||n>63)return 0;for(usize i=0;i<n;i++)if(!token_char(s[i]))return 0;return 1; }
static void space(const char **s) { while(**s==' '||**s=='\t'||**s=='\r'||**s=='\n')(*s)++; }
static int string(const char **s,char *out,usize cap) {
    space(s);if(*(*s)++!='"')return -1;usize n=0;
    while(**s&&**s!='"') { if((unsigned char)**s<32||**s=='\\'||n+1>=cap)return -1;out[n++]=*(*s)++; }
    if(**s!='"')return -1;
    (*s)++;out[n]=0;return 0;
}
/* Only four string fields, no escapes/arrays/numbers/duplicates/extensions. */
static int request(const char *raw,const char *wanted,char out_case[64]) {
    const char *p=raw;unsigned keys=0;space(&p);if(*p++!='{')return -1;
    for(unsigned i=0;i<4;i++) {
        char key[32],value[128];if(string(&p,key,sizeof key)<0)return -1;
        space(&p);if(*p++!=':'||string(&p,value,sizeof value)<0)return -1;
        unsigned bit=0;
        if(equal(key,"schema")) {bit=1;if(!equal(value,schema))return -1;}
        else if(equal(key,"nonce")) {bit=2;if(!equal(value,nonce))return -1;}
        else if(equal(key,"event")) {bit=4;if(!equal(value,wanted))return -1;}
        else if(equal(key,"case_id")) {bit=8;if(!case_id(value))return -1;copy(out_case,value);}
        else return -1;
        if(keys&bit)return -1;
        keys|=bit;space(&p);
        if(*p++!=(i==3?'}':','))return -1;
    }
    space(&p);return keys==15&&!*p?0:-1;
}
static usize append(char *out,usize n,const char *s) { while(*s&&n<1000)out[n++]=*s++;return n; }
static usize decimal(char *out,usize n,unsigned long value) {
    char rev[24];usize k=0;do {rev[k++]=(char)('0'+value%10);value/=10;}while(value&&k<24);
    while(k&&n<1000)out[n++]=rev[--k];
    return n;
}
static int event(const char *kind,const char *id) {
    char out[1024];usize n=0;
    n=append(out,n,"{\"schema\":\"");n=append(out,n,schema);n=append(out,n,"\",\"nonce\":\"");
    n=append(out,n,nonce);n=append(out,n,"\",\"seq\":");n=decimal(out,n,++sequence);
    n=append(out,n,",\"event\":\"");n=append(out,n,kind);n=append(out,n,"\",\"case_id\":\"");
    n=append(out,n,id);
    if(equal(kind,"stopped")) {
        n=append(out,n,"\"}");
    } else if(equal(kind,"started")) {
        n=append(out,n,"\",\"roles\":{\"init\":");n=decimal(out,n,(unsigned long)initpid);
        n=append(out,n,",\"runner\":");n=decimal(out,n,(unsigned long)runnerpid);n=append(out,n,"}}");
    } else {
        n=append(out,n,"\",\"reaped_pids\":[");n=decimal(out,n,(unsigned long)initpid);
        n=append(out,n,",");n=decimal(out,n,(unsigned long)runnerpid);n=append(out,n,"]}");
    }
    return n<1000&&send_packet(control,out,n)==(long)n?0:-1;
}
static int parent_guard(long parent) {
    return S2(PRCTL,PR_SET_PDEATHSIG,SIGKILL)==0&&S0(GETPPID)==parent?0:-1;
}
static int reap(long pid,long deadline,int watch_peer) {
    for(;;) {
        int status=0;long rc=S4(WAIT4,pid,&status,WNOHANG,NIL);
        if(rc==pid)return status==0?0:-1;
        if(rc<0||now()<0||now()>=deadline||(watch_peer&&!alive(peerfd)))return -1;
        S3(POLL,NIL,0,1);
    }
}
static int clean(void) {
    if(!created) {closefd(&runnerfd);closefd(&initfd);closefd(&pairfd);return 0;}
    if(runnerfd>=0)S4(PIDFD_SIGNAL,runnerfd,SIGKILL,NIL,0);
    if(initfd>=0)S4(PIDFD_SIGNAL,initfd,SIGKILL,NIL,0);
    long deadline=now()+CLEANUP_SECONDS*1000000000L;int empty=0;
    while(now()>0&&now()<deadline) {
        int status;long rc=S4(WAIT4,-1,&status,WNOHANG,NIL);
        if(rc==-10) {empty=1;break;} /* ECHILD: this fresh subreaper's children only. */
        if(rc<0&&rc!=-4)break;
        if(rc==0)S3(POLL,NIL,0,1);
    }
    closefd(&runnerfd);closefd(&initfd);closefd(&pairfd);if(empty)created=0;return empty?0:-1;
}
static void runner(int gate,int report,long parent,long deadline) __attribute__((noreturn));
static void runner(int gate,int report,long parent,long deadline) {
    S1(CLOSE,report);if(parent_guard(parent)<0)leave(31);
    char go;if(wait_ready(gate,deadline,0)<0||S3(RD,gate,&go,1)!=1||go!='G')leave(32);
    S1(CLOSE,gate);
    volatile unsigned long sum=0;for(unsigned i=0;i<1024;i++)sum+=i;
    leave(sum==523776?0:33);
}
static void init_role(int report,long parent,long deadline) __attribute__((noreturn));
static void init_role(int report,long parent,long deadline) {
    closefd(&control);closefd(&peerfd);if(parent_guard(parent)<0)leave(21);
    int gates[2];if(S2(PIPE2,gates,O_CLOEXEC)<0)leave(22);
    int rfd=-1;long self=S0(GETPID);
    long r=S5(CLONE,CLONE_PIDFD|SIGCHLD,0,&rfd,0,0);
    if(r==0) {S1(CLOSE,gates[1]);runner(gates[0],report,self,deadline);}
    S1(CLOSE,gates[0]);if(r<0)leave(23);
    char ancillary[24]={0};struct cmsghdr *header=(void*)ancillary;
    header->len=sizeof *header+sizeof(int);header->level=SOL_SOCKET;header->type=SCM_RIGHTS;
    *(int*)(ancillary+sizeof *header)=rfd;
    struct iovec io={&r,sizeof r};struct msghdr msg={0};msg.iov=&io;msg.iovlen=1;msg.control=ancillary;msg.controllen=sizeof ancillary;
    if(S3(SENDMSG,report,&msg,MSG_DONTWAIT|MSG_NOSIGNAL)!=(long)sizeof r)leave(24);
    char go[2];if(recv_packet(report,go,sizeof go,deadline,0)!=1||go[0]!='G')leave(25);
    if(S3(WR,gates[1],"G",1)!=1)leave(26);
    S1(CLOSE,gates[1]);
    int ok=reap(r,deadline,0);S1(CLOSE,rfd);S1(CLOSE,report);leave(ok==0?0:27);
}
static int one_case(const char *id) {
    long deadline=now()+CASE_SECONDS*1000000000L;int pair[2];
    if(deadline>lifetime_deadline)deadline=lifetime_deadline;
    if(S4(SOCKETPAIR,AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair)<0)return -1;
    long parent=S0(GETPID);
    initpid=S5(CLONE,CLONE_PIDFD|SIGCHLD,0,&initfd,0,0);
    if(initpid==0) {S1(CLOSE,pair[0]);init_role(pair[1],parent,deadline);}
    S1(CLOSE,pair[1]);pairfd=pair[0];if(initpid<0)return -1;created=1;
    if(wait_ready(pairfd,deadline,1)<0)return -1;
    char ancillary[24]={0};struct iovec io={&runnerpid,sizeof runnerpid};struct msghdr msg={0};
    msg.iov=&io;msg.iovlen=1;msg.control=ancillary;msg.controllen=sizeof ancillary;
    long got=S3(RECVMSG,pairfd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    struct cmsghdr *header=(void*)ancillary;
    if(got!=(long)sizeof runnerpid||(msg.flags&(MSG_TRUNC|MSG_CTRUNC))||msg.controllen!=sizeof ancillary||
       header->len!=sizeof *header+sizeof(int)||header->level!=SOL_SOCKET||header->type!=SCM_RIGHTS||runnerpid<=0)return -1;
    runnerfd=*(int*)(ancillary+sizeof *header);
    if(runnerfd<0||!alive(initfd)||!alive(runnerfd)||event("started",id)<0)return -1;
    char raw[2048],ack_case[64];long ack_deadline=now()+ACK_SECONDS*1000000000L;
    if(ack_deadline>deadline)ack_deadline=deadline;
    if(recv_packet(control,raw,sizeof raw,ack_deadline,1)<0||request(raw,"registered",ack_case)<0||!equal(ack_case,id))return -1;
    if(send_packet(pairfd,"G",1)!=1||reap(initpid,deadline,1)<0)return -1;
    /* I has waited R; C has waited I. Require no remaining adopted child. */
    int status;if(S4(WAIT4,-1,&status,WNOHANG,NIL)!=-10)return -1;
    closefd(&runnerfd);closefd(&initfd);closefd(&pairfd);created=0;
    return event("finished",id);
}
static long number(const char *s) { long v=0;if(!*s)return -1;while(*s) {if(*s<'0'||*s>'9'||v>100000000)return -1;v=v*10+(*s++-'0');}return v; }
static int run(long argc,char **argv) {
    if(argc!=8||!equal(argv[1],"--trusted-fixture-v1")||!equal(argv[2],"--socket")||
       !equal(argv[4],"--nonce")||!equal(argv[6],"--worker-pid"))return 2;
    if(S0(GETUID)<=0||S0(GETUID)!=S0(GETEUID)||S2(PRCTL,PR_SET_NO_NEW_PRIVS,1)<0||
       S2(PRCTL,PR_SET_CHILD_SUBREAPER,1)<0)return 3;
    /* WNOWAIT observes without reaping an ambient child inherited across exec.
     * Require ECHILD before creating any fixture descendant. */
    long info[16]={0};if(S5(WAITID,0,0,info,0x01000005,NIL)!=-10)return 3;
    if(length(argv[5])!=32)return 4;
    for(unsigned i=0;i<32;i++)if(!((argv[5][i]>='0'&&argv[5][i]<='9')||(argv[5][i]>='a'&&argv[5][i]<='f')))return 4;
    copy(nonce,argv[5]);long worker=number(argv[7]);if(worker<=0)return 4;
    struct sockaddr_un address={0};address.family=AF_UNIX;
    if(argv[3][0]!='/'||length(argv[3])>=sizeof address.path)return 4;
    copy(address.path,argv[3]);
    control=(int)S3(SOCKET,AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(control<0||S3(CONNECT,control,&address,sizeof address)<0)return 5;
    struct ucred cred;u32 size=sizeof cred;
    if(S5(GETSOCKOPT,control,SOL_SOCKET,SO_PEERCRED,&cred,&size)<0||size!=sizeof cred||cred.pid!=worker||cred.uid!=(u32)S0(GETUID))return 6;
    size=sizeof peerfd;if(S5(GETSOCKOPT,control,SOL_SOCKET,SO_PEERPIDFD,&peerfd,&size)<0||size!=sizeof peerfd||!alive(peerfd))return 6;
    lifetime_deadline=now()+1200L*1000000000L;
    for(unsigned count=0;count<=MAX_CASES;count++) {
        char raw[2048],id[64];
        if(recv_packet(control,raw,sizeof raw,lifetime_deadline,1)<0)return 7;
        if(request(raw,"stop",id)==0&&equal(id,"shutdown"))return event("stopped",id)==0?0:10;
        if(count==MAX_CASES)return 8; /* Last iteration permits stop, never another fork. */
        if(request(raw,"start",id)<0)return 8;
        for(unsigned j=0;j<count;j++)if(equal(seen[j],id))return 8;
        copy(seen[count],id);
        if(one_case(id)<0) {clean();return 9;}
    }
    return 0;
}
static void entry(long *stack) __attribute__((used,noreturn));
static void entry(long *stack) { int code=run(stack[0],(char**)&stack[1]);clean();closefd(&control);closefd(&peerfd);leave(code); }
__attribute__((naked,noreturn)) void _start(void) {
    __asm__ volatile("mov %rsp,%rdi\n\tandq $-16,%rsp\n\tcall entry\n\tud2");
}
