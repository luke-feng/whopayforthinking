/* F trusted finite fixture, Linux x86-64, static libc build. NOT a candidate
 * executor or N=32 proof. E Python keeper survives this controller's death.
 * No compiler or executable is run by the Python synthetic tests.
 * Frame ABI is defined HERE (no borrowed/omitted project headers).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { MAGIC=0x464c5431, HELLO=1, ROLE=2, ARMED=3, REAPED=4, PHASE=5, DONE=6, FAILED=7 };
struct report { uint32_t magic, kind, seq, role; char nonce[33]; int32_t value; };
_Static_assert(sizeof(struct report)==56, "F frame ABI must match Python <IIII33s3xi");
static char nonce[33];
static unsigned sequence;
static int escaped;

static int64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) _exit(111);
    return (int64_t)t.tv_sec*1000000000LL+t.tv_nsec;
}
static int ready(int fd,int64_t until) {
    struct pollfd p={fd,POLLIN,0};
    while(now_ns()<until) {
        int r=poll(&p,1,20);
        if(r<0&&errno==EINTR) continue;
        if(r<0||(r>0&&(p.revents&(POLLERR|POLLHUP|POLLNVAL)))) return -1;
        if(r>0&&(p.revents&POLLIN)) return 0;
    }
    return -1;
}
static int packet(int fd,unsigned kind,unsigned role,int value,int passed) {
    struct report r={MAGIC,kind,++sequence,role,{0},value};
    memcpy(r.nonce,nonce,33);
    struct iovec v={&r,sizeof r};
    char extra[CMSG_SPACE(sizeof(int))]={0};
    struct msghdr m={0}; m.msg_iov=&v;m.msg_iovlen=1;
    if(passed>=0) {
        m.msg_control=extra;m.msg_controllen=sizeof extra;
        struct cmsghdr *c=CMSG_FIRSTHDR(&m);
        c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&passed,sizeof(int));
    }
    return sendmsg(fd,&m,MSG_NOSIGNAL|MSG_DONTWAIT)==(ssize_t)sizeof r?0:-1;
}
static int report_self(int fd,unsigned role) {
    int p=(int)syscall(SYS_pidfd_open,getpid(),0);
    if(p<0) return -1;
    int rc=packet(fd,ROLE,role,0,p);close(p);return rc;
}
static int unix_socket(const char *path,int server) {
    struct sockaddr_un a={.sun_family=AF_UNIX};
    if(strlen(path)>=sizeof a.sun_path) return -1;
    strcpy(a.sun_path,path);
    int s=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(s<0) return -1;
    int rc=server?bind(s,(void*)&a,sizeof a):connect(s,(void*)&a,sizeof a);
    if(rc<0) { close(s);return -1; }
    if(server&&(chmod(path,0600)||listen(s,1))) {close(s);return -1;}
    return s;
}
static int wait_one(pid_t pid,int64_t until,int *status) {
    while(now_ns()<until) {
        pid_t r=waitpid(pid,status,WNOHANG);
        if(r==pid) return 0;
        if(r<0&&errno!=EINTR) return -1;
        struct timespec pause={0,1000000};nanosleep(&pause,NULL);
    }
    return -1;
}
static int write_map(pid_t child,const char *leaf,const char *text) {
    char path[128];
    int n=snprintf(path,sizeof path,"/proc/%ld/%s",(long)child,leaf);
    if(n<0||(size_t)n>=sizeof path) return -1;
    int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return -1;
    size_t len=strlen(text);
    ssize_t rc=write(fd,text,len);close(fd);return rc==(ssize_t)len?0:-1;
}
static int drop_caps(void) {
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct d[2]={{0,0,0},{0,0,0}};
    return (int)syscall(SYS_capset,&h,d);
}
static int delayed(int fd,unsigned role,unsigned seconds) {
    if(report_self(fd,role)) return 1;
    close(fd);
    struct timespec t={(time_t)seconds,0};
    while(nanosleep(&t,&t)&&errno==EINTR) {}
    return 0;
}
static int inner(int control,int mapping_gate) {
    char go;
    if(read(mapping_gate,&go,1)!=1||go!='G') return 20;
    close(mapping_gate);
    if(getpid()!=1||prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)) return 21;
    struct rlimit nproc={8,8};
    if(setrlimit(RLIMIT_NPROC,&nproc)||drop_caps()||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) return 22;
    if(report_self(control,4)) return 23;
    if(!escaped) {
        pid_t child=fork();
        if(child<0) return 24;
        if(child==0) _exit(delayed(control,5,20));
        if(packet(control,ARMED,4,0,-1)) return 25;
        int status;
        if(wait_one(child,now_ns()+25000000000LL,&status)||status) return 26;
        packet(control,REAPED,5,status,-1);
        return 0;
    }
    if(packet(control,ARMED,4,0,-1)||ready(control,now_ns()+25000000000LL)||recv(control,&go,1,0)!=1||go!='R') return 27;
    /* Actual-path bounded double fork: two descendants. Namespace init is the
     * subreaper, retains wait ownership after the intermediate parent exits.
     * The prior host stage uses exactly one descendant; total fixture creates=3.
     */
    pid_t first=fork();
    if(first<0) return 28;
    if(first==0) {
        if(setsid()<0||report_self(control,6)) _exit(29);
        /* O must really observe this living session leader. The host controller
         * forwards K only after W receives the authenticated O observation ACK.
         * No sleep duration substitutes for that observation. */
        if(ready(control,now_ns()+10000000000LL)||recv(control,&go,1,0)!=1||go!='K') _exit(35);
        pid_t second=fork();
        if(second<0) _exit(30);
        if(second==0) {
            if(setsid()<0||report_self(control,7)) _exit(36);
            if(ready(control,now_ns()+10000000000LL)||recv(control,&go,1,0)!=1||go!='K') _exit(37);
            close(control);
            /* Intentionally outlives the 30s case. Success requires step cancel
             * while this distinct session/cgroup member is still alive. */
            struct timespec t={45,0};
            while(nanosleep(&t,&t)&&errno==EINTR) {}
            _exit(0);
        }
        _exit(0);
    }
    int status;
    if(wait_one(first,now_ns()+15000000000LL,&status)||status||packet(control,REAPED,6,status,-1)) return 31;
    int64_t until=now_ns()+70000000000LL;
    int reaped=0;
    while(now_ns()<until) {
        pid_t p=waitpid(-1,&status,WNOHANG);
        if(p>0) {if(status) return 32;reaped++;packet(control,REAPED,7,status,-1);}
        else if(p<0&&errno==ECHILD) break;
        else {struct timespec t={0,1000000};nanosleep(&t,NULL);}
    }
    if(reaped!=1) return 33;
    return packet(control,DONE,4,0,-1)?34:0;
}
static int factory(const char *path) {
    int control=unix_socket(path,0);
    if(control<0||report_self(control,3)) return 40;
    int gate[2];if(pipe2(gate,O_CLOEXEC)) return 41;
    uid_t uid=getuid();gid_t gid=getgid();
    pid_t child=(pid_t)syscall(SYS_clone,CLONE_NEWUSER|CLONE_NEWPID|SIGCHLD,NULL,NULL,NULL,0);
    if(child<0) return 42;
    if(child==0) {close(gate[1]);_exit(inner(control,gate[0]));}
    close(gate[0]);
    char map[128];
    if(write_map(child,"setgroups","deny\n")) return 43;
    snprintf(map,sizeof map,"%u %u 1\n",uid,uid);
    if(write_map(child,"uid_map",map)) return 44;
    snprintf(map,sizeof map,"%u %u 1\n",gid,gid);
    if(write_map(child,"gid_map",map)||write(gate[1],"G",1)!=1) return 45;
    close(gate[1]);
    int status;
    if(wait_one(child,now_ns()+(escaped?90000000000LL:30000000000LL),&status)||!WIFEXITED(status)||WEXITSTATUS(status)) return 46;
    close(control);return 0;
}
static int forward(int from,int to,int *done) {
    struct report r;
    struct iovec v={&r,sizeof r};char extra[CMSG_SPACE(sizeof(int))]={0};
    struct msghdr m={0};m.msg_iov=&v;m.msg_iovlen=1;m.msg_control=extra;m.msg_controllen=sizeof extra;
    ssize_t n=recvmsg(from,&m,MSG_CMSG_CLOEXEC);
    if(n!=(ssize_t)sizeof r||m.msg_flags&(MSG_TRUNC|MSG_CTRUNC)||r.magic!=MAGIC||memcmp(r.nonce,nonce,33)) return -1;
    int passed=-1;
    struct cmsghdr *c=CMSG_FIRSTHDR(&m);
    if(c) {
        if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len!=CMSG_LEN(sizeof(int))||CMSG_NXTHDR(&m,c)) return -1;
        memcpy(&passed,CMSG_DATA(c),sizeof passed);
    }
    int rc=packet(to,r.kind,r.role,r.value,passed);
    if(passed>=0) close(passed);
    if(r.kind==DONE) *done=1;
    return rc;
}
static int host_stage(int outer) {
    int gate[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,gate)) return -1;
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        close(gate[0]);
        if(setsid()<0) _exit(60);
        if(send(gate[1],"S",1,MSG_NOSIGNAL)!=1||ready(gate[1],now_ns()+10000000000LL)) _exit(67);
        char released;if(recv(gate[1],&released,1,0)!=1||released!='G') _exit(68);
        close(gate[1]);
        struct timespec t={1,0};nanosleep(&t,NULL);_exit(0);
    }
    close(gate[1]);
    char armed;
    if(ready(gate[0],now_ns()+5000000000LL)||recv(gate[0],&armed,1,0)!=1||armed!='S') return -1;
    int pidfd=(int)syscall(SYS_pidfd_open,child,0);
    if(pidfd<0) return -1;
    int sent=packet(outer,ROLE,8,0,pidfd);close(pidfd);
    if(sent) return -1;
    char ack;
    if(ready(outer,now_ns()+10000000000LL)||recv(outer,&ack,1,0)!=1||ack!='K'||send(gate[0],"G",1,MSG_NOSIGNAL)!=1) return -1;
    close(gate[0]);
    int status;
    if(wait_one(child,now_ns()+3000000000LL,&status)||status) return -1;
    return packet(outer,REAPED,8,status,-1);
}
static int controller(char **v) {
    const char *runtime=v[5],*image=v[6],*self=v[7],*inside=v[8];
    int control=unix_socket(v[3],0);
    if(control<0||report_self(control,1)) return 50;
    char cmd;
    if(ready(control,now_ns()+10000000000LL)||recv(control,&cmd,1,0)!=1||cmd!='A') return 51;
    int server=unix_socket(inside,1);if(server<0) return 52;
    char bind_self[4096],bind_sock[4096];
    if(snprintf(bind_self,sizeof bind_self,"%s:/fault/fixture:ro",self)>=(int)sizeof bind_self||
       snprintf(bind_sock,sizeof bind_sock,"%s:/fault/inside.sock:ro",inside)>=(int)sizeof bind_sock) return 53;
    pid_t child=fork();
    if(child<0) return 54;
    if(child==0) {
        struct rlimit files={65536,65536};if(setrlimit(RLIMIT_FSIZE,&files)) _exit(55);
        char *argv[]={(char*)runtime,"exec","--containall","--cleanenv","--no-home","--no-eval","--userns",
          "--no-mount","home,cwd,hostfs,bind-paths,/home,/scratch,/shares,/apps","--net","--network","none",
          "--drop-caps","ALL","--pwd","/tmp","--bind",bind_self,"--bind",bind_sock,(char*)image,
          "/fault/fixture","--factory",v[2],"/fault/inside.sock",nonce,NULL};
        char *env[]={"PATH=/usr/bin:/bin","LC_ALL=C","TZ=UTC","HOME=/nonexistent","APPTAINER_BIND=","APPTAINER_BINDPATH=",NULL};
        close(control);close(server);
        execve(runtime,argv,env);_exit(56);
    }
    if(ready(server,now_ns()+10000000000LL)) return 57;
    int peer=accept4(server,NULL,NULL,SOCK_CLOEXEC);close(server);
    if(peer<0) return 58;
    struct ucred cred; socklen_t size=sizeof cred;
    if(getsockopt(peer,SOL_SOCKET,SO_PEERCRED,&cred,&size)||cred.uid!=getuid()) return 59;
    int done=0;int64_t until=now_ns()+90000000000LL;
    while(now_ns()<until&&!done) {
        struct pollfd p[2]={{peer,POLLIN,0},{control,POLLIN,0}};
        if(poll(p,2,20)<0) {if(errno==EINTR) continue;return 61;}
        if(p[0].revents&POLLIN) {if(forward(peer,control,&done)) return 62;}
        if(p[1].revents&POLLIN) {
            if(recv(control,&cmd,1,0)!=1||!escaped) return 63;
            if(cmd=='R') {
                if(host_stage(control)||send(peer,"R",1,MSG_NOSIGNAL)!=1) return 64;
            } else if(cmd=='K') {
                if(send(peer,"K",1,MSG_NOSIGNAL)!=1) return 69;
            } else return 63;
        }
        if((p[1].revents&(POLLHUP|POLLERR))||p[0].revents&POLLERR) break;
        if(!escaped&&p[0].revents&POLLHUP) break;
    }
    int status;
    if(wait_one(child,now_ns()+90000000000LL,&status)) return 65;
    close(peer);close(control);
    return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:66;
}
int main(int argc,char **argv) {
    signal(SIGPIPE,SIG_IGN);
    if(argc==5&&!strcmp(argv[1],"--factory")) {
        if(strlen(argv[4])!=32) return 70;
        memcpy(nonce,argv[4],33);escaped=!strcmp(argv[2],"escaped-session");return factory(argv[3]);
    }
    if(argc!=9||strcmp(argv[1],"--controller")||strlen(argv[4])!=32) return 71;
    for(unsigned i=0;i<32;i++) if(!((argv[4][i]>='0'&&argv[4][i]<='9')||(argv[4][i]>='a'&&argv[4][i]<='f'))) return 72;
    if(strcmp(argv[2],"controller-loss")&&strcmp(argv[2],"master-loss")&&strcmp(argv[2],"escaped-session")&&strcmp(argv[2],"supervisor-loss")) return 73;
    memcpy(nonce,argv[4],33);escaped=!strcmp(argv[2],"escaped-session");
    if(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)) return 74;
    return controller(argv);
}
