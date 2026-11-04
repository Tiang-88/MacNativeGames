/* nn::socket over the host's BSD sockets, for mods that bring their own networking.

   The game's own services have no network on this port (nifm answers offline and there is no bsd service), but a mod
   reaches the socket API through the module's imports, which the loader resolves here. The thirteen entry points below
   are the ones the multiplayer mod uses: an IPv4 TCP client with non-blocking connect, polled through GetPeerName and
   SO_ERROR. The SDK numbers errno the Linux way (its socket library is the Linux ABI) while the host uses the BSD
   values, so every failure is translated; the structures themselves (sockaddr with sin_len, SOL_SOCKET 0xffff,
   SO_ERROR 0x1007) are the same on both. Set TOTK_NET_LOG=1 to see every call. */
#include "runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static __thread int net_last_errno;

/* The guest's errno for a host one. The SDK's socket library is Linux's: the same numbers as Linux for the common
   errors, and the socket family the host numbers quite differently (EAGAIN 35 vs 11, ECONNREFUSED 61 vs 111). */
static int net_errno(int host) {
 switch(host) {
 case EAGAIN: return 11;
 case EINPROGRESS: return 115;
 case EALREADY: return 114;
 case ENOTSOCK: return 88;
 case EDESTADDRREQ: return 89;
 case EMSGSIZE: return 90;
 case EPROTOTYPE: return 91;
 case ENOPROTOOPT: return 92;
 case EPROTONOSUPPORT: return 93;
 case EOPNOTSUPP: return 95;
 case EAFNOSUPPORT: return 97;
 case EADDRINUSE: return 98;
 case EADDRNOTAVAIL: return 99;
 case ENETDOWN: return 100;
 case ENETUNREACH: return 101;
 case ENETRESET: return 102;
 case ECONNABORTED: return 103;
 case ECONNRESET: return 104;
 case ENOBUFS: return 105;
 case EISCONN: return 106;
 case ENOTCONN: return 107;
 case ESHUTDOWN: return 108;
 case ETOOMANYREFS: return 109;
 case ETIMEDOUT: return 110;
 case ECONNREFUSED: return 111;
 case EHOSTDOWN: return 112;
 case EHOSTUNREACH: return 113;
 case ELOOP: return 40;
 case ENAMETOOLONG: return 36;
 case EDEADLK: return 35;
 case ENOSYS: return 38;
 default: return host;
 }
}
/* Data calls (Send, Recv, Fcntl) report failures as -1; the Result-style ones as a nonzero guest errno, which is what
   the mod tests for and then reads back through GetLastErrno. */
static int net_fail(void) { net_last_errno=net_errno(errno); return -1; }
static int net_result(void) { return net_last_errno=net_errno(errno); }

/* FreeBSD, and so Horizon, answers getpeername while the socket is still connecting: the peer address is already in
   the protocol control block. macOS only answers once the handshake finished, so a mod that polls GetPeerName to learn
   that a non-blocking Connect completed spins at full speed on the game's own thread for a whole round trip (measured
   on this port: 78,713 calls in 212 ms, a frozen frame). Remember the address handed to Connect and answer from it
   while the connect is still in flight. */
typedef struct { int fd, length, connecting; unsigned char address[128]; } net_peer_t;
static net_peer_t net_peers[8];
static pthread_mutex_t net_peer_lock=PTHREAD_MUTEX_INITIALIZER;
static void net_peer_set(int fd,const void *address,unsigned length,int connecting) {
 if(!address||length>sizeof net_peers[0].address) return;
 pthread_mutex_lock(&net_peer_lock);
 net_peer_t *slot=NULL;
 for(size_t i=0;i<sizeof net_peers/sizeof *net_peers;i++) if(net_peers[i].fd==fd) slot=&net_peers[i];
 if(!slot) for(size_t i=0;i<sizeof net_peers/sizeof *net_peers;i++) if(!net_peers[i].fd) slot=&net_peers[i];
 if(slot){ slot->fd=fd; slot->length=(int)length; slot->connecting=connecting; memcpy(slot->address,address,length); }
 pthread_mutex_unlock(&net_peer_lock);
}
static int net_peer_get(int fd,void *address,unsigned *length) {
 pthread_mutex_lock(&net_peer_lock);
 net_peer_t *slot=NULL;
 for(size_t i=0;i<sizeof net_peers/sizeof *net_peers;i++) if(net_peers[i].fd==fd) slot=&net_peers[i];
 if(slot&&address&&length&&*length>=(unsigned)slot->length){ memcpy(address,slot->address,(size_t)slot->length); *length=(unsigned)slot->length; }
 else slot=NULL;
 pthread_mutex_unlock(&net_peer_lock);
 return slot!=NULL;
}
static void net_peer_clear(int fd) {
 pthread_mutex_lock(&net_peer_lock);
 for(size_t i=0;i<sizeof net_peers/sizeof *net_peers;i++) if(net_peers[i].fd==fd) memset(&net_peers[i],0,sizeof net_peers[i]);
 pthread_mutex_unlock(&net_peer_lock);
}

/* An optional buffer override, in bytes: unset or <=0 keeps the host default. */
static int net_buffer_from_env(const char *name,int fallback) {
 const char *text=getenv(name);
 if(!text||!*text) return fallback;
 int value=atoi(text);
 return value>0?value:0;
}

static int net_initialize(void *pool, unsigned long size, unsigned long extra, int revision) {
 (void)pool; (void)size; (void)extra;
 static int shown;
 if(!shown) { shown=1; fprintf(stderr,"[totk-net] nn::socket initialized (revision %d)\n",revision); }
 return 0;
}

/* The guest's SOCK_NONBLOCK / SOCK_CLOEXEC bits (0x800 / 0x80000, the Linux numbers) have no bearing on the host's
   socket(), which lacks them: they are applied by hand afterwards. */
static int net_socket(int domain, int type, int protocol) {
 int fd=socket(domain==10?AF_INET6:domain, type&0xf, protocol);
 if(fd<0) return net_fail();
 if(type&0x800) fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK);
 if(type&0x80000) fcntl(fd,F_SETFD,FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
 { int one=1; setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof one); }   /* Send must not raise SIGPIPE */
#endif
 /* The mod never calls SetSockOpt, and macOS keeps Nagle on: a 60 Hz stream of small TCP packets then waits for the
    previous segment's ACK before each send, which reads as heavy lag against a server a few RTTs away. Console
    emulators hand game sockets to the host with NODELAY already off; do the same for every stream socket. */
 if((type&0xf)==SOCK_STREAM) { int one=1; setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one); }
 /* The host's default window caps a join at ~2.5 MB/s at this server's 46 ms RTT. Widening it is only headroom: the
    join download stays at 1.3-1.5 MB/s because the mod's own pipeline is the limit (doc 05 §3). */
 if((type&0xf)==SOCK_STREAM) {
  int rcv=net_buffer_from_env("TOTK_NET_RCVBUF",4<<20), snd=net_buffer_from_env("TOTK_NET_SNDBUF",512<<10);
  if(rcv>0) setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&rcv,sizeof rcv);
  if(snd>0) setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&snd,sizeof snd);
 }
 net_last_errno=0;
 if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] Socket(%d,%d,%d) -> %d\n",domain,type,protocol,fd);
 return fd;
}

static int net_connect(int fd, const void *addr, unsigned length) {
 int r=connect(fd,(const struct sockaddr *)addr,(socklen_t)length);
 if(r) {
  if(errno==EINPROGRESS||errno==EALREADY) net_peer_set(fd,addr,length,1);
  if(getenv("TOTK_NET_LOG")) { char text[32]="?"; if(addr&&length>=8) inet_ntop(AF_INET,&((const struct sockaddr_in *)addr)->sin_addr,text,sizeof text);
   fprintf(stderr,"[totk-net] Connect(%d) %s:%u -> errno %d (%d)\n",fd,text,ntohs(((const struct sockaddr_in *)addr)->sin_port),errno,net_errno(errno)); }
  return net_result();
 }
 net_peer_set(fd,addr,length,0);
 net_last_errno=0;
 if(getenv("TOTK_NET_LOG")) { char text[32]="?"; if(addr&&length>=8) inet_ntop(AF_INET,&((const struct sockaddr_in *)addr)->sin_addr,text,sizeof text);
  fprintf(stderr,"[totk-net] Connect(%d) %s:%u -> connected\n",fd,text,ntohs(((const struct sockaddr_in *)addr)->sin_port)); }
 return 0;
}

/* MSG_DONTWAIT, MSG_WAITALL and MSG_NOSIGNAL differ between the two ABIs (the last does not exist on the host; the
   socket's SO_NOSIGPIPE covers it). */
static int net_flags(int guest) {
 int flags=guest&~0x1540;
 if(guest&0x40) flags|=0x80;    /* DONTWAIT */
 if(guest&0x100) flags|=0x40;   /* WAITALL */
 return flags;
}

/* Set TOTK_NET_STATS=1 for a line every five seconds per socket: packets and bytes each way, the longest gap between
   two sends (the mod's own frame pacing) and between two receives (the server's), how long the slowest send blocked
   (a full socket buffer, i.e. the guest is behind), and the bytes still queued for reading. This is how the remaining
   "the other player runs in place and then jumps" is placed: gaps are large at send -> the mod is not feeding us,
   block is large -> we are not draining, gaps are large at receive -> the network or the server. */
typedef struct {
 int fd;
 uint64_t last_report, last_in, last_out;
 unsigned in_pkt, in_bad, out_pkt, out_bad;
 unsigned long long in_bytes, out_bytes;
 double in_gap, out_gap, block;
} net_stat_t;
static net_stat_t net_stats[8];
static pthread_mutex_t net_stat_lock=PTHREAD_MUTEX_INITIALIZER;

static void net_stat_account(int fd,int out,long bytes,double block_ms) {
 if(fd<0||!getenv("TOTK_NET_STATS")) return;
 uint64_t now=runtime_now_ns();
 pthread_mutex_lock(&net_stat_lock);
 net_stat_t *s=NULL;
 size_t i;
 for(i=0;i<sizeof net_stats/sizeof *net_stats;i++) if(net_stats[i].fd==fd) s=&net_stats[i];
 if(!s) for(i=0;i<sizeof net_stats/sizeof *net_stats;i++) if(!net_stats[i].fd) {
  s=&net_stats[i]; memset(s,0,sizeof *s);
  s->fd=fd; s->last_report=now; s->last_in=now; s->last_out=now;
  break;
 }
 if(!s) { pthread_mutex_unlock(&net_stat_lock); return; }
 if(bytes>=0) {
  uint64_t *prev=out?&s->last_out:&s->last_in;
  if(*prev) {
   double gap=(double)(now-*prev)/1e6;
   double *worst=out?&s->out_gap:&s->in_gap;
   if(gap>*worst) *worst=gap;
  }
  *prev=now;
  if(out) { s->out_pkt++; s->out_bytes+=(unsigned long long)bytes; if(block_ms>s->block) s->block=block_ms; }
  else { s->in_pkt++; s->in_bytes+=(unsigned long long)bytes; }
 } else if(out) s->out_bad++;
 else s->in_bad++;
 double span=(double)(now-s->last_report)/1e9;
 if(span>=5.0) {
  int queued=-1, pending=0;
  if(!ioctl(fd,FIONREAD,&pending)) queued=pending;
  fprintf(stderr,"[totk-net-stats] fd %d %4.1fs out %u pkt/%llu B maxgap %.1f ms block %.1f ms%s | in %u pkt/%llu B maxgap %.1f ms, %d B queued in the socket%s\n",
   fd,span,s->out_pkt,s->out_bytes,s->out_gap,s->block,s->out_bad?" (failed)":"",
   s->in_pkt,s->in_bytes,s->in_gap,queued,s->in_bad?" (failed)":"");
  s->last_report=now; s->in_pkt=s->in_bad=s->out_pkt=s->out_bad=0;
  s->in_bytes=s->out_bytes=0; s->in_gap=s->out_gap=s->block=0;
 }
 pthread_mutex_unlock(&net_stat_lock);
}
static void net_stat_clear(int fd) {
 pthread_mutex_lock(&net_stat_lock);
 for(size_t i=0;i<sizeof net_stats/sizeof *net_stats;i++) if(net_stats[i].fd==fd) memset(&net_stats[i],0,sizeof net_stats[i]);
 pthread_mutex_unlock(&net_stat_lock);
}

/* Payload capture for the multiplayer protocol, without a debugger (a paused
   process trips the 2 s encode-stage watchdog).
   TOTK_NET_LOG=2 dumps the head of every completed send; =3 also dumps recv
   (the boot-time content download is several MiB of recv, so it stays off
   unless asked for).
   TOTK_NET_RAW=<path> appends every completed send/recv to a file as
   [u8 direction, u32 little-endian length, bytes] so the framing stays intact
   and the stream can be parsed offline. */
static int net_log_level(void) {
 const char *e=getenv("TOTK_NET_LOG");
 return e?atoi(e):0;
}
static _Atomic long net_dump_budget=16777216;   /* stop after ~16 MiB of payload */
static void net_dump(const char *dir,int fd,const void *buffer,long n,double t_ms) {
 if(n<=0||net_log_level()<2) return;
 if(atomic_fetch_sub(&net_dump_budget,n+64)<=0) {
  static _Atomic int told;
  if(!atomic_exchange(&told,1)) fprintf(stderr,"[totk-net-dump] payload dump budget exhausted; further payloads are not logged\n");
  return;
 }
 const unsigned char *p=(const unsigned char *)buffer;
 long lim=n<256?n:256;
 static const char hx[]="0123456789abcdef";
 char hex[3*256+1],txt[256+1];
 int o=0,t=0;
 for(long i=0;i<lim;i++) {
  hex[o++]=hx[p[i]>>4]; hex[o++]=hx[p[i]&15]; hex[o++]=' ';
  txt[t++]=(p[i]>=0x20&&p[i]<0x7f)?(char)p[i]:'.';
 }
 hex[o]=0; txt[t]=0;
 fprintf(stderr,"[totk-net-dump] %s fd %d len %ld t %.3f%s hex %s\n[totk-net-dump] %s fd %d txt %s\n",
   dir,fd,n,t_ms/1000.0,n>lim?" (head)":"",hex,dir,fd,txt);
}
static FILE *net_raw_fp;
static _Atomic int net_raw_tried;
static _Atomic long net_raw_budget=134217728;   /* cap the capture at 128 MiB */
static _Atomic long net_raw_base_ms=-1;
static void net_raw(const char *dir,const void *buffer,long n,double t_ms) {
 if(n<=0) return;
 if(!atomic_load(&net_raw_tried)&&!atomic_exchange(&net_raw_tried,1)) {
  const char *p=getenv("TOTK_NET_RAW");
  if(p&&*p) net_raw_fp=fopen(p,"wb");
 }
 if(!net_raw_fp) return;
 if(atomic_fetch_sub(&net_raw_budget,n+16)<=0) return;
 unsigned char hdr[9];
 hdr[0]=dir[0]=='o'?1:0;
 uint32_t len=(uint32_t)n;
 memcpy(hdr+1,&len,4);
 long base=atomic_load(&net_raw_base_ms);
 if(base<0) atomic_store(&net_raw_base_ms,(long)t_ms);
 base=atomic_load(&net_raw_base_ms);
 uint32_t rel=(uint32_t)((long)t_ms-base);
 memcpy(hdr+5,&rel,4);
 flockfile(net_raw_fp);
 fwrite(hdr,1,9,net_raw_fp);
 fwrite(buffer,1,(size_t)n,net_raw_fp);
 fflush(net_raw_fp);
 funlockfile(net_raw_fp);
}
static long net_send(int fd, const void *buffer, unsigned long length, int flags) {
 uint64_t began=runtime_now_ns();
 ssize_t r=send(fd,buffer,(size_t)length,net_flags(flags));
 double blocked=r<0?0.0:(double)(runtime_now_ns()-began)/1e6;
 net_stat_account(fd,1,r<0?-1:(long)r,blocked);
 if(net_log_level()) fprintf(stderr,"[totk-net] Send(%d,%lu) -> %ld\n",fd,length,r<0?(long)net_errno(errno):(long)r);
 if(r>0) {
  double t_ms=(double)began/1e6;
  net_dump("out",fd,buffer,(long)r,t_ms);
  net_raw("out",buffer,(long)r,t_ms);
 }
 return r<0?net_fail():(net_last_errno=0,(long)r);
}
static long net_recv(int fd, void *buffer, unsigned long length, int flags) {
 ssize_t r=recv(fd,buffer,(size_t)length,net_flags(flags));
 net_stat_account(fd,0,r<0?-1:(long)r,0.0);
 if(net_log_level()) fprintf(stderr,"[totk-net] Recv(%d,%lu) -> %ld\n",fd,length,r<0?(long)net_errno(errno):(long)r);
 if(r>0) {
  double t_ms=(double)runtime_now_ns()/1e6;
  if(net_log_level()>=3) net_dump("in",fd,buffer,(long)r,t_ms);
  net_raw("in",buffer,(long)r,t_ms);
 }
 return r<0?net_fail():(net_last_errno=0,(long)r);
}

static int net_close(int fd) {
 net_peer_clear(fd);
 net_stat_clear(fd);
 if(close(fd)) return net_result();
 net_last_errno=0;
 return 0;
}

static int net_flags_to_host(int guest) {
 int flags=guest&~(0x400|0x800);
 if(guest&0x800) flags|=O_NONBLOCK;
 if(guest&0x400) flags|=O_APPEND;
 return flags;
}
static int net_flags_to_guest(int host) {
 int flags=host&~(O_APPEND|O_NONBLOCK);
 if(host&O_NONBLOCK) flags|=0x800;
 if(host&O_APPEND) flags|=0x400;
 return flags;
}
/* Fcntl is variadic in the SDK, but the mod passes an int (F_SETFL's flags); GETFL ignores it. */
static int net_fcntl(int fd, int cmd, int arg) {
 int r;
 if(cmd==F_SETFL) r=fcntl(fd,F_SETFL,net_flags_to_host(arg));
 else if(cmd==F_GETFL) { r=fcntl(fd,F_GETFL,0); if(r>=0) r=net_flags_to_guest(r); }
 else r=fcntl(fd,cmd,arg);
 if(r<0) return net_fail();
 net_last_errno=0;
 if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] Fcntl(%d,%d,%#x) -> %d\n",fd,cmd,arg,r);
 return r;
}

/* SO_ERROR comes back as a host errno in the value. */
static int net_get_sockopt(int fd, int level, int option, void *value, unsigned *length) {
 socklen_t len=length?*length:0;
 int r=getsockopt(fd,level,option,value,&len);
 if(r) { if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] GetSockOpt(%d,%#x,%#x) -> %d\n",fd,level,option,net_errno(errno)); return net_result(); }
 if(length) *length=len;
 if(level==0xffff&&option==0x1007&&value&&len>=4) *(int *)value=net_errno(*(int *)value);
 if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] GetSockOpt(%d,%#x,%#x) -> %d\n",fd,level,option,value&&len>=4?*(int *)value:0);
 net_last_errno=0;
 return 0;
}

/* The guest's sockaddr is the BSD one (sin_len first), the same as the host's, so the result is passed straight back. */
static int net_get_peer_name(int fd, void *address, unsigned *length) {
 socklen_t len=length?*length:0;
 int r=getpeername(fd,(struct sockaddr *)address,&len);
 if(r) {
  int saved=errno, pending=0; socklen_t plen=sizeof pending;
  if(saved==ENOTCONN&&address&&length&&!getsockopt(fd,SOL_SOCKET,SO_ERROR,&pending,&plen)&&pending==0&&net_peer_get(fd,address,length)) {
   if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] GetPeerName(%d) -> connecting\n",fd);
   net_last_errno=0;
   return 0;
  }
  errno=saved;
  if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] GetPeerName(%d) -> %d\n",fd,net_errno(errno));
  return net_result();
 }
 if(length) *length=len;
 if(getenv("TOTK_NET_LOG")) fprintf(stderr,"[totk-net] GetPeerName(%d) -> connected\n",fd);
 net_last_errno=0;
 return 0;
}

static int net_get_last_errno(void) { return net_last_errno; }

static int net_inet_aton(const char *text, void *address) {
 int r=inet_aton(text,(struct in_addr *)address);
 return r?1:(net_fail(),0);
}
static int net_inet_pton(int family, const char *text, void *address) {
 int r=inet_pton(family==10?AF_INET6:family,text,address);
 return r<0?net_fail():r;
}
static unsigned short net_inet_htons(unsigned short value) { return htons(value); }

void *runtime_net_override(const char *name) {
 static const struct { const char *name; void *fn; } entries[]={
  {"_ZN2nn6socket10InitializeEPvmmi",(void *)net_initialize},
  {"_ZN2nn6socket6SocketEiii",(void *)net_socket},
  {"_ZN2nn6socket7ConnectEiPK8sockaddrj",(void *)net_connect},
  {"_ZN2nn6socket4SendEiPKvmi",(void *)net_send},
  {"_ZN2nn6socket4RecvEiPvmi",(void *)net_recv},
  {"_ZN2nn6socket5CloseEi",(void *)net_close},
  {"_ZN2nn6socket5FcntlEiiz",(void *)net_fcntl},
  {"_ZN2nn6socket10GetSockOptEiiiPvPj",(void *)net_get_sockopt},
  {"_ZN2nn6socket11GetPeerNameEiP8sockaddrPj",(void *)net_get_peer_name},
  {"_ZN2nn6socket12GetLastErrnoEv",(void *)net_get_last_errno},
  {"_ZN2nn6socket8InetAtonEPKcP7in_addr",(void *)net_inet_aton},
  {"_ZN2nn6socket8InetPtonEiPKcPv",(void *)net_inet_pton},
  {"_ZN2nn6socket9InetHtonsEt",(void *)net_inet_htons}};
 for(size_t i=0;i<sizeof entries/sizeof *entries;i++) if(!strcmp(name,entries[i].name)) return entries[i].fn;
 return NULL;
}
