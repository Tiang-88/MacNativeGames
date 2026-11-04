/* Offline local user identity. Handles are validated; profile survives restarts. */
#include "runtime.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
typedef struct{uint64_t lo,hi;} Uid;
typedef struct{Uid uid;uint64_t token;} UserHandle;
static Uid local;
/* Canaries around the lock: an intermittent hang showed this mutex's internal words changed while nobody held it. */
#define GUARD 0x6163636f756e7447ULL
static struct{uint64_t pre[8];pthread_mutex_t m;uint64_t post[8];} guarded={{GUARD,GUARD,GUARD,GUARD,GUARD,GUARD,GUARD,GUARD},PTHREAD_MUTEX_INITIALIZER,{GUARD,GUARD,GUARD,GUARD,GUARD,GUARD,GUARD,GUARD}};
#define lock_ guarded.m
static _Atomic(uint64_t) lock_owner;
static void check_guard(void){for(unsigned i=0;i<8;i++)if(guarded.pre[i]!=GUARD||guarded.post[i]!=GUARD){fprintf(stderr,"[totk] account lock guard %s[%u] overwritten: %#llx\n",guarded.pre[i]!=GUARD?"pre":"post",i,(unsigned long long)(guarded.pre[i]!=GUARD?guarded.pre[i]:guarded.post[i]));runtime_fail("host memory near the account lock was overwritten");}}
static void lock_acquire(void){check_guard();pthread_mutex_lock(&lock_);uint64_t t;pthread_threadid_np(NULL,&t);lock_owner=t;}
static void lock_release(void){lock_owner=0;pthread_mutex_unlock(&lock_);check_guard();}
uint64_t runtime_account_lock_owner(void){const uint32_t *w=(const uint32_t *)(const void *)&guarded;fprintf(stderr,"[totk-dump] account lock with guards @%p:",(void *)&guarded);for(unsigned i=0;i<sizeof(guarded)/4;i++)fprintf(stderr," %08x",w[i]);fputc('\n',stderr);return lock_owner;}
static uint64_t tokens[64],nextToken=1;
static uint32_t initialize(void){
 if(getenv("TOTK_ACC_TRACE"))fprintf(stderr,"[acc] initialize (host) on thread %llu\n",(unsigned long long)pthread_mach_thread_np(pthread_self()));
 lock_acquire();if(local.lo||local.hi){lock_release();return 0;}
 const char *dir=getenv("TOTK_PROFILE_DIR");if(!dir)dir="user-data";
 if(mkdir(dir,0700)&&errno!=EEXIST)runtime_fail("create local account directory");
 char path[4096];if(snprintf(path,sizeof(path),"%s/account.uid",dir)>=(int)sizeof(path))runtime_fail("local account path length");
 int fd=open(path,O_RDWR|O_CREAT|O_NOFOLLOW,0600);if(fd<0||flock(fd,LOCK_EX))runtime_fail("open local account identity");
 struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode))runtime_fail("invalid local account identity file");
 if(st.st_size==0){do{arc4random_buf(&local,sizeof(local));}while(!local.lo&&!local.hi);if(write(fd,&local,sizeof(local))!=sizeof(local)||fsync(fd))runtime_fail("persist local account identity");}
 else if(st.st_size!=sizeof(local)||pread(fd,&local,sizeof(local),0)!=sizeof(local)||(!local.lo&&!local.hi))runtime_fail("corrupt local account identity");
 close(fd);lock_release();fprintf(stderr,"[totk] persistent local account initialized\n");return 0;
}
static bool same(const Uid *uid){return uid&&uid->lo==local.lo&&uid->hi==local.hi;}
static bool valid(const UserHandle *handle){if(!handle||!same(&handle->uid))return false;for(unsigned i=0;i<64;i++)if(tokens[i]&&tokens[i]==handle->token)return true;return false;}
static unsigned preselected(UserHandle *out){if(!out)runtime_fail("account null user handle");initialize();lock_acquire();for(unsigned i=0;i<64;i++)if(!tokens[i]){tokens[i]=nextToken++;*out=(UserHandle){local,tokens[i]};lock_release();return 1;}lock_release();return 0;}
static uint32_t user_id(Uid *out,const UserHandle *handle){lock_acquire();bool ok=out&&valid(handle);if(ok)*out=local;lock_release();return ok?0:0x7c67;}
static void close_user(const UserHandle *handle){lock_acquire();if(!valid(handle))runtime_fail("invalid local account handle close");for(unsigned i=0;i<64;i++)if(tokens[i]==handle->token){tokens[i]=0;break;}lock_release();}
static uint32_t existence(unsigned char *out,const Uid *uid){if(!out||!uid)return 0x7c67;initialize();*out=same(uid);return 0;}
/* The multiplayer mod builds its login packet from the last opened user: uid, nickname and profile picture. There is no
   picture here, and the packet format has a marker for that (a zero size), so report size 0 instead of an image. */
static uint32_t last_opened(Uid *out){if(!out)return 0x7c67;initialize();*out=local;return 0;}
static uint32_t profile_image(uint64_t *size,void *buffer,uint64_t buffer_size,const Uid *uid){
 (void)buffer;(void)buffer_size;if(!size)return 0x7c67;initialize();if(!same(uid))return 0x7c67;*size=0;return 0;}
/* The multiplayer mod (subsdk4) sends this nickname in its login packet, and the game shows it as the player name.
   It is set by the player: TOTK_PLAYER_NAME, or <profile>/sdcard/TOTKOnlineName.txt. Nothing is guessed from the host
   account; without a setting the name stays "Local", as before. A name is at most 32 UTF-8 bytes (the Nintendo Nickname
   field is 33 bytes with its terminator) and never ends in half of a multi-byte character, which the console's own
   nickname rules also forbid. */
static char player_name[33];
static const char *player_name_source;
static const char *profile_dir(void){const char *dir=getenv("TOTK_PROFILE_DIR");return (dir&&*dir)?dir:"user-data";}
static void name_from_text(const char *text,const char *source){
 if(!text)return;
 while(*text==' '||*text=='\t')text++;
 size_t n=strlen(text);
 for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)text[i];if(c<0x20||c==0x7f){n=i;break;}}   /* first line only */
 while(n&&(text[n-1]==' '||text[n-1]=='\t'))n--;
 size_t keep=n;if(keep>32){keep=32;while(keep&&((unsigned char)text[keep]&0xc0)==0x80)keep--;}
 if(!keep)return;
 memcpy(player_name,text,keep);memset(player_name+keep,0,sizeof(player_name)-keep);player_name_source=source;
}
static void read_name_file(void){
 char path[4096];if(snprintf(path,sizeof(path),"%s/sdcard/TOTKOnlineName.txt",profile_dir())>=(int)sizeof(path))return;
 int fd=open(path,O_RDONLY|O_NOFOLLOW);if(fd<0)return;
 char text[512];ssize_t n=read(fd,text,sizeof(text)-1);close(fd);
 if(n<=0)return;text[n]=0;name_from_text(text,"sdcard/TOTKOnlineName.txt");
}
static pthread_once_t name_once=PTHREAD_ONCE_INIT;
static void resolve_player_name(void){
 name_from_text(getenv("TOTK_PLAYER_NAME"),"TOTK_PLAYER_NAME");
 if(!player_name[0])read_name_file();
 if(!player_name[0]){memcpy(player_name,"Local",6);player_name_source="default";}
 if(!strcmp(player_name_source,"default"))
  fprintf(stderr,"[totk] player nickname: \"%s\" (default; set one in %s/sdcard/TOTKOnlineName.txt or TOTK_PLAYER_NAME)\n",player_name,profile_dir());
 else fprintf(stderr,"[totk] player nickname: \"%s\" (%s)\n",player_name,player_name_source);
}
static const char *player_nickname(void){pthread_once(&name_once,resolve_player_name);return player_name;}
static uint32_t nickname(char *out,const Uid *uid){initialize();if(!out||!same(uid))return 0x7c67;memset(out,0,33);strncpy(out,player_nickname(),32);return 0;}
void runtime_account_uid(uint64_t out[2]){initialize();out[0]=local.lo;out[1]=local.hi;}
#ifdef GAME_BOTW
/* SDK 7 (Breath of the Wild 1.6.0, botw.md) opens the preselected user with the aborting variant and lists the users. */
static void open_preselected(UserHandle *out){if(!preselected(out))runtime_fail("open preselected user");}
static uint32_t list_users(int *count,Uid *out,int max){initialize();if(!count||(max>0&&!out))return 0x7c67;*count=0;if(max>0){out[0]=local;*count=1;}return 0;}
/* SDK 20.5 (1.9.0) takes the users the system opened at launch instead: the one local user. */
static uint32_t pop_open_users(int *count,UserHandle *out,int max){if(!count||(max>0&&!out))return 0x7c67;*count=0;if(max>0){open_preselected(&out[0]);*count=1;}return 0;}
#endif
void *runtime_account_override(const char *name){
 static const struct{const char *name;void *fn;} entries[]={
 {"_ZN2nn7account10InitializeEv",initialize},{"_ZN2nn7account22TryOpenPreselectedUserEPNS0_10UserHandleE",preselected},
 {"_ZN2nn7account9CloseUserERKNS0_10UserHandleE",close_user},{"_ZN2nn7account9GetUserIdEPNS0_3UidERKNS0_10UserHandleE",user_id},
 {"_ZN2nn7account16GetUserExistenceEPbRKNS0_3UidE",existence},{"_ZN2nn7account11GetNicknameEPNS0_8NicknameERKNS0_3UidE",nickname}
 ,{"_ZN2nn7account17GetLastOpenedUserEPNS0_3UidE",last_opened},{"_ZN2nn7account16LoadProfileImageEPmPvmRKNS0_3UidE",profile_image}
#ifdef GAME_BOTW
 ,{"_ZN2nn7account19OpenPreselectedUserEPNS0_10UserHandleE",open_preselected},{"_ZN2nn7account12ListAllUsersEPiPNS0_3UidEi",list_users}
 ,{"_ZN2nn7account12PopOpenUsersEPiPNS0_10UserHandleEi",pop_open_users}
#endif
 };
 for(unsigned i=0;i<sizeof(entries)/sizeof(*entries);i++)if(!strcmp(name,entries[i].name))return entries[i].fn;return NULL;
}
