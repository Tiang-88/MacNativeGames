/* Native ARM64 module loader. Guest images and generated metadata stay local. */
#include "runtime.h"
#include "totk_ui_lang.h"
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <mach/mach.h>
#include "mach_vm_compat.h"
#include <sys/ucontext.h>
#include "game_data.h"
#include "game_patches.h"
#include "game_version.h"
#include <errno.h>
/* A player mod build (docs/mods.md) loads the synthetic rtld and the player's subsdk modules as real modules, in this
   order; the tables file of the build and the executable must agree on it. */
#ifdef TOTK_MOD_SUBSDK3
#  define MOD_COUNT 6
#  define MOD_ORDER {"rtld","main","subsdk0","subsdk1","subsdk3","sdk"}
#elif defined(TOTK_MOD_SUBSDK1)
#  define MOD_COUNT 5
#  define MOD_ORDER {"rtld","main","subsdk0","subsdk1","sdk"}
#endif
#ifdef MOD_COUNT
#  define NM MOD_COUNT
#else
#  define NM 3
#  define MOD_ORDER {"main","subsdk0","sdk"}
#endif
pthread_key_t runtime_keys[8];
static uint64_t timer_calls, svc_calls;
_Noreturn void runtime_fail(const char *message) { fprintf(stderr,"[totk] FAIL: %s\n",message); exit(1); }
static void need(bool c,const char *m) { if(!c) runtime_fail(m); }
/* The modules' tables (layout, symbols, relocations, gates) that scripts/prepare_runtime.py derives from the player's
   verified rewrites: runtime-tables.bin in the game data folder (game_data.h), mapped at start. Nothing of them is compiled
   in, so this program can be replaced in an app on its own. Every count and offset is checked before use; each module's
   SHA-256 in the file binds it to its image as before (map_module). */
static Module modules[NM];
static unsigned main_index;   /* which of them is main: found by name in load_tables */
#define MAIN_MODULE_INDEX main_index
static uint64_t probe_plt,probe_slot;   /* main's original PLT stub of nn::os::GetSystemTick and its GOT slot (probe) */
#define PROBE_PLT probe_plt
#define PROBE_SLOT probe_slot
typedef struct {char magic[8],version[8];uint32_t nmodule,format;uint64_t probe_plt,probe_slot,strings,strings_size,size;} TablesHeader;
typedef struct {char name[16],digest[72];uint64_t file_size,text_end,ro_off,data_off,patch_off,key_off,init,ctor_flag,init_array,init_size,symbols,relocs,gates;uint32_t nsym,nreloc,ngate,reserved;} TablesModule;
typedef struct {uint64_t value,size;uint32_t name;uint8_t defined,binding,type,reserved;} TablesSymbol;
_Static_assert(sizeof(TablesHeader)==64&&sizeof(TablesModule)==208&&sizeof(TablesSymbol)==24&&sizeof(Reloc)==24&&sizeof(Gate)==24,"runtime-tables.bin layout");
static int gate_order(const void *a,const void *b){uint64_t x=((const Gate *)a)->ret,y=((const Gate *)b)->ret;return (x>y)-(x<y);}
static int tables_range(uint64_t size,uint64_t off,uint64_t count,uint64_t each){return off%8==0&&off<=size&&count<=(size-off)/each;}
static void load_tables(void) {
 char path[4096];runtime_game_data_path("runtime-tables.bin",path,sizeof path);
 int fd=open(path,O_RDONLY);
 if(fd<0){fprintf(stderr,"[totk] %s: %s\n",path,strerror(errno));runtime_fail("game tables missing (build_app.py writes them into the app; update_runtime.py --work adds them to an older app)");}
 struct stat st;need(fstat(fd,&st)==0&&st.st_size>=(off_t)sizeof(TablesHeader)&&st.st_size<(1LL<<30),"game tables size");
 const uint8_t *b=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);close(fd);need(b!=MAP_FAILED,"map game tables");
 const TablesHeader *h=(const void *)b;uint64_t size=(uint64_t)st.st_size;
 need(!memcmp(h->magic,"TOTKTAB1",8)&&h->format==1&&h->size==size,"game tables format");
 if(strncmp(h->version,TOTK_GAME_DATA_DIR,sizeof h->version)){fprintf(stderr,"[totk] game tables are for %.8s, this program for " TOTK_GAME_DATA_DIR "\n",h->version);runtime_fail("game tables of another game version");}
 need(h->nmodule==NM&&tables_range(size,sizeof *h,NM,sizeof(TablesModule))&&h->strings_size>0&&tables_range(size,h->strings,h->strings_size,1)&&!b[h->strings+h->strings_size-1],"game tables layout");
 const char *strings=(const char *)b+h->strings;static const char *const names[NM]=MOD_ORDER;
 for(unsigned i=0;i<NM;i++){
  const TablesModule *t=(const TablesModule *)(b+sizeof *h)+i;Module *m=&modules[i];
  need(!t->name[sizeof t->name-1]&&!strcmp(t->name,names[i])&&strnlen(t->digest,sizeof t->digest)==64,"game tables module");
  need(tables_range(size,t->symbols,t->nsym,sizeof(TablesSymbol))&&tables_range(size,t->relocs,t->nreloc,sizeof(Reloc))&&tables_range(size,t->gates,t->ngate,sizeof(Gate)),"game tables bounds");
  *m=(Module){.name=t->name,.digest=t->digest,.file_size=t->file_size,.text_end=t->text_end,.ro_off=t->ro_off,.data_off=t->data_off,.patch_off=t->patch_off,.key_off=t->key_off,
   .init=t->init,.ctor_flag=t->ctor_flag,.init_array=t->init_array,.init_size=t->init_size,.nsym=t->nsym,.relocs=(const Reloc *)(b+t->relocs),.nreloc=t->nreloc,
   .gates=(const Gate *)(b+t->gates),.ngate=t->ngate};
  Symbol *symbols=calloc(t->nsym?t->nsym:1,sizeof *symbols);need(symbols!=NULL,"game tables memory");
  const TablesSymbol *ts=(const TablesSymbol *)(b+t->symbols);
  for(unsigned k=0;k<t->nsym;k++){need(ts[k].name<h->strings_size,"game tables symbol name");
   symbols[k]=(Symbol){.name=strings+ts[k].name,.value=ts[k].value,.size=ts[k].size,.defined=ts[k].defined,.binding=ts[k].binding,.type=ts[k].type};}
  m->symbols=symbols;
  /* runtime_dispatch finds a gate by binary search: sorted here too, so tables written before prepare_runtime.py sorted them work. */
  Gate *gates=malloc((t->ngate?t->ngate:1)*sizeof *gates);need(gates!=NULL,"game tables memory");
  memcpy(gates,b+t->gates,t->ngate*sizeof *gates);qsort(gates,t->ngate,sizeof *gates,gate_order);
  for(unsigned k=1;k<t->ngate;k++)need(gates[k].ret>gates[k-1].ret,"game tables: two gates with one return address");
  m->gates=gates;
 }
 int main_at=-1;for(unsigned i=0;i<NM;i++)if(!strcmp(modules[i].name,"main"))main_at=(int)i;
 need(main_at>=0,"game tables: no main module");main_index=(unsigned)main_at;
 probe_plt=h->probe_plt;probe_slot=h->probe_slot;
 uint64_t nreloc=0;for(unsigned i=0;i<NM;i++)nreloc+=modules[i].nreloc;
 fprintf(stderr,"[totk] game tables %s: %u modules, %llu relocations\n",path,NM,(unsigned long long)nreloc);
}
static size_t page_up(size_t x) { return (x+0x3fff)&~(size_t)0x3fff; }
static unsigned hash_name(const char *s) { unsigned h=2166136261u; for(;*s;s++)h=(h^(uint8_t)*s)*16777619u;return h; }
static void make_hash(Module *m) {
 unsigned cap=16;while(cap<m->nsym*2)cap<<=1;
 m->hash=calloc(cap,sizeof(unsigned));need(m->hash!=NULL,"symbol hash allocation");m->hash_mask=cap-1;
 for(unsigned i=1;i<m->nsym;i++)if(m->symbols[i].defined) {
  const char *s=m->symbols[i].name;unsigned p=hash_name(s)&m->hash_mask;
  while(m->hash[p]&&strcmp(s,m->symbols[m->hash[p]].name))p=(p+1)&m->hash_mask;
  if(!m->hash[p])m->hash[p]=i;
 }
}
static void *module_symbol(Module *m,const char *name) {
 unsigned p=hash_name(name)&m->hash_mask;
 while(m->hash[p]) {
  const Symbol *s=&m->symbols[m->hash[p]];
  if(!strcmp(name,s->name))return s->value<m->key_off?m->base+s->value:NULL;
  p=(p+1)&m->hash_mask;
 }
 return NULL;
}
void *runtime_symbol(const char *name) {
 for(unsigned i=0;i<NM;i++){void *p=module_symbol(&modules[i],name);if(p)return p;}
 return NULL;
}
uint8_t *runtime_module_base(const char *name){for(unsigned i=0;i<NM;i++)if(!strcmp(modules[i].name,name))return modules[i].base;return NULL;}
/* Is pc in a module's original code (not in the patch area, where rewritten windows and gates are)? Called from a signal
   handler (threads.c, asynchronous preemption, both games): only reads the module table. */
int runtime_guest_code_pc(uint64_t pc){for(unsigned i=0;i<NM;i++){uint64_t b=(uintptr_t)modules[i].base;if(b&&pc>=b&&pc-b<modules[i].text_end)return 1;}return 0;}
/* RELRO in newer SDKs protects relocated data after linking. Keep permissions at
 * the guest's 4 KiB granularity. A Darwin 16 KiB page receives the union of its
 * four guest permissions, so protecting an edge never removes access from an
 * adjacent writable object. Whole interior pages are actually made read-only. */
static pthread_mutex_t module_permission_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned char *module_permissions[NM];
static unsigned module_page_permission(unsigned i,uint64_t off){
 Module *m=&modules[i];
 if(off<m->data_off)return off<page_up(m->text_end)?5:1;
 if(off>=m->key_off)return off>=m->patch_off?5:1;
 return module_permissions[i]?module_permissions[i][(off-m->data_off)/4096]:3;
}
uint64_t runtime_module_permission(uint64_t address,uint64_t size,unsigned permission){
 if(address&4095)return 0xcc01;
 if(!size||(size&4095))return 0xca01;
 if(permission!=0&&permission!=1&&permission!=3)return 0xd801;
 for(unsigned i=0;i<NM;i++){
  Module *m=&modules[i];uint64_t base=(uintptr_t)m->base;
  if(address<base||address-base<m->data_off||address-base>=m->key_off||size>m->key_off-(address-base))continue;
  uint64_t off=address-base;
  pthread_mutex_lock(&module_permission_lock);
  if(!module_permissions[i]){size_t count=(m->key_off-m->data_off+4095)/4096;module_permissions[i]=malloc(count);need(module_permissions[i]!=NULL,"module permission table");memset(module_permissions[i],3,count);}
  for(uint64_t p=0;p<size/4096;p++)if(module_permissions[i][(off-m->data_off)/4096+p]&16){pthread_mutex_unlock(&module_permission_lock);return 0xd401;}
  memset(module_permissions[i]+(off-m->data_off)/4096,permission,size/4096);
  uint64_t lo=off&~0x3fffULL,hi=page_up(off+size);
  for(uint64_t page=lo;page<hi;page+=0x4000){
   unsigned combined=0;for(unsigned p=0;p<4;p++)combined|=module_page_permission(i,page+p*4096);
   int prot=(combined&1?PROT_READ:0)|(combined&2?PROT_WRITE:0);
   need(!(combined&4),"module permission overlaps executable page");
   need(mprotect(m->base+page,0x4000,prot)==0,"module data permission");
  }
  pthread_mutex_unlock(&module_permission_lock);
  fprintf(stderr,"[totk] %s data permission +%#llx size=%#llx perm=%u\n",m->name,(unsigned long long)off,(unsigned long long)size,permission);
  return 0;
 }
 return 0xd401;
}
uint64_t runtime_module_lock_permission(uint64_t address,uint64_t size,unsigned mask,unsigned attribute){
 if(address&4095)return 0xcc01;
 if(!size||(size&4095))return 0xca01;
 /* The only module attribute used by the SDK is the irreversible RELRO lock. */
 if(mask!=16||attribute!=16)return 0xd801;
 for(unsigned i=0;i<NM;i++){
  Module *m=&modules[i];uint64_t start=(uintptr_t)m->base;
  if(address<start||address-start<m->data_off||address-start>=m->key_off||size>m->key_off-(address-start))continue;
  pthread_mutex_lock(&module_permission_lock);
  if(!module_permissions[i]){size_t count=(m->key_off-m->data_off+4095)/4096;module_permissions[i]=malloc(count);need(module_permissions[i]!=NULL,"module attribute table");memset(module_permissions[i],3,count);}
  size_t first=(address-start-m->data_off)/4096;
  for(uint64_t p=0;p<size/4096;p++)module_permissions[i][first+p]|=16;
  pthread_mutex_unlock(&module_permission_lock);return 0;
 }
 return 0xd401;
}
int runtime_module_query(uint64_t address,uint64_t *base,uint64_t *size,unsigned *state,unsigned *permission,unsigned *attribute){
 for(unsigned i=0;i<NM;i++){
  Module *m=&modules[i];uint64_t start=(uintptr_t)m->base;
  if(address<start||address-start>=m->key_off)continue;
  uint64_t off=(address-start)&~4095ULL,lo=off,hi=off+4096;
  pthread_mutex_lock(&module_permission_lock);
  unsigned perm=module_page_permission(i,off);int data=off>=m->data_off;
  uint64_t limit=data?m->data_off:0,end=data?m->key_off:m->data_off;
  while(lo>limit&&module_page_permission(i,lo-4096)==perm)lo-=4096;
  while(hi<end&&module_page_permission(i,hi)==perm)hi+=4096;
  pthread_mutex_unlock(&module_permission_lock);
  *base=start+lo;*size=hi-lo;*state=data?4:3;*permission=perm&7;*attribute=perm&16;return 1;
 }
 return 0;
}
int runtime_module_contains(uint64_t address,uint64_t size){
 for(unsigned i=0;i<NM;i++){uint64_t start=(uintptr_t)modules[i].base;
  if(address>=start&&address-start<=modules[i].size&&size<=modules[i].size-(address-start))return 1;}
 return 0;
}
#ifdef TOTK_MOD_SUBSDK1
/* Regions of the fixed module arena, including the key page, the writable gap
   before the patch area, the patch area and main's private page. Addresses in
   the gaps between modules and after the last one are free. */
int runtime_arena_query(uint64_t address,uint64_t *base,uint64_t *size,unsigned *state,unsigned *permission,unsigned *attribute) {
 uint8_t *start=runtime_module_arena_base(),*end=runtime_module_arena_end();
 if(!start||address<(uintptr_t)start||address>=(uintptr_t)end)return 0;
 uint64_t cursor=(uintptr_t)start;
 for(unsigned i=0;i<NM;i++) {
  Module *m=&modules[i];uint64_t b=(uintptr_t)m->base,image=(uint64_t)page_up(m->file_size);
  if(address<b){if(b>cursor&&address>=cursor){*base=cursor;*size=b-cursor;*state=0;*permission=0;*attribute=0;return 1;}continue;}
  if(address<b+m->size){
   uint64_t off=address-b;
   if(off<m->key_off)return runtime_module_query(address,base,size,state,permission,attribute);
   if(off<m->key_off+0x4000){*base=b+m->key_off;*size=0x4000;*state=4;*permission=1;*attribute=0;return 1;}
   if(off<m->patch_off){*base=b+m->key_off+0x4000;*size=m->patch_off-(m->key_off+0x4000);*state=4;*permission=3;*attribute=0;return 1;}
   if(off<image){*base=b+m->patch_off;*size=image-m->patch_off;*state=4;*permission=5;*attribute=0;return 1;}
   *base=b+image;*size=m->size-image;*state=4;*permission=3;*attribute=0;return 1;
  }
  cursor=b+m->size;
 }
 runtime_fail("arena address outside every module");return 0;
}
#endif
void runtime_describe_address(uint64_t a,char *out,size_t n){for(unsigned i=0;i<NM;i++)if(a>=(uintptr_t)modules[i].base&&a<(uintptr_t)modules[i].base+modules[i].size){snprintf(out,n,"%s+0x%llx",modules[i].name,(unsigned long long)(a-(uintptr_t)modules[i].base));return;}Dl_info di;if(dladdr((void *)(uintptr_t)a,&di)&&di.dli_sname){snprintf(out,n,"%s+0x%llx",di.dli_sname,(unsigned long long)(a-(uintptr_t)di.dli_saddr));return;}snprintf(out,n,"0x%llx",(unsigned long long)a);}
/* Guest frame-pointer chain. Guest threads run on guest stacks (not the host pthread stack), so frames are read with
   mach_vm_read_overwrite (a bad pointer ends the walk instead of faulting); the chain must grow upwards. */
void runtime_trace_guest(uint64_t fp,uint64_t lr) {
 for(unsigned n=0;n<16;n++) {
  for(unsigned i=0;i<NM;i++)if(lr>=(uintptr_t)modules[i].base&&lr<(uintptr_t)modules[i].base+modules[i].size)fprintf(stderr,"[totk] caller %s+0x%llx\n",modules[i].name,(unsigned long long)(lr-(uintptr_t)modules[i].base));
  if(!fp||fp%8)break;uint64_t f[2];mach_vm_size_t got=0;
  if(mach_vm_read_overwrite(mach_task_self(),fp,16,(uintptr_t)f,&got)!=KERN_SUCCESS||got!=16)break;
  lr=f[1];if(f[0]<=fp||f[0]-fp>(64u<<20))break;fp=f[0];
 }
}
static int safe_read64(uint64_t a,uint64_t *v){mach_vm_size_t got=0;return mach_vm_read_overwrite(mach_task_self(),a,8,(uintptr_t)v,&got)==KERN_SUCCESS&&got==8;}
void runtime_dump_break_state(uint64_t fp,uint64_t lr) {
 uint8_t *sdk=NULL;for(unsigned i=0;i<NM;i++)if(!strcmp(modules[i].name,"sdk"))sdk=modules[i].base;
 if(sdk){uint64_t g=0;memcpy(&g,sdk+0xd16bb8,8);fprintf(stderr,"[totk] sdk=%p ThreadManagerImpl=%#llx\n",(void *)sdk,(unsigned long long)g);
  if(g)for(unsigned i=0;i<48;i++){uint64_t v=0;if(safe_read64(g+0x80+i*8,&v))fprintf(stderr,"[totk] tmi+%03x=%#llx\n",0x80+i*8,(unsigned long long)v);}
 }
 for(unsigned n=0;n<24&&fp&&fp%8==0;n++){
  char where[96];runtime_describe_address(lr,where,sizeof where);
  uint64_t regs[12];mach_vm_size_t got=0;
  if(mach_vm_read_overwrite(mach_task_self(),fp,96,(uintptr_t)regs,&got)!=KERN_SUCCESS||got!=96)break;
  fprintf(stderr,"[totk] frame%u fp=%#llx lr=%#llx %s spills:",n,(unsigned long long)fp,(unsigned long long)lr,where);
  for(unsigned i=2;i<12;i++)fprintf(stderr," %#llx",(unsigned long long)regs[i]);
  fprintf(stderr,"\n");
  uint64_t nfp=regs[0];lr=regs[1];if(nfp<=fp)break;fp=nfp;
 }
}
static void *required(const char *name) { void *p=runtime_symbol(name);if(!p){fprintf(stderr,"missing %s\n",name);runtime_fail("required symbol");}return p; }
#if TARGET_OS_IPHONE
/* iOS: code written into memory at run time cannot execute, so ios/tools/gen_embed.py compiles each rewritten image into
   this executable: the text (with the game patches already applied on the Mac, TOTK_EXPORT_IOS) and the patch area go
   into the r-x segment __TOTKX, everything between them (rodata, data, bss, key page) into the rw segment __TOTK<name>W.
   Here one contiguous range is reserved and the three parts are vm_remap'ed back to their original relative offsets:
   code pages shared with the signed executable (copy=FALSE, r-x), the data part copy-on-write. Main's extra private
   page after the image (real-time frame step) stays plain zero-filled memory from the reservation. */
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include "ios_embed.h"
static void remap_at(Module *m,uintptr_t to,const void *from,size_t size,boolean_t copy,vm_prot_t need_prot) {
 mach_vm_address_t a=to;vm_prot_t cur=0,max=0;
 kern_return_t kr=mach_vm_remap(mach_task_self(),&a,size,0,VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,mach_task_self(),(uintptr_t)from,copy,&cur,&max,VM_INHERIT_NONE);
 if(kr!=KERN_SUCCESS||a!=to){fprintf(stderr,"[totk] %s vm_remap %p -> %#lx (%#zx bytes) failed: %d\n",m->name,from,(unsigned long)to,size,kr);runtime_fail("remap embedded module");}
 need((cur&need_prot)==need_prot,"embedded module permissions after remap");
}
static void digest_hex(const void *p,size_t n,char hex[65]){unsigned char d[32];CC_SHA256(p,(CC_LONG)n,d);for(unsigned i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",d[i]);}
static void map_module(Module *m,const char *dir) {
 (void)dir;
 const IosEmbed *e=NULL;for(unsigned i=0;i<sizeof(ios_embed)/sizeof(*ios_embed);i++)if(!strcmp(ios_embed[i].name,m->name))e=&ios_embed[i];
 need(e!=NULL,"module missing from ios_embed.h");
 char sx0[17],sx1[17],sw[17];snprintf(sx0,sizeof sx0,"__%sx0",m->name);snprintf(sx1,sizeof sx1,"__%sx1",m->name);snprintf(sw,sizeof sw,"__TOTK%sW",m->name);
 unsigned long z0=0,zw=0,z1=0;
 const uint8_t *x0=getsectiondata(&_mh_execute_header,"__TOTKX",sx0,&z0),*w=getsectiondata(&_mh_execute_header,sw,"__img",&zw),*x1=getsectiondata(&_mh_execute_header,"__TOTKX",sx1,&z1);
 need(x0&&w&&x1,"embedded module sections missing");
 need(z0==page_up(m->text_end)&&z0+zw==m->patch_off&&m->patch_off+z1==page_up(m->file_size),"embedded module layout");
 need(!((uintptr_t)x0&0x3fff)&&!((uintptr_t)w&0x3fff)&&!((uintptr_t)x1&0x3fff),"embedded sections not 16 KiB aligned");
 char hex[65];
 digest_hex(x0,z0,hex);need(!strcmp(hex,e->x0),"embedded text SHA256 differs from the exported patched text");
 digest_hex(w,zw,hex);need(!strcmp(hex,e->w),"embedded data SHA256 differs from verified rewrite");
 digest_hex(x1,z1,hex);need(!strcmp(hex,e->x1),"embedded patch area SHA256 differs from verified rewrite");
 m->size=page_up(m->file_size)+(!strcmp(m->name,"main")?0x4000:0);
 mach_vm_address_t base=0;need(mach_vm_allocate(mach_task_self(),&base,m->size,VM_FLAGS_ANYWHERE)==KERN_SUCCESS,"reserve module range");
 remap_at(m,base,x0,z0,FALSE,VM_PROT_READ|VM_PROT_EXECUTE);
 remap_at(m,base+z0,w,zw,TRUE,VM_PROT_READ|VM_PROT_WRITE);
 remap_at(m,base+m->patch_off,x1,z1,FALSE,VM_PROT_READ|VM_PROT_EXECUTE);
 m->base=(uint8_t *)(uintptr_t)base;
 need(m->key_off%0x4000==0&&m->key_off+0x4000<=m->patch_off&&m->patch_off<m->size,"key and patch layout");
 uint64_t *key=(void *)(m->base+m->key_off);
 for(unsigned i=0;i<8;i++)key[i]=runtime_keys[i]*8;
 make_hash(m);
 fprintf(stderr,"[totk] mapped embedded %s at %p size=%zu symbols=%u\n",m->name,m->base,m->size,m->nsym);
}
#else
static const char *image_dir;   /* the rewritten folder every module was read from (see report_hook_targets) */
static void map_module(Module *m,const char *dir) {
 image_dir=dir;
 char path[4096];need(snprintf(path,sizeof(path),"%s/%s.patched.bin",dir,m->name)<(int)sizeof(path),"image path");
 FILE *f=fopen(path,"rb");need(f!=NULL,"open patched module");
 struct stat st;need(fstat(fileno(f),&st)==0&&(size_t)st.st_size==m->file_size,"patched module size");
 /* The main module gets one private, writable page after its rewritten image. The
    real-time frame-step patch reads its two floats from this page via ADRP. The sdk module gets one too
    when a mod resolves SDK functions by name: the redirects (below) load their target from that page. */
 m->size=page_up(m->file_size)+((!strcmp(m->name,"main")
#ifdef TOTK_MOD_SUBSDK3
  ||!strcmp(m->name,"sdk")
#endif
  )?0x4000:0);
#ifdef TOTK_MOD_SUBSDK1
 m->base=runtime_arena_alloc(m->size);
#else
 m->base=mmap(NULL,m->size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
#endif
 need(m->base!=MAP_FAILED,"map module");need(fread(m->base,1,m->file_size,f)==m->file_size,"read image");fclose(f);
 unsigned char digest[32];CC_SHA256(m->base,(CC_LONG)m->file_size,digest);char hex[65];
 for(unsigned i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
 need(!strcmp(hex,m->digest),"image SHA256 differs from verified rewrite");
 need(m->key_off%0x4000==0&&m->key_off+0x4000<=m->patch_off&&m->patch_off<m->size,"key and patch layout");
 uint64_t *key=(void *)(m->base+m->key_off);
 for(unsigned i=0;i<8;i++)key[i]=runtime_keys[i]*8;
 make_hash(m);
 fprintf(stderr,"[totk] mapped %s size=%zu symbols=%u\n",m->name,m->size,m->nsym);
}
/* TOTK_EXPORT_IOS=<dir>: after the game patches, write each module's text [0, page_up(TEXT_END)) and patch area
   [PATCH_OFF, page_up(file size)) for ios/tools/gen_embed.py (Breath of the Wild's exclusive-acquire patch also changes the
   rewriter's patch area; Tears of the Kingdom's leave it as it is). Relocations never reach either (they start at
   DATA_OFF, below PATCH_OFF), so the exported bytes differ from the verified image only at the patch sites; the counts
   are printed. */
static void export_ios_text(const char *rewritten,const char *out) {
 for(unsigned i=0;i<NM;i++){Module *m=&modules[i];char path[4096];size_t n=page_up(m->text_end);
  need(snprintf(path,sizeof path,"%s/%s.patched.bin",rewritten,m->name)<(int)sizeof path,"image path");
  FILE *f=fopen(path,"rb");need(f!=NULL,"open patched module");uint8_t *orig=malloc(n);need(orig&&fread(orig,1,n,f)==n,"read original text");fclose(f);
  unsigned diff=0;for(size_t k=0;k<n;k+=4)if(memcmp(orig+k,m->base+k,4))diff++;free(orig);
  need(snprintf(path,sizeof path,"%s/%s.x0.bin",out,m->name)<(int)sizeof path,"export path");
  f=fopen(path,"wb");need(f&&fwrite(m->base,1,n,f)==n&&fclose(f)==0,"write exported text");
  size_t p0=m->patch_off,p1=page_up(m->file_size);need(p0<=p1&&p1<=m->size,"patch area layout");
  need(snprintf(path,sizeof path,"%s/%s.patched.bin",rewritten,m->name)<(int)sizeof path,"image path");
  f=fopen(path,"rb");need(f!=NULL,"open patched module");uint8_t *img=calloc(1,p1-p0);need(img!=NULL,"patch area buffer");
  need(fseek(f,(long)p0,SEEK_SET)==0,"seek patch area");size_t got=fread(img,1,m->file_size-p0,f);fclose(f);need(got==m->file_size-p0,"read patch area");
  unsigned pdiff=0;for(size_t k=0;k<p1-p0;k+=4)if(memcmp(img+k,m->base+p0+k,4))pdiff++;free(img);
  need(snprintf(path,sizeof path,"%s/%s.x1.bin",out,m->name)<(int)sizeof path,"export path");
  f=fopen(path,"wb");need(f&&fwrite(m->base+p0,1,p1-p0,f)==p1-p0&&fclose(f)==0,"write exported patch area");
  printf("%s text_bytes=%zu patched_words=%u patch_area_bytes=%zu patched_words=%u\n",m->name,n,diff,p1-p0,pdiff);}
}
#endif
/* Some imports are data, not code: they must never pass through the host-stack wrapper, which
   turns its target into an executable thunk. subsdk3's RTTI record is one of them. */
static void *runtime_data_override(const char *name);
static void relocate(Module *m) {
 for(unsigned i=0;i<m->nreloc;i++) {
  const Reloc *r=&m->relocs[i];
  need(r->where>=m->data_off&&r->where+8<=m->key_off&&r->symbol<m->nsym,"relocation bounds");
  uintptr_t v;
  if(r->kind==1027) { need(r->addend>=0&&(uint64_t)r->addend<m->key_off,"relative addend");v=(uintptr_t)m->base+r->addend;m->relative++; }
  else {
   need(r->kind==257||r->kind==1025||r->kind==1026,"relocation kind");
   const Symbol *s=&m->symbols[r->symbol];void *p=runtime_data_override(s->name);
   if(!p) {
    p=r->kind==1026?runtime_observer(s->name):NULL;
    if(!p)p=runtime_override(s->name);
    if(p)p=runtime_hle_wrap_named(p,s->name);   /* host replacements run on the thread's host stack */
   }
   if(!p)p=s->defined?(s->value<m->key_off?m->base+s->value:NULL):runtime_symbol(s->name);
   if(!p&&s->binding!=2){fprintf(stderr,"%s unresolved %s\n",m->name,s->name);runtime_fail("strong import unresolved");}
   if(!p)m->weak++;
   if(p&&!s->defined)m->cross++;
   v=(uintptr_t)p+(r->kind==1026?0:r->addend);m->symbolic++;
  }
  memcpy(m->base+r->where,&v,8);
 }
}
#ifdef TOTK_MOD_SUBSDK3
/* UltraCam's subsdk3 links UC::ConfigVarBase's key function into a companion module this pack does
   not ship, so its typeinfo record is a strong import. Five derived records (UC::ConfigVarI<bool>,
   <float>, <int>, UC::EAConfigVarI<bool>, UC::Configurator...) store it as __base_type, and
   dynamic_cast walks that field, so an unresolved or NULL slot is not usable. Rebuild it as a real
   __class_type_info record (two words, no base field) out of subsdk3's own statically linked
   libc++abi: its vtable and the mangled name already live in this image. */
static void *uc_typeinfo_config_var_base(void) {
 static uint64_t record[2];
 uint8_t *b=runtime_module_base("subsdk3");need(b!=NULL,"subsdk3 must be loaded for its typeinfo shim");if(record[0])return (void *)record;
 /* 0x3e6d30 is the header of __class_type_info's vtable (offset_to_top, type_info*, entries at +0x10)
    and its type_info record names itself from rodata. RELR is applied before RELA in this pass, so the
    fields may already hold host addresses; accept either form and refuse to build on anything else. */
 uint64_t top,back,name;memcpy(&top,b+0x3e6d30,8);memcpy(&back,b+0x3e6d38,8);memcpy(&name,b+0x3e6d20,8);
 need(!top,"subsdk3 __class_type_info vtable header");
 need(back==0x3e6d18||(uintptr_t)back==(uintptr_t)(b+0x3e6d18),"subsdk3 __class_type_info vtable header");
 need(name==0x387198||(uintptr_t)name==(uintptr_t)(b+0x387198),"subsdk3 __class_type_info type_info");
 need(!memcmp(b+0x387198,"N10__cxxabiv117__class_type_infoE",32),"subsdk3 __class_type_info name");
 need(!memcmp(b+0x390eea,"N2UC13ConfigVarBaseE",21),"subsdk3 ConfigVarBase mangled name");
 record[0]=(uintptr_t)(b+0x3e6d40);record[1]=(uintptr_t)(b+0x390eea);
 fprintf(stderr,"[totk] subsdk3 synthesised _ZTIN2UC13ConfigVarBaseE at %p\n",(void *)record);
 return (void *)record;
}
#endif
static void *runtime_data_override(const char *name) {
#ifdef TOTK_MOD_SUBSDK3
 if(!strcmp(name,"_ZTIN2UC13ConfigVarBaseE"))return uc_typeinfo_config_var_base();
#endif
 (void)name;return NULL;
}
#ifdef TOTK_MOD_SUBSDK3
/* A mod looks SDK functions up by name (nn::ro::LookupSymbol) and then both hooks and calls whatever it gets, so
   the SDK body has to be the code this port actually runs. Every SDK function the port replaces from the host
   therefore gets its first words replaced by a redirect: load the host wrapper's address out of this module's own
   private page and branch to it. The mod's trampoline saves those three words as the "original function", so the
   hook's call to the original lands on the host implementation as well, and no guest code ever reaches the fsp-srv
   or hidcs IPC this port does not run. The slot sits in the module's own mapping because ADRP only reaches 4 GiB,
   and modules are mapped far apart from each other. */
static unsigned redirect_used;   /* bytes of the sdk module's private page holding redirect targets */
static uintptr_t redirect_seen[512],redirect_host[512];static unsigned redirect_count;static const char *redirect_label[512];
static const Symbol *module_definition(Module *m,const char *name) {   /* the defining symbol, to check its size */
 unsigned p=hash_name(name)&m->hash_mask;
 while(m->hash[p]) {const Symbol *s=&m->symbols[m->hash[p]];if(!strcmp(name,s->name)&&s->defined)return s;p=(p+1)&m->hash_mask;}
 return NULL;
}
static void redirect_name(const char *name) {
 void *host=runtime_override(name);if(!host)return;
 host=runtime_hle_wrap_named(host,name);
 void *guest=runtime_symbol(name);if(!guest)return;
 for(unsigned i=0;i<NM;i++) {
  Module *m=&modules[i];uint64_t off=(uintptr_t)guest-(uintptr_t)m->base;
  if((uintptr_t)guest<(uintptr_t)m->base||off>=page_up(m->text_end))continue;
  if(strcmp(m->name,"sdk"))return;   /* only the SDK's own bodies are replaced; a module's internal function stays as it is */
  if(off+12>m->size||page_up(m->file_size)+8>m->size){fprintf(stderr,"[totk] redirect %s: %s has no private page\n",name,m->name);return;}
  for(unsigned j=0;j<redirect_count;j++)if(redirect_seen[j]==off+(uintptr_t)m->base)return;   /* two names, one body */
  if(redirect_count==sizeof redirect_seen/sizeof*redirect_seen)runtime_fail("redirect table full");
  const Symbol *s=module_definition(m,name);
  if(s&&s->size&&s->size<12){fprintf(stderr,"[totk] redirect %s: %s+%#llx is only %llu bytes\n",name,m->name,(unsigned long long)off,(unsigned long long)s->size);return;}
  uint64_t slot=(uintptr_t)(m->base+page_up(m->file_size)+redirect_used),stub=(uintptr_t)guest;
  int64_t pages=(int64_t)((slot&~4095ULL)-(stub&~4095ULL))/4096;
  unsigned byte=(unsigned)(slot&4095);
  if(pages<-(1ll<<20)||pages>=(1ll<<20)||byte&7||byte>32760){fprintf(stderr,"[totk] redirect %s: slot out of ADRP reach\n",name);return;}
  uint32_t words[3]={0x90000010u|(uint32_t)(((pages&3)<<29)|(((pages>>2)&0x7ffff)<<5)),
                     0xf9400210u|(byte/8)<<10,0xd61f0200u};
  memcpy((void *)stub,words,sizeof words);
  *(uint64_t *)(uintptr_t)slot=(uint64_t)(uintptr_t)host;
  redirect_used+=8;redirect_host[redirect_count]=(uintptr_t)host;redirect_label[redirect_count]=name;redirect_seen[redirect_count++]=(uintptr_t)stub;
  fprintf(stderr,"[totk] %s+%#llx redirected to the host %s\n",m->name,(unsigned long long)off,name);
  return;
 }
}
/* Every name a loaded module imports is a name a mod can also ask for by string, so the SDK bodies behind all of
   them are redirected. subsdk3 resolves the two below from rodata strings instead of through an import (its
   fallback mount path), so they are named explicitly. */
static void redirect_sdk_bodies(void) {
 static const char *extra[]={"_ZN2nn2fs8MountRomEPKcPvm","_ZN2nn2fs22QueryMountRomCacheSizeEPm"};
 for(unsigned i=0;i<NM;i++)for(unsigned j=1;j<modules[i].nsym;j++) {
  const Symbol *s=&modules[i].symbols[j];
  if(!s->defined&&s->name&&*s->name)redirect_name(s->name);
 }
 for(unsigned j=0;j<sizeof extra/sizeof*extra;j++)redirect_name(extra[j]);
 fprintf(stderr,"[totk] %u SDK bodies replaced by the host implementations\n",redirect_count);
}
/* An import resolved straight to a host replacement skips the guest body, and with it everything a mod wrote
   there: UltraCam's NvnBootstrapHook patches the SDK's nvnBootstrapLoader, and because the game's call never
   reached that body its overlay backend (an ImGui-on-NVN renderer started from that hook) never initialised.
   Once the body is only a redirect to the host, the import can point at the body instead: the same host
   implementation one indirect branch away, and a mod's trampoline now sits in the path. */
static void route_redirected_imports(void) {
 unsigned rerouted=0,shown=0;
 for(unsigned i=0;i<NM;i++)for(unsigned j=0;j<modules[i].nreloc;j++) {
  Module *m=&modules[i];const Reloc *r=&m->relocs[j];
  if(r->kind==1027)continue;
  const char *name=m->symbols[r->symbol].name;uintptr_t current;memcpy(&current,m->base+r->where,8);
  for(unsigned k=0;k<redirect_count;k++)if(name&&!strcmp(name,redirect_label[k])) {
   uintptr_t want=redirect_host[k]+(r->kind==1026?0:r->addend);
   if(current==want) {
    memcpy(m->base+r->where,&redirect_seen[k],8);rerouted++;
    if(strstr(name,"nvn"))fprintf(stderr,"[totk] %s import of %s now goes through the SDK body %#lx\n",
     m->name,name,(unsigned long)redirect_seen[k]);
   } else if(shown<8) {
    fprintf(stderr,"[totk] %s import of %s at %#llx holds %#lx, not the redirect %#lx (kind %u addend %lld)\n",
     m->name,name,(unsigned long long)r->where,(unsigned long)current,(unsigned long)want,r->kind,(long long)r->addend);
    shown++;
   }
   break;
  }
 }
 fprintf(stderr,"[totk] %u imports rerouted through their redirected SDK bodies\n",rerouted);
}
#endif
static void verify_identity(int negative) {
 unsigned checked=0;void *original=required("nnMain");
 for(unsigned i=0;i<NM;i++)for(unsigned j=0;j<modules[i].nreloc;j++) {
  Module *m=&modules[i];const Reloc *r=&m->relocs[j];
  if(r->kind==1027||r->kind==1026||strcmp(m->symbols[r->symbol].name,"nnMain"))continue;
  uintptr_t actual;memcpy(&actual,m->base+r->where,8);
  if(negative){actual=(uintptr_t)runtime_observer("nnMain");memcpy(m->base+r->where,&actual,8);}
  need(actual==(uintptr_t)original,"guest nnMain address identity changed");checked++;
 }
 need(checked>0,"nnMain identity reference missing");
}
static void seal(Module *m) {
 size_t rx=page_up(m->text_end),ro_end=m->data_off&~(size_t)0x3fff;
 need(rx<=ro_end,"text/data overlap");
#if TARGET_OS_IPHONE
 if(ro_end>rx)need(mprotect(m->base+rx,ro_end-rx,PROT_READ)==0,"rodata R");   /* code parts are already r-x shared pages */
 need(mprotect(m->base+m->key_off,0x4000,PROT_READ)==0,"key page R");
 return;
#endif
 need(mprotect(m->base,rx,PROT_READ|PROT_EXEC)==0,"text RX");
 if(ro_end>rx)need(mprotect(m->base+rx,ro_end-rx,PROT_READ)==0,"rodata R");
 need(mprotect(m->base+m->key_off,0x4000,PROT_READ)==0,"key page R");
 size_t patch_end=page_up(m->file_size);
 need(mprotect(m->base+m->patch_off,patch_end-m->patch_off,PROT_READ|PROT_EXEC)==0,"patch RX");
 sys_icache_invalidate(m->base,rx);sys_icache_invalidate(m->base+m->patch_off,patch_end-m->patch_off);
}
static void check_permissions(Module *m) {
 mach_vm_address_t a=(uintptr_t)m->base,end=a+m->size;
 while(a<end) {
  mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
  mach_vm_address_t requested=a;
  need(mach_vm_region(mach_task_self(),&a,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&obj)==KERN_SUCCESS&&a==requested&&size>0,"mapped region query");
  if(obj)mach_port_deallocate(mach_task_self(),obj);
  uint64_t off=a-(uintptr_t)m->base;
  vm_prot_t expected=off>=page_up(m->file_size)?(VM_PROT_READ|VM_PROT_WRITE):
   (off<page_up(m->text_end)||off>=m->patch_off)?(VM_PROT_READ|VM_PROT_EXECUTE):
   ((off>=page_up(m->text_end)&&off<(m->data_off&~0x3fffULL))||off==m->key_off)?VM_PROT_READ:(VM_PROT_READ|VM_PROT_WRITE);
  need(info.protection==expected,"module permission mismatch");a+=size;
 }
}
typedef struct {void *tls,*tlr,*dummy,*signal_stack;} ThreadEnvironment;
static pthread_key_t environment_key;
#define SIGNAL_STACK_SIZE (256u<<10)
static void environment_destroy(void *p) {
 ThreadEnvironment *e=p;if(!e)return;
 if(e->signal_stack){stack_t off={.ss_flags=SS_DISABLE};sigaltstack(&off,NULL);free(e->signal_stack);}
 free(e->dummy);free(e->tlr);free(e->tls);free(e);
}
void runtime_thread_init(void) {
 need(!pthread_getspecific(environment_key),"duplicate guest thread environment");
 ThreadEnvironment *e=calloc(1,sizeof(*e));need(e!=NULL,"thread environment");
 e->tls=calloc(1,8192);e->tlr=calloc(1,0x200);e->dummy=calloc(1,0x400);
 need(e->tls&&e->tlr&&e->dummy,"thread environment allocation");
 /* Faults and emulated instructions are handled off the guest stack, which can be as small as 4 KiB. */
 e->signal_stack=malloc(SIGNAL_STACK_SIZE);need(e->signal_stack!=NULL,"signal stack allocation");
 stack_t ss={.ss_sp=e->signal_stack,.ss_size=SIGNAL_STACK_SIZE,.ss_flags=0};need(sigaltstack(&ss,NULL)==0,"install signal stack");memcpy((uint8_t *)e->tlr+0x1f8,&e->dummy,8);
 need(pthread_setspecific(environment_key,e)==0&&pthread_setspecific(runtime_keys[0],NULL)==0,"thread ownership");
 need(pthread_setspecific(runtime_keys[1],e->tls)==0&&pthread_setspecific(runtime_keys[2],e->tlr)==0&&pthread_setspecific(runtime_keys[3],(void *)runtime_gate)==0,"thread slots");
 uintptr_t tp;__asm__ volatile("mrs %0,tpidrro_el0":"=r"(tp));
 need((tp&7)==0,"unaligned raw Darwin TSD incompatible with patches");
 for(unsigned i=0;i<4;i++){void *raw;memcpy(&raw,(void *)(tp+runtime_keys[i]*8),8);need(raw==pthread_getspecific(runtime_keys[i]),"Darwin TSD layout");}
}
static void thread_cleanup(void) {
 ThreadEnvironment *e=pthread_getspecific(environment_key);pthread_setspecific(environment_key,NULL);
 for(unsigned i=0;i<4;i++)pthread_setspecific(runtime_keys[i],NULL);environment_destroy(e);
}
uint64_t runtime_now_ns(void) {mach_timebase_info_data_t tb;mach_timebase_info(&tb);return (uint64_t)((__uint128_t)mach_absolute_time()*tb.numer/tb.denom);}
void runtime_dispatch(uint64_t ret,uint64_t *regs) {
 for(unsigned i=0;i<NM;i++) {
  uintptr_t b=(uintptr_t)modules[i].base;if(!b||ret<b)continue;
  unsigned lo=0,hi=modules[i].ngate;   // gates sorted by return address (prepare_runtime.py)
  while(lo<hi){unsigned m=(lo+hi)/2;if(b+modules[i].gates[m].ret<ret)lo=m+1;else hi=m;}
  if(lo==modules[i].ngate||b+modules[i].gates[lo].ret!=ret)continue;
  const Gate *g=&modules[i].gates[lo];
  if(g->timer==2){runtime_spin_wait(i,g->original);return;}   // spin wait (patch_nso.py "Spin waits"): no register changes
  if(g->timer){mach_timebase_info_data_t tb;mach_timebase_info(&tb);__uint128_t ns=(__uint128_t)mach_absolute_time()*tb.numer/tb.denom;
   need(g->arg<31&&g->arg!=18,"timer target register");regs[g->arg]=(uint64_t)(ns*12/625);__atomic_fetch_add(&timer_calls,1,__ATOMIC_RELAXED);return;}
  __atomic_fetch_add(&svc_calls,1,__ATOMIC_RELAXED);runtime_svc(g->arg,regs,modules[i].name,g->original);return;
 }
 runtime_fail("unknown gate return address");
}
/* Signal diagnostics use only stack buffers + write; no guest continuation. */
__thread sigjmp_buf *runtime_fault_guard;
static void signal_hex(const char *label,uint64_t value) {
 char b[128];size_t n=0;while(*label)b[n++]=*label++;b[n++]='0';b[n++]='x';
 for(int i=15;i>=0;i--)b[n++]="0123456789abcdef"[(value>>(i*4))&15];b[n++]='\n';write(2,b,n);
}
/* CTR_EL0 for 128-byte host cache lines: DminLine=IminLine=5 (32 words), ERG=CWG=5, PIPT I-cache, IDC/DIC clear. */
#define HOST_CTR_EL0 0x8555c005ULL
#ifndef GAME_BOTW   /* TOTK addresses (GAME_ADDR) */
/* #57: the same optional reference as below (object+0x6b0, a holder whose first word is the target) can outlive its
   holder: after long play the freed holder's memory held other data (the low region's base, two floats 1.0), the caller
   at GAME_ADDR(0x15ecb0c) passed that word as the target, and the callee faulted reading the target's id (+0x10). The
   callee takes a null target, but its caller then uses the word again, so the target is treated as absent where it is
   read: the callee's frame is popped (its prologue decoded: frame size and the callee-saved registers it stored), the
   caller resumes at its "no target" branch, and the stale reference is cleared as in the load-time case. Only this exact
   signature is handled: fault at the callee's ldr w8,[x22,#0x10] with x1 == x22 and the address x22+0x10, return address
   right after the caller's bl, and the caller's instructions as expected. */
static int stale_target_reference(int num,siginfo_t *info,ucontext_t *u){
 if((num!=SIGSEGV&&num!=SIGBUS)||!modules[MAIN_MODULE_INDEX].base)return 0;
 const uint32_t *site=(const uint32_t *)(uintptr_t)(modules[MAIN_MODULE_INDEX].base+GAME_ADDR(0x15ecb0c));   /* ldr x21,[x8] */
 uint64_t pc=u->uc_mcontext->__ss.__pc,*x=u->uc_mcontext->__ss.__x;
 if(site[-2]!=0xf9435a68u||site[0]!=0xf9400115u||(site[1]&0xff00001fu)!=0xb4000015u||(site[6]&0xfc000000u)!=0x94000000u)return 0;   /* ldr x8,[x19,#0x6b0]; ldr x21,[x8]; cbz x21; bl */
 if(u->uc_mcontext->__ss.__lr!=(uintptr_t)(site+7)||*(const uint32_t *)(uintptr_t)pc!=0xb94012c8u||x[1]!=x[22]||(uintptr_t)info->si_addr!=x[22]+0x10)return 0;
 int32_t bl=(int32_t)(site[6]<<6)>>6,skip=(int32_t)((site[1]>>5)<<13)>>13;
 const uint32_t *callee=site+6+bl,*resume=site+1+skip;
 int64_t frame=0;unsigned saved[32]={0};int nsaved=0;uint64_t at[32];
 for(const uint32_t *i=callee;i<callee+12&&(uintptr_t)i<pc;i++){uint32_t w=*i;unsigned rt=w&31,rt2=(w>>10)&31,rn=(w>>5)&31;int64_t imm7=((int64_t)(int32_t)(((w>>15)&0x7f)<<25)>>25)*8;
  if((w&0xffc00000u)==0xa9800000u&&rn==31&&rt==29&&rt2==30&&imm7<0&&!frame){frame=-imm7;saved[nsaved]=29;at[nsaved++]=0;saved[nsaved]=30;at[nsaved++]=8;}   /* stp x29,x30,[sp,#-N]! */
  else if((w&0xffc00000u)==0xa9000000u&&rn==31&&frame&&nsaved<30){saved[nsaved]=rt;at[nsaved++]=(uint64_t)imm7;saved[nsaved]=rt2;at[nsaved++]=(uint64_t)imm7+8;}   /* stp xa,xb,[sp,#o] */
  else if((w&0xffc00000u)==0xf9000000u&&rn==31&&frame&&nsaved<31){saved[nsaved]=rt;at[nsaved++]=((w>>10)&0xfff)*8;}}   /* str xa,[sp,#o] */
 if(!frame||frame>0x100)return 0;
 uint64_t sp=u->uc_mcontext->__ss.__sp,stack[32];mach_vm_size_t got=0;
 if(mach_vm_read_overwrite(mach_task_self(),sp,(mach_vm_size_t)frame,(uintptr_t)stack,&got)!=KERN_SUCCESS||got!=(mach_vm_size_t)frame)return 0;
 for(int i=0;i<nsaved;i++){if(at[i]+8>(uint64_t)frame)return 0;uint64_t v=stack[at[i]/8];
  if(saved[i]==29)u->uc_mcontext->__ss.__fp=v;else if(saved[i]==30)u->uc_mcontext->__ss.__lr=v;else if(saved[i]<29)x[saved[i]]=v;}
 u->uc_mcontext->__ss.__sp=sp+(uint64_t)frame;u->uc_mcontext->__ss.__pc=(uintptr_t)resume;
 uint64_t stale=x[21];uintptr_t field=x[19]+0x6b0;uint64_t holder=0,word=0;   /* the caller's x19 = the object, x21 = the stale word */
 if(mach_vm_read_overwrite(mach_task_self(),field,8,(uintptr_t)&holder,&got)==KERN_SUCCESS&&got==8&&holder&&
    mach_vm_read_overwrite(mach_task_self(),holder,8,(uintptr_t)&word,&got)==KERN_SUCCESS&&got==8&&word==stale)
  __atomic_compare_exchange_n((uint64_t *)field,&holder,0,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
 static const char note[]="[totk] ignored a stale optional target reference (#57)\n";write(2,note,sizeof(note)-1);
 return 1;
}
#endif
static void crash(int num,siginfo_t *info,void *context) {
 ucontext_t *u=context;
#if !TARGET_OS_IPHONE
 if(num==SIGTRAP){extern int runtime_mem_scan_trap(void *);if(runtime_mem_scan_trap(context))return;}   /* mscan watch (diagnostic, runtime/mem_scan.h) */
#endif
#ifdef GAME_BOTW
 if(num==SIGTRAP){extern int botw_jq_hook(void *);if(botw_jq_hook(context))return;}   /* TOTK_JQ_CHECK diagnostics (game_patches_botw.c) */
#endif
#ifndef GAME_BOTW
#if defined(TOTK_GAME_V143) && !TARGET_OS_IPHONE
 if(num==SIGTRAP){extern int runtime_diag_watch_trap(void *);if(runtime_diag_watch_trap(context))return;}   /* #61 frmwatch (diagnostic) */
#endif
 if(stale_target_reference(num,info,u))return;
 /* During save load, this optional game object can contain a tagged invalid
    reference. Treat it as absent, as the following cbz path expects. */
 if(num==SIGSEGV&&modules[MAIN_MODULE_INDEX].base&&
    u->uc_mcontext->__ss.__pc==(uintptr_t)modules[MAIN_MODULE_INDEX].base+GAME_ADDR(0x15ecb0c)&&
    (uintptr_t)info->si_addr==0xffff0000ffffffffULL&&
    u->uc_mcontext->__ss.__x[8]==0xffff0000ffffffffULL){
  uintptr_t field=u->uc_mcontext->__ss.__x[19]+0x6b0;
  uint64_t current=0;mach_vm_size_t got=0;
  if(mach_vm_read_overwrite(mach_task_self(),field,sizeof(current),(uintptr_t)&current,&got)==KERN_SUCCESS&&
     got==sizeof(current)&&current==0xffff0000ffffffffULL){
   uint64_t expected=current;
   if(__atomic_compare_exchange_n((uint64_t *)field,&expected,0,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST)){
    static const char note[]="[totk] ignored invalid optional menu reference\n";
    write(2,note,sizeof(note)-1);
    u->uc_mcontext->__ss.__x[8]=0;
    u->uc_mcontext->__ss.__pc-=4;
    return;
   }
  }
 }
#endif
 /* EL0 cache maintenance that Darwin traps but Horizon allows: emulate exactly two encodings (SDK only). */
 if(num==SIGILL){uint32_t insn=*(const uint32_t *)(uintptr_t)u->uc_mcontext->__ss.__pc;unsigned rt=insn&31;
  if((insn&~31u)==0xd53b0020u){if(rt!=31)u->uc_mcontext->__ss.__x[rt]=HOST_CTR_EL0;u->uc_mcontext->__ss.__pc+=4;
#ifdef TOTK_MOD_SUBSDK1
   mod_window_publish();   /* RwPages::Sync reads CTR_EL0 first; publish alias writes before the source is used */
#endif
   return;}   /* mrs Xt, CTR_EL0 */
  if((insn&~31u)==0xd50b7e20u){uintptr_t a=rt==31?0:(uintptr_t)u->uc_mcontext->__ss.__x[rt];sys_dcache_flush((void *)(a&~(uintptr_t)127),128);u->uc_mcontext->__ss.__pc+=4;return;}   /* dc civac, Xt */
 }
 if((num==SIGBUS||num==SIGSEGV)&&runtime_fault_guard){sigjmp_buf *g=runtime_fault_guard;runtime_fault_guard=NULL;siglongjmp(*g,1);}   /* guarded host read of guest memory (uniform snapshot copies) */
 if(runtime_gfx_fault(info->si_addr,(u->uc_mcontext->__es.__esr>>6)&1,context))return;uint64_t pc=u->uc_mcontext->__ss.__pc,fp=u->uc_mcontext->__ss.__fp;
 signal_hex("[totk] signal=",num);signal_hex("fault=",(uintptr_t)info->si_addr);signal_hex("esr=",u->uc_mcontext->__es.__esr);
 {mach_vm_address_t ra=(uintptr_t)info->si_addr;mach_vm_size_t rs=0;vm_region_basic_info_data_64_t ri;mach_msg_type_number_t rc=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t ro=0;
  if(mach_vm_region(mach_task_self(),&ra,&rs,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&ri,&rc,&ro)==KERN_SUCCESS){signal_hex("region=",ra);signal_hex("region size=",rs);signal_hex("region prot=",(uint64_t)ri.protection|((uint64_t)ri.max_protection<<8));}}signal_hex("pc=",pc);signal_hex("lr=",u->uc_mcontext->__ss.__lr);signal_hex("fp=",fp);
#ifdef GAME_BOTW
 {Dl_info di;for(int k=0;k<2;k++){uint64_t a=k?u->uc_mcontext->__ss.__lr:pc;if(dladdr((void *)(uintptr_t)a,&di)&&di.dli_sname){write(2,k?"lr host ":"pc host ",8);write(2,di.dli_sname,strlen(di.dli_sname));signal_hex(" +",a-(uintptr_t)di.dli_saddr);}}}   /* a fault in a host function: name it */
 /* Diagnostics (TOTK_CRASH_THREADS=1): what every other guest thread was doing at the fault (wait states, last SVC chains,
    and the live pc of the ones running), to see a job running into data another thread is rebuilding. Once per process. */
 {static int dumped;if(getenv("TOTK_CRASH_THREADS")&&!__atomic_fetch_add(&dumped,1,__ATOMIC_SEQ_CST)){extern void runtime_dump_threads(void);runtime_dump_threads();}}
#endif
 for(unsigned i=0;i<NM;i++)if(pc>=(uintptr_t)modules[i].base&&pc<(uintptr_t)modules[i].base+modules[i].size){write(2,modules[i].name,strlen(modules[i].name));signal_hex(" offset=",pc-(uintptr_t)modules[i].base);}
 for(unsigned i=0;i<29;i++)signal_hex("x=",u->uc_mcontext->__ss.__x[i]);signal_hex("sp=",u->uc_mcontext->__ss.__sp);
 for(unsigned depth=0;depth<24&&fp&&!(fp&15);depth++){uint64_t frame[2];mach_vm_size_t got=0;if(mach_vm_read_overwrite(mach_task_self(),fp,16,(uintptr_t)frame,&got)!=KERN_SUCCESS||got!=16)break;signal_hex("frame lr=",frame[1]);for(unsigned i=0;i<NM;i++)if(frame[1]>=(uintptr_t)modules[i].base&&frame[1]<(uintptr_t)modules[i].base+modules[i].size){write(2,modules[i].name,strlen(modules[i].name));signal_hex(" offset=",frame[1]-(uintptr_t)modules[i].base);}if(frame[0]==fp)break;fp=frame[0];   /* host-stack switch: frames may move between stacks */}
 /* TOTK_CRASH_MEM=<reg>[:<signed offset>[:<bytes>]]: dump words at register+offset; TOTK_CRASH_MEM_FOLLOW=k1,k2,...: for each
    listed word index, dump 0x100 bytes at that pointer and the ASCII of every readable pointer inside it (data-structure faults). */
 {const char *e=getenv("TOTK_CRASH_MEM");if(e){unsigned r=(unsigned)strtoul(e,NULL,0);const char *c=strchr(e,':');int64_t off=c?strtoll(c+1,NULL,0):0;const char *c2=c?strchr(c+1,':'):NULL;
  uint64_t len=c2?strtoull(c2+1,NULL,0):0x100;if(len>0x1000)len=0x1000;if(r<29){uint64_t a=u->uc_mcontext->__ss.__x[r]+(uint64_t)off,w[512];mach_vm_size_t got=0;signal_hex("mem at=",a);
  if(mach_vm_read_overwrite(mach_task_self(),a,len,(uintptr_t)w,&got)==KERN_SUCCESS&&got==len){unsigned nw=(unsigned)(len/8);for(unsigned i=0;i<nw;i++){signal_hex("m=",w[i]);}
   const char *f=getenv("TOTK_CRASH_MEM_FOLLOW");while(f&&*f){unsigned k=(unsigned)strtoul(f,NULL,0);uint64_t v[32];if(k<nw&&mach_vm_read_overwrite(mach_task_self(),w[k],sizeof(v),(uintptr_t)v,&got)==KERN_SUCCESS&&got==sizeof(v)){
     signal_hex("follow word=",k);signal_hex("follow at=",w[k]);for(unsigned i=0;i<32;i++){signal_hex("f=",v[i]);
      if(v[i]>=0x100000000ULL&&v[i]<0x800000000000ULL){char t[128];mach_vm_size_t g2=0;if(mach_vm_read_overwrite(mach_task_self(),v[i],120,(uintptr_t)t,&g2)==KERN_SUCCESS&&g2==120){
       unsigned printable=0;for(unsigned j=0;j<120&&t[j];j++)if(t[j]>=0x20&&t[j]<0x7f)printable++;else break;
       if(printable>=3){char b[160];size_t n=0;const char *lab="  str=";while(*lab)b[n++]=*lab++;for(unsigned j=0;j<printable&&j<120;j++)b[n++]=t[j];b[n++]='\n';write(2,b,n);}}}}}
    const char *nx=strchr(f,',');f=nx?nx+1:NULL;}}}}}
 {const char *hw=getenv("TOTK_CRASH_HEAPWALK");if(hw){unsigned r=(unsigned)strtoul(hw,NULL,0);const char *c=strchr(hw,':');int64_t off=c?strtoll(c+1,NULL,0):0;mach_vm_size_t got=0;uint64_t hp=0,hh[32];
  if(r<29&&mach_vm_read_overwrite(mach_task_self(),u->uc_mcontext->__ss.__x[r]+(uint64_t)off,8,(uintptr_t)&hp,&got)==KERN_SUCCESS&&got==8&&mach_vm_read_overwrite(mach_task_self(),hp,sizeof(hh),(uintptr_t)hh,&got)==KERN_SUCCESS&&got==sizeof(hh)){
   uint64_t start=hh[5],size=hh[6];signal_hex("heapwalk heap=",hp);signal_hex("heapwalk start=",start);signal_hex("heapwalk size=",size);
   if(start==hp&&size<0x40000000ULL){uint64_t sentinel=hp+0xc8,p=0;unsigned count=0;   /* sead::ExpHeap use list: OffsetList node at +0xc8, blocks linked by their 16-byte ListNode */
    if(mach_vm_read_overwrite(mach_task_self(),sentinel+8,8,(uintptr_t)&p,&got)!=KERN_SUCCESS)p=0;
    while(p&&p!=sentinel&&count<20000){uint64_t h[4],d0=0;if(mach_vm_read_overwrite(mach_task_self(),p,32,(uintptr_t)h,&got)!=KERN_SUCCESS||got!=32)break;
     mach_vm_read_overwrite(mach_task_self(),p+0x20,8,(uintptr_t)&d0,&got);
     char b[200];size_t n=0;const char *lab="blk off=";while(*lab)b[n++]=*lab++;
     uint64_t vals[4]={p-start,h[3],h[2],d0};const char *labs[4]={""," size="," attr="," data0="};
     for(unsigned k=0;k<4;k++){const char *l=labs[k];while(*l)b[n++]=*l++;b[n++]='0';b[n++]='x';for(int i=15;i>=0;i--)b[n++]="0123456789abcdef"[(vals[k]>>(i*4))&15];}
     b[n++]='\n';write(2,b,n);p=h[1];count++;}}}}}
 /* TOTK_CRASH_HEAPFIND=<reg>: locate the sead::Heap (self pointer at +0x28, size at +0x30) whose range contains the register's
    address by scanning backwards page by page (resource heaps are page-aligned in the alias region), then walk and dump it. */
 {const char *hf=getenv("TOTK_CRASH_HEAPFIND");if(hf){unsigned r=(unsigned)strtoul(hf,NULL,0);mach_vm_size_t got=0;uint64_t a=r<29?u->uc_mcontext->__ss.__x[r]:0,found=0;
  for(uint64_t pg=a&~0xfffULL;pg&&a-pg<(256ULL<<20);pg-=0x1000){uint64_t hh[8];if(mach_vm_read_overwrite(mach_task_self(),pg,sizeof hh,(uintptr_t)hh,&got)!=KERN_SUCCESS||got!=sizeof hh)continue;
   if(hh[5]==pg&&hh[6]>=0x1000&&hh[6]<0x40000000ULL&&a<pg+hh[6]){found=pg;break;}}
  signal_hex("heapfind reg value=",a);signal_hex("heapfind heap=",found);
  if(found){uint64_t hh[32];if(mach_vm_read_overwrite(mach_task_self(),found,sizeof hh,(uintptr_t)hh,&got)==KERN_SUCCESS&&got==sizeof hh){
   char t[128];mach_vm_size_t g2=0;if(hh[4]>=0x100000000ULL&&mach_vm_read_overwrite(mach_task_self(),hh[4],120,(uintptr_t)t,&g2)==KERN_SUCCESS){unsigned pr=0;for(unsigned j=0;j<120&&t[j];j++)if(t[j]>=0x20&&t[j]<0x7f)pr++;else break;char b[160];size_t n=0;const char *lab="heapfind name=";while(*lab)b[n++]=*lab++;for(unsigned j=0;j<pr;j++)b[n++]=t[j];b[n++]='\n';write(2,b,n);}
   signal_hex("heapfind size=",hh[6]);signal_hex("heapfind freelist head=",hh[22]);signal_hex("heapfind free count=",hh[24]&0xffffffff);
   uint64_t sentinel=found+0xc8,p=0;unsigned count=0;if(mach_vm_read_overwrite(mach_task_self(),sentinel+8,8,(uintptr_t)&p,&got)!=KERN_SUCCESS)p=0;
   while(p&&p!=sentinel&&count<20000){uint64_t h[4],d0=0;if(mach_vm_read_overwrite(mach_task_self(),p,32,(uintptr_t)h,&got)!=KERN_SUCCESS||got!=32)break;mach_vm_read_overwrite(mach_task_self(),p+0x20,8,(uintptr_t)&d0,&got);
    char b[200];size_t n=0;const char *lab="blk off=";while(*lab)b[n++]=*lab++;uint64_t vals[4]={p-found,h[3],h[2],d0};const char *labs[4]={""," size="," attr="," data0="};
    for(unsigned k=0;k<4;k++){const char *l=labs[k];while(*l)b[n++]=*l++;b[n++]='0';b[n++]='x';for(int i=15;i>=0;i--)b[n++]="0123456789abcdef"[(vals[k]>>(i*4))&15];}b[n++]='\n';write(2,b,n);p=h[1];count++;}
   const char *dp=getenv("TOTK_CRASH_HEAPDUMP");if(dp){int fd=open(dp,O_WRONLY|O_CREAT|O_TRUNC,0644);if(fd>=0){uint64_t done=0;static char buf2[65536];while(done<hh[6]){uint64_t n=hh[6]-done;if(n>sizeof buf2)n=sizeof buf2;
    if(mach_vm_read_overwrite(mach_task_self(),found+done,n,(uintptr_t)buf2,&got)!=KERN_SUCCESS||got!=n)break;if(write(fd,buf2,(size_t)n)!=(ssize_t)n)break;done+=n;}close(fd);signal_hex("heapdump bytes=",done);}}}}}}
 /* TOTK_CRASH_HEAPDUMP=<path>: also write the walked heap's bytes (same heap as TOTK_CRASH_HEAPWALK) to a file for offline comparison. */
 {const char *hw=getenv("TOTK_CRASH_HEAPWALK"),*dp=getenv("TOTK_CRASH_HEAPDUMP");if(hw&&dp){unsigned r=(unsigned)strtoul(hw,NULL,0);const char *c=strchr(hw,':');int64_t off=c?strtoll(c+1,NULL,0):0;mach_vm_size_t got=0;uint64_t hp=0,hh[8];
  if(r<29&&mach_vm_read_overwrite(mach_task_self(),u->uc_mcontext->__ss.__x[r]+(uint64_t)off,8,(uintptr_t)&hp,&got)==KERN_SUCCESS&&got==8&&mach_vm_read_overwrite(mach_task_self(),hp,sizeof(hh),(uintptr_t)hh,&got)==KERN_SUCCESS&&got==sizeof(hh)&&hh[5]==hp&&hh[6]<0x40000000ULL){
   int fd=open(dp,O_WRONLY|O_CREAT|O_TRUNC,0644);if(fd>=0){uint64_t done=0;static char buf[65536];while(done<hh[6]){uint64_t n=hh[6]-done;if(n>sizeof buf)n=sizeof buf;
    if(mach_vm_read_overwrite(mach_task_self(),hp+done,n,(uintptr_t)buf,&got)!=KERN_SUCCESS||got!=n)break;if(write(fd,buf,(size_t)n)!=(ssize_t)n)break;done+=n;}close(fd);signal_hex("heapdump bytes=",done);}}}}
 _exit(128+num);
}
static void *probe_thread(void *unused) {
 (void)unused;runtime_thread_init();
 typedef uint64_t (*Fn)(void);Fn fn=(Fn)(void *)(modules[MAIN_MODULE_INDEX].base+PROBE_PLT);uint64_t previous=0;
 for(unsigned i=0;i<1000;i++){uint64_t current=fn();need(current>=previous&&current>0,"cross-module clock result");previous=current;}
 thread_cleanup();return NULL;
}
static void probe(void) {
 uintptr_t slot;memcpy(&slot,modules[MAIN_MODULE_INDEX].base+PROBE_SLOT,8);
 need(slot==(uintptr_t)required("_ZN2nn2os13GetSystemTickEv"),"main PLT GOT resolution");
 pthread_t threads[4];for(unsigned i=0;i<4;i++)need(pthread_create(&threads[i],NULL,probe_thread,NULL)==0,"probe thread");
 for(unsigned i=0;i<4;i++)need(pthread_join(threads[i],NULL)==0,"join probe");need(timer_calls==4000,"timer gate count");
 printf("{\"status\":\"pass\",\"execution\":\"native arm64 main PLT -> sdk -> host timer -> return\",\"calls\":4000,\"threads\":4,\"modules\":[");
 for(unsigned i=0;i<NM;i++){Module *m=&modules[i];printf("%s{\"name\":\"%s\",\"relative\":%u,\"symbolic\":%u,\"cross\":%u,\"weak_zero\":%u}",i?",":"",m->name,m->relative,m->symbolic,m->cross,m->weak);}
 puts("],\"scope\":\"cross-module calls; constructors and game entry not run\"}");
}
#ifdef TOTK_MOD_SUBSDK1
/* Guest MemoryInfo as SVC 0x06 writes it: base, size, state, attribute, permission. */
typedef struct {uint64_t base,size;uint32_t state,attribute,permission,ipc,device,pad;} ProbeMemoryInfo;
typedef struct {uint64_t text,total,text_again,text_size,rodata,rodata_size,data,data_size;} ProbeRecord;
static int probe_query(const char *module,uint64_t address,ProbeMemoryInfo *info) {
 uint64_t r[32]={0};r[0]=(uint64_t)(uintptr_t)info;r[2]=address;
 uint64_t result=runtime_svc(0x06,r,module,address);
 return result==0&&r[0]==0;
}
typedef struct {ProbeRecord record[16];unsigned records,queries;uint64_t end;} ProbeScan;
/* Replays subsdk1 0x485c FindModules: QueryMemory(previous base + size), require text (state 3, R-X),
   rodata (state 3, R--) and data (state 4, RW-) in that order, write the 64-byte module record, and stop
   when a region base falls below the previous one (the 2^39 wrap). FindModules runs inside subsdk1, so
   the replay uses its SVC 0x06 view: "subsdk1" ends every free run at the module arena, hides the heap
   reservation and rejects unaligned free-run addresses. The game view is pinned separately below. */
static void probe_scan(const char *module,ProbeScan *out,int write_table) {
 Module *sub=&modules[3];
 memset(out,0,sizeof *out);
 unsigned phase=0,ended=0;uint64_t text=0,text_size=0,rodata=0,rodata_size=0,previous=0,next=0;
 int trace=getenv("TOTK_PROBE_MOD_TRACE")!=NULL;
 while(out->queries<4096&&!ended) {
  ProbeMemoryInfo info;need(probe_query(module,next,&info),"FindModules QueryMemory failed");
  need(info.size>0,"FindModules empty region");
  if(trace)fprintf(stderr,"[probe-mod] %s query %u addr=0x%llx base=0x%llx size=0x%llx state=%u perm=%u\n",module,out->queries+1,(unsigned long long)next,(unsigned long long)info.base,(unsigned long long)info.size,info.state,info.permission&7);
  if(info.base>=previous)need(next>=info.base&&next<info.base+info.size,"FindModules region does not contain the query");
  uint32_t state=info.state,permission=info.permission&7;
  if(phase==0) {
   if(state==3&&permission==5){text=info.base;text_size=info.size;phase=1;}
   else{text=text_size=rodata=rodata_size=0;}
  } else if(phase==1) {
   if(state==3&&permission==1){rodata=info.base;rodata_size=info.size;phase=2;}
   else{text=text_size=rodata=rodata_size=0;phase=0;}
  } else if(state==4&&permission==3) {
   need(out->records<sizeof(out->record)/sizeof(out->record[0]),"FindModules record overflow");
   ProbeRecord *p=&out->record[out->records];
   p->text=text;p->total=info.base+info.size-text;p->text_again=text;p->text_size=text_size;
   p->rodata=rodata;p->rodata_size=rodata_size;p->data=info.base;p->data_size=info.size;
   if(write_table) {
    if(text==(uintptr_t)sub->base){uint32_t index=out->records;memcpy(sub->base+0xc008,&index,4);}
    uint32_t count=out->records+1;memcpy(sub->base+0xc004,&count,4);
   }
   out->records++;text=text_size=rodata=rodata_size=0;phase=0;
  } else {text=text_size=rodata=rodata_size=0;phase=0;}
  out->queries++;
  if(info.base<previous)ended=1;else{previous=info.base;next=info.base+info.size;}
 }
 need(ended,"FindModules scan never wrapped at 2^39");
 need(next==(1ULL<<39),"FindModules scan ended before the 2^39 wrap");
 out->end=next;
 need(out->records==NM,"FindModules found a different module count");
}
static uint64_t probe_map(uint64_t dst,uint64_t src,uint64_t size) {
 uint64_t r[8]={0};r[0]=dst;r[1]=0xffff8001ULL;r[2]=src;r[3]=size;
 return runtime_svc(0x74,r,"subsdk1",0);
}
static uint64_t probe_unmap(uint64_t dst,uint64_t src,uint64_t size) {
 uint64_t r[8]={0};r[0]=dst;r[1]=0xffff8001ULL;r[2]=src;r[3]=size;
 return runtime_svc(0x75,r,"subsdk1",0);
}
static uint64_t probe_getinfo(const char *module,unsigned id) {
 uint64_t r[8]={0};r[1]=id;need(runtime_svc(0x29,r,module,0)==0,"GetInfo failed");return r[1];
}
static void probe_mod(void) {
 need(NM==MOD_COUNT,"mod build must load the expected module count");
 static const char *order[]=MOD_ORDER;
 for(unsigned i=0;i<NM;i++)need(!strcmp(modules[i].name,order[i]),"module order rtld/main/subsdk0/subsdk1/[subsdk3]/sdk");
 need(MAIN_MODULE_INDEX==1,"main must be the second module");
 uint8_t *arena=runtime_module_arena_base(),*arena_end=runtime_module_arena_end();
 need(arena!=NULL&&arena_end!=NULL,"module arena not allocated");
 need(arena==modules[0].base,"arena must start at rtld");
 need(arena_end==modules[NM-1].base+modules[NM-1].size,"arena must end after sdk");
 for(unsigned i=0;i<NM;i++) {
  Module *m=&modules[i];
  need(((uintptr_t)m->base&0x3fff)==0,"module base alignment");
  need(m->key_off%0x4000==0&&m->key_off+0x4000<=m->patch_off&&m->patch_off<page_up(m->file_size),"key/patch layout");
  need((uintptr_t)m->base+m->size<=(uintptr_t)arena_end,"module outside arena");
  if(i+1<NM)need(m->base+m->size==modules[i+1].base,"modules must be contiguous");
 }
 Module *sub=&modules[3];
 uint64_t module_start;memcpy(&module_start,sub->base+0xcb30,8);
 need(module_start==(uintptr_t)sub->base,"subsdk1 __module_start relocation");
 void *resolver=runtime_symbol("_ZN2nn2ro6detail35g_LookupGlobalManualFunctionPointerE");
 need(resolver==modules[0].base+modules[0].data_off,"rtld import export");
 uint64_t resolver_got;memcpy(&resolver_got,sub->base+0xcad8,8);
 need(resolver_got==(uint64_t)(uintptr_t)resolver,"subsdk1 rtld import relocation");
 uint32_t initial_count,initial_self;
 memcpy(&initial_count,sub->base+0xc004,4);memcpy(&initial_self,sub->base+0xc008,4);
 need(initial_count==0xffffffffu&&initial_self==0xffffffffu,"subsdk1 module table must start unset");
 ProbeScan baseline;probe_scan("subsdk1",&baseline,1);
 uint32_t count,self;memcpy(&count,sub->base+0xc004,4);memcpy(&self,sub->base+0xc008,4);
 need(count==NM,"module count global");
 need(self==3,"subsdk1 module index");
 for(unsigned i=0;i<NM;i++) {
  Module *m=&modules[i];ProbeRecord *p=&baseline.record[i];uint64_t rx=page_up(m->text_end);
  need(p->text==(uintptr_t)m->base&&p->text_again==(uintptr_t)m->base,"record text base");
  need(p->text_size==rx,"record text size");
  need(p->rodata==(uintptr_t)m->base+rx&&p->rodata_size==m->data_off-rx,"record rodata");
  need(p->data==(uintptr_t)m->base+m->data_off&&p->data_size==m->key_off-m->data_off,"record data");
  need(p->total==m->key_off,"record total size");
 }
 /* SVC 0x1e GetSystemTick: the caller does `bl; str x0`, so the tick is in x0, at 19.2 MHz. */
 {uint64_t r[8]={0};uint64_t t0=runtime_svc(0x1e,r,"probe-mod",0),n0=runtime_now_ns();
  need(t0>0,"GetSystemTick must be nonzero");
  usleep(50000);
  uint64_t t1=runtime_svc(0x1e,r,"probe-mod",0),n1=runtime_now_ns();
  need(t1>=t0,"GetSystemTick went backwards");
  uint64_t ticks=t1-t0,expect=(n1-n0)*12/625;
  need(ticks>0&&ticks<=expect+384000&&ticks+384000>=expect,"GetSystemTick is not a 19.2 MHz host tick");}
 /* SVC 0x29 GetInfo: the current-process handle exlaunch passes to MapProcessMemory, and the ASLR pool it allocates from. */
 {uint64_t lo=runtime_guest_low_base(),low_size=runtime_guest_low_size(),aslr_size;
  need(probe_getinfo("probe-mod",0xfde9)==0xffff8001ULL,"GetInfo FDE9 (game)");
  need(probe_getinfo("subsdk1",0xfde9)==0xffff8001ULL,"GetInfo FDE9 (subsdk1)");
  need(probe_getinfo("probe-mod",12)==lo,"GetInfo 12 (game)");
  aslr_size=probe_getinfo("probe-mod",13);
  need(aslr_size>=low_size,"game ASLR span must cover the low reservation");
  need(probe_getinfo("subsdk1",12)==lo,"GetInfo 12 (subsdk1)");
  need(probe_getinfo("subsdk1",13)==low_size,"GetInfo 13 (subsdk1)");
  /* QueryMemory has two views of the same map. exlaunch's module scan needs a monotonic one: the guest
     stack, the heap reservation and the module arena are separate regions, free runs end at the arena, and
     unaligned addresses read reserved so its 4 KiB allocator retries on a host page. The game keeps the
     retail view byte-for-byte, where [low, heap) is one free run (no guest stack region) and everything
     past the heap start up to the low reservation's end is free. */
  uint64_t stack0=probe_getinfo("probe-mod",14),heap0=probe_getinfo("probe-mod",4),heap_cap=probe_getinfo("probe-mod",5);
  ProbeMemoryInfo info;
  need(probe_query("subsdk1",lo,&info)&&info.base==lo&&info.size==stack0-lo&&info.state==0&&(info.permission&7)==0,"subsdk1 free run before the stack");
  need(probe_query("subsdk1",lo+0x1000,&info)&&info.base==lo+0x1000&&info.size==0x1000&&info.state==0x10,"unaligned free run must read reserved");
  need(probe_query("probe-mod",lo+0x1000,&info)&&info.base==lo&&info.size==heap0-lo&&info.state==0,"game view keeps the guest stack inside one free run");
  need(probe_query("subsdk1",heap0+0x200000,&info)&&info.base==heap0&&info.size==heap_cap&&info.state==0x10,"subsdk1 heap reservation");
  need(probe_query("probe-mod",heap0+0x200000,&info)&&info.base==heap0&&info.size>heap_cap&&info.state==0,"game view of the heap reservation");
  /* SVC 0x74/0x75: a congruent window must alias the module page; a non-congruent one must
     copy back on unmap. Windows are modelled in the exlaunch view, whose module scan they split. */
  Module *game=&modules[1];uint64_t src=page_up((uintptr_t)game->base+game->data_off);
  need(src+0x4000<=(uintptr_t)game->base+game->key_off,"window source must stay in main data");
  uint64_t dst1=page_up(lo+0x400000),dst2=page_up(lo+0x800000);
  need(dst1+0x4000<=stack0&&dst2+0x4000<=stack0,"window destinations must fit before the stack");
  uint64_t saved=0,saved_private=0,marker=0xdeadbeefcafebabeULL,marker2=0x0123456789abcdefULL;
  memcpy(&saved,(void *)(uintptr_t)src,8);memcpy(&saved_private,(void *)(uintptr_t)(src+0x1000),8);
  need(probe_map(dst1,src,0x1000)==0,"shared MapProcessMemory");
  need(probe_map(dst2,src+0x1000,0x1000)==0,"copied MapProcessMemory");
  memcpy((void *)(uintptr_t)dst1,&marker,8);
  need(!memcmp((void *)(uintptr_t)src,&marker,8),"shared window must alias the source");
  memcpy((void *)(uintptr_t)dst2,&marker2,8);
  need(memcmp((void *)(uintptr_t)(src+0x1000),&marker2,8)!=0,"copied window must not alias the source");
  need(probe_query("subsdk1",dst1,&info)&&info.base==dst1&&info.size==0x4000&&info.state==5&&(info.permission&7)==3,"window must be mapped in QueryMemory");
  need(probe_query("subsdk1",lo,&info)&&info.base==lo&&info.size==dst1-lo&&info.state==0,"free run must stop at the first window");
  need(probe_query("subsdk1",dst1+0x4000,&info)&&info.base==dst1+0x4000&&info.size==dst2-(dst1+0x4000)&&info.state==0,"free run between windows");
  need(probe_query("subsdk1",dst2+0x4000,&info)&&info.base==dst2+0x4000&&info.size==stack0-(dst2+0x4000)&&info.state==0,"free run after the windows");
  ProbeScan live;probe_scan("subsdk1",&live,0);
  need(live.records==baseline.records&&live.end==baseline.end,"FindModules with windows active");
  need(!memcmp(live.record,baseline.record,live.records*sizeof(ProbeRecord)),"windows must not change FindModules records");
  need(probe_unmap(dst2,src+0x1000,0x1000)==0,"UnmapProcessMemory (copied)");
  uint64_t back=0;memcpy(&back,(void *)(uintptr_t)(src+0x1000),8);
  need(back==marker2,"copied window must write back on unmap");
  need(probe_query("subsdk1",dst2,&info)&&info.base==dst1+0x4000&&info.size==stack0-(dst1+0x4000)&&info.state==0,"unmapped copied window must return to the free run");
  memcpy((void *)(uintptr_t)(src+0x1000),&saved_private,8);
  need(probe_unmap(dst1,src,0x1000)==0,"UnmapProcessMemory (shared)");
  memcpy((void *)(uintptr_t)src,&saved,8);
  need(probe_unmap(dst1,src,0x1000)==0xd401,"double unmap must be rejected");
  need(probe_query("subsdk1",lo,&info)&&info.base==lo&&info.size==stack0-lo&&info.state==0,"unmapped windows must restore the free run");
  need(probe_query("subsdk1",dst1,&info)&&info.base==lo&&info.size==stack0-lo,"window address must be free again");}
 printf("{\"status\":\"pass\",\"modules\":[");
 for(unsigned i=0;i<NM;i++)printf("%s\"%s\"",i?",":"",modules[i].name);
 printf("],\"main_index\":%u,\"arena\":\"0x%llx\",\"arena_bytes\":%llu,\"find_modules\":{\"count\":%u,\"self_index\":%u,\"queries\":%u,\"terminated\":\"wrap below 2^39\",\"records\":[",
  (unsigned)MAIN_MODULE_INDEX,(unsigned long long)(uintptr_t)arena,(unsigned long long)(arena_end-arena),count,self,baseline.queries);
 for(unsigned i=0;i<NM;i++){ProbeRecord *p=&baseline.record[i];printf("%s{\"name\":\"%s\",\"text\":\"0x%llx\",\"text_size\":%llu,\"rodata\":\"0x%llx\",\"rodata_size\":%llu,\"data\":\"0x%llx\",\"data_size\":%llu,\"total\":%llu}",i?",":"",modules[i].name,
  (unsigned long long)p->text,(unsigned long long)p->text_size,(unsigned long long)p->rodata,(unsigned long long)p->rodata_size,(unsigned long long)p->data,(unsigned long long)p->data_size,(unsigned long long)p->total);}
 puts("]},\"svc\":{\"system_tick\":\"19.2 MHz host tick in x0\",\"current_process\":\"0xffff8001\",\"aslr_pool\":\"subsdk1-scoped GetInfo 12/13\",\"query_memory\":\"heap reservation + 16 KiB alignment\",\"map_process_memory\":\"shared alias + copied write-back, QueryMemory split, double unmap rejected\"},"
  "\"scope\":\"module mapping, FindModules QueryMemory state machine and the exlaunch SVCs it needs; no DT_INIT, no game entry\"}");
}
static uint32_t probe_rd32(uintptr_t address) {uint32_t value;memcpy(&value,(void *)address,4);return value;}
static uint64_t probe_rd64(uintptr_t address) {uint64_t value;memcpy(&value,(void *)address,8);return value;}
/* Runs the three steps DT_INIT 0x4120 performs, in order and with the real module code:
   0x4000 static heap bounds, 0x40b4 FindModules/FindRegions/global RwPages ctor, 0x402c init array.
   DT_INIT then tail-branches to 0x53a4 (exlaunch main), which this probe deliberately does not enter. */
static void probe_mod_init(void) {
 need(NM==MOD_COUNT,"mod build must load the expected module count");
 static const char *order[]=MOD_ORDER;
 for(unsigned i=0;i<NM;i++)need(!strcmp(modules[i].name,order[i]),"module order rtld/main/subsdk0/subsdk1/[subsdk3]/sdk");
 uintptr_t base=(uintptr_t)modules[3].base;
 need(probe_rd64(base+0xcb30)==base,"subsdk1 __module_start relocation");
 /* The PLT stubs load the gate entry from the Darwin TSD slot named by key[3]; boot() sets it
    per thread before module init, so the probe must too. */
 runtime_thread_init();
 ((void(*)(void))(base+0x4000))();
 need(probe_rd64(base+0x125f8)==base+0xd3e0&&probe_rd64(base+0x12600)==base+0x123e0,"0x4000 static heap bounds");
 fprintf(stderr,"[probe-mod-init] 0x4000 static heap [0x%llx,0x%llx)\n",(unsigned long long)probe_rd64(base+0x125f8),(unsigned long long)probe_rd64(base+0x12600));
 ((void(*)(void))(base+0x40b4))();
 uint32_t count=probe_rd32(base+0xc004),self=probe_rd32(base+0xc008);
 need(count==NM,"real FindModules module count");
 need(self==3,"real FindModules self index");
 for(unsigned i=0;i<NM;i++) {
  Module *m=&modules[i];uintptr_t rec=base+0xd0a0+i*0x40;uint64_t rx=page_up(m->text_end);
  need(probe_rd64(rec+0x00)==(uintptr_t)m->base&&probe_rd64(rec+0x10)==(uintptr_t)m->base,"real record text base");
  need(probe_rd64(rec+0x18)==rx,"real record text size");
  need(probe_rd64(rec+0x20)==(uintptr_t)m->base+rx&&probe_rd64(rec+0x28)==m->data_off-rx,"real record rodata");
  need(probe_rd64(rec+0x30)==(uintptr_t)m->base+m->data_off&&probe_rd64(rec+0x38)==m->key_off-m->data_off,"real record data");
  need(probe_rd64(rec+0x08)==m->key_off,"real record total");
 }
 uint64_t lo=runtime_guest_low_base(),low_size=runtime_guest_low_size();
 uint64_t hbase=probe_getinfo("probe-mod",4),hcap=probe_getinfo("probe-mod",5);
 uint64_t abase=probe_getinfo("probe-mod",2),asize=probe_getinfo("probe-mod",3);
 need(probe_rd64(base+0x12550)==lo&&probe_rd64(base+0x12558)==lo+low_size,"FindRegions ASLR pool");
 need(probe_rd64(base+0x12560)==hbase&&probe_rd64(base+0x12568)==hbase+hcap,"FindRegions heap");
 need(probe_rd64(base+0x12570)==abase&&probe_rd64(base+0x12578)==abase+asize,"FindRegions alias");
 uintptr_t rw=base+0xd078;
 uint64_t src=probe_rd64(rw),alias=probe_rd64(rw+8),size=probe_rd64(rw+0x10);
 uint8_t active;memcpy(&active,(void *)(rw+0x20),1);
 need(active==1,"global RwPages active");
 need(src==(uintptr_t)modules[1].base,"global RwPages source is main");
 need(size==probe_rd64(base+0xd100)+probe_rd64(base+0xd108)-src,"global RwPages covers main text and rodata");
 need((alias&0x3fff)==0,"global RwPages alias alignment");
 need(alias>=lo&&size<=low_size&&alias-lo<=low_size-size,"global RwPages alias inside the ASLR pool");
 ProbeMemoryInfo info;
 need(probe_query("subsdk1",alias,&info)&&info.base==alias&&info.size>=0x4000&&info.state==5&&(info.permission&7)==3,"global window in exlaunch QueryMemory");
 need(!memcmp((void *)(uintptr_t)src,(void *)(uintptr_t)alias,0x1000),"global window aliases the source");
 fprintf(stderr,"[probe-mod-init] 0x40b4 modules=%u self=%u rwpages src=0x%llx alias=0x%llx size=0x%llx\n",count,self,(unsigned long long)src,(unsigned long long)alias,(unsigned long long)size);
 ((void(*)(void))(base+0x402c))();
 /* init_array entries 0xac8/0x20fc store {pointer, byte size} pairs into 0xd000/0xd040. */
 need(probe_rd64(base+0xd000)==base+0x1000&&probe_rd64(base+0xd008)==0x1000,"init_array[0] wrote its table");
 need(probe_rd64(base+0xd040)==base+0x3000&&probe_rd64(base+0xd048)==0x1000,"init_array[1] wrote its table");
 fprintf(stderr,"[probe-mod-init] 0x402c init array returned\n");
 printf("{\"status\":\"pass\",\"phase\":\"init-order\",\"steps\":[\"0x4000\",\"0x40b4\",\"0x402c\"],\"find_modules\":{\"count\":%u,\"self_index\":%u},\"regions\":{\"aslr\":\"0x%llx+0x%llx\",\"heap\":\"0x%llx+0x%llx\",\"alias\":\"0x%llx+0x%llx\"},"
  "\"rwpages\":{\"src\":\"0x%llx\",\"alias\":\"0x%llx\",\"size\":%llu,\"alias_aligned\":true},\"scope\":\"real subsdk1 DT_INIT steps 0x4000/0x40b4/0x402c; 0x53a4 exlaunch main not entered\"}\n",
  count,self,(unsigned long long)lo,(unsigned long long)low_size,(unsigned long long)hbase,(unsigned long long)hcap,(unsigned long long)abase,(unsigned long long)asize,
  (unsigned long long)src,(unsigned long long)alias,(unsigned long long)size);
}
/* DT_INIT 0x4120 runs the real init order and exlaunch main 0x53a4, which installs the v121 hook set.
   Every record is within +-128 MiB of its target, so each target receives a single B; an inline
   trampoline only relocates the one displaced instruction. The synthetic hook drives the whole
   record -> dispatcher -> callback -> trampoline -> target+4 path once. */
static unsigned probe_hook_calls;static uint64_t probe_hook_x0,probe_hook_x1;
static uint64_t probe_hook_callback(uint64_t *regs) {probe_hook_calls++;probe_hook_x0=regs[0];probe_hook_x1=regs[1];regs[0]=0x100;return 0;}
static uint64_t probe_branch_target(uint32_t insn,uintptr_t pc) {return (uint64_t)((int64_t)pc+(((int64_t)(int32_t)(insn<<6))>>6)*4);}
static void probe_check_target_branch(uintptr_t target,uintptr_t record,const char *message) {
 uint32_t insn=probe_rd32(target);
 need((insn&0xfc000000)==0x14000000,message);
 need(probe_branch_target(insn,target)==record,message);
}
static void probe_write_code(uintptr_t address,const uint32_t *insn,unsigned count) {
 uintptr_t page=address&~(uintptr_t)0x3fff;
 need(mprotect((void *)page,0x4000,PROT_READ|PROT_WRITE)==0,"unlock text page");
 memcpy((void *)address,insn,count*4);
 need(mprotect((void *)page,0x4000,PROT_READ|PROT_EXEC)==0,"relock text page");
 sys_icache_invalidate((void *)page,0x4000);
}
/* The relocator resumes with a direct B when target+4 is in range and with ldr x17/br x17/
   .quad when it is not; both forms are accepted. */
static int probe_resume_at(uintptr_t trampoline,unsigned off,uintptr_t at) {
 uint32_t insn=probe_rd32(trampoline+off);
 if((insn&0xfc000000)==0x14000000)return probe_branch_target(insn,trampoline+off)==at;
 return insn==0x58000051&&probe_rd32(trampoline+off+4)==0xd61f0220&&probe_rd64(trampoline+off+8)==at;
}
static void probe_check_trampoline(uintptr_t target,uintptr_t trampoline,uintptr_t alias) {
 need(probe_rd32(trampoline)!=0,"relocated trampoline instruction");
 need(!memcmp((void *)trampoline,(void *)alias,0x40),"published trampoline");
 int found=0;
 for(unsigned off=4;off<=0x30;off+=4)if(probe_resume_at(trampoline,off,target+4))found=1;
 if(!found){fprintf(stderr,"[probe-mod-hooks] no resume at target=%#llx trampoline=%#llx:",(unsigned long long)target,(unsigned long long)trampoline);
  for(unsigned off=0;off<0x30;off+=4)fprintf(stderr," %08x",probe_rd32(trampoline+off));fprintf(stderr,"\n");}
 need(found,"trampoline must resume at target+4");
}
static void probe_mod_hooks(void) {
 need(NM==MOD_COUNT,"mod build must load the expected module count");
 uintptr_t base=(uintptr_t)modules[3].base,mainb=(uintptr_t)modules[1].base;
 need(probe_rd64(base+0xcb30)==base,"subsdk1 __module_start relocation");
 runtime_thread_init();
 ((void(*)(void))(base+0x4120))();
 need(probe_rd64(base+0x125f8)==base+0xd3e0&&probe_rd64(base+0x12600)==base+0x123e0,"DT_INIT static heap bounds");
 need(probe_rd32(base+0xc004)==NM&&probe_rd32(base+0xc008)==3,"DT_INIT FindModules");
 need(probe_rd64(base+0xd0e0)==mainb&&probe_rd64(base+0x12508)==mainb,"DT_INIT main module base");
 need(probe_rd32(base+0x12510)==5,"DT_INIT display version index");
 need(probe_rd64(base+0x12520)==mainb+0x1111ae0&&probe_rd64(base+0x12528)==mainb+0x1111d14,"DT_INIT version pointers");
 need(probe_rd64(base+0xcaa8)==base+0x5bfc&&probe_rd32(base+0x5bfc)==0xd10403ff,"hook dispatcher");
 fprintf(stderr,"[probe-mod-hooks] inline=%llu trampolines=%u version=%u\n",(unsigned long long)probe_rd64(base+0xd038),probe_rd32(base+0xc000),probe_rd32(base+0x12510));
 need(probe_rd64(base+0xd038)==7&&probe_rd32(base+0xc000)==6,"DT_INIT hook counts");
 need(probe_rd64(base+0xd050)==base+0x3000&&probe_rd64(base+0xd010)==base+0x1000,"hook pools");
 static const uint32_t plain_target[3]={0x1111f6c,0x15714f4,0x1674bc4},plain_record[3]={0x509c,0x509c,0x50ec};
 static const uint32_t inline_target[7]={0x1111924,0x1795740,0x1795b5c,0x1794844,0x17953d8,0x17959cc,0x17947b0};
 static const uint32_t inline_callback[7]={0x50b0,0x5100,0x51b4,0x5280,0x5074,0x5074,0x5074};
 for(unsigned i=0;i<3;i++)probe_check_target_branch(mainb+plain_target[i],base+plain_record[i],"plain hook target must branch to its record");
 uint64_t record_alias=probe_rd64(base+0xd058),trampoline_alias=probe_rd64(base+0xd018);
 for(unsigned i=0;i<7;i++) {
  uintptr_t target=mainb+inline_target[i],record=base+0x3000+i*0x18,trampoline=base+0x1000+i*0xc8;
  probe_check_target_branch(target,record,"inline hook target must branch to its record");
  need(probe_rd32(record)==0xf81f03fe&&probe_rd32(record+8)==0xf85f03fe,"inline record save/restore");
  uint32_t bl=probe_rd32(record+4),b=probe_rd32(record+0xc);
  need((bl&0xfc000000)==0x94000000&&probe_branch_target(bl,record+4)==base+0x5bfc,"inline record must call the dispatcher");
  need((b&0xfc000000)==0x14000000&&probe_branch_target(b,record+0xc)==trampoline,"inline record must branch to its trampoline");
  need(probe_rd64(record+0x10)==base+inline_callback[i],"inline record callback");
  need(!memcmp((void *)record,(void *)(record_alias+i*0x18),0x18),"published inline record");
  probe_check_trampoline(target,trampoline,trampoline_alias+i*0xc8);
 }
 uintptr_t synthetic=base+0x7f00;
 for(unsigned i=0;i<2;i++)need(probe_rd32(synthetic+i*4)==0,"synthetic target must be text padding");
 static const uint32_t code[2]={0x11000400,0xd65f03c0};   /* add w0,w0,#1; ret */
 probe_write_code(synthetic,code,2);
 unsigned calls=probe_hook_calls;
 ((void(*)(uintptr_t,uintptr_t))(base+0x2018))(synthetic,(uintptr_t)probe_hook_callback);
 need(probe_rd64(base+0xd038)==8&&probe_rd32(base+0xc000)==7,"synthetic hook counters");
 uintptr_t srecord=base+0x3000+7*0x18,strampoline=base+0x1000+7*0xc8;
 probe_check_target_branch(synthetic,srecord,"synthetic target must branch to its record");
 need(probe_rd64(srecord+0x10)==(uintptr_t)probe_hook_callback,"synthetic callback record");
 need(!memcmp((void *)srecord,(void *)(probe_rd64(base+0xd058)+7*0x18),0x18),"published synthetic record");
 probe_check_trampoline(synthetic,strampoline,probe_rd64(base+0xd018)+7*0xc8);
 uint64_t result=((uint64_t(*)(uint64_t,uint64_t))synthetic)(7,0x5678);
 need(result==0x101,"synthetic hook must return through the relocated prologue");
 need(probe_hook_calls==calls+1&&probe_hook_x0==7&&probe_hook_x1==0x5678,"synthetic hook callback registers");
 printf("{\"status\":\"pass\",\"phase\":\"hooks\",\"version_index\":%u,\"main_base\":\"0x%llx\",\"subsdk1_base\":\"0x%llx\",\"dispatcher\":\"0x%llx\",\"counters\":{\"inline\":8,\"trampolines\":7,\"real_inline\":7},\"plain\":[",
  probe_rd32(base+0x12510),(unsigned long long)mainb,(unsigned long long)base,(unsigned long long)probe_rd64(base+0xcaa8));
 for(unsigned i=0;i<3;i++)printf("%s{\"target\":\"0x%llx\",\"record\":\"0x%llx\"}",i?",":"",(unsigned long long)(mainb+plain_target[i]),(unsigned long long)(base+plain_record[i]));
 printf("],\"inline\":[");
 for(unsigned i=0;i<7;i++)printf("%s{\"target\":\"0x%llx\",\"record\":\"0x%llx\",\"callback\":\"0x%llx\",\"trampoline\":\"0x%llx\"}",i?",":"",
  (unsigned long long)(mainb+inline_target[i]),(unsigned long long)(base+0x3000+i*0x18),(unsigned long long)(base+inline_callback[i]),(unsigned long long)(base+0x1000+i*0xc8));
 printf("],\"synthetic\":{\"target\":\"0x%llx\",\"record\":\"0x%llx\",\"trampoline\":\"0x%llx\",\"returned\":%llu,\"callback_x0\":%llu,\"callback_x1\":%llu},"
  "\"scope\":\"real DT_INIT hook set at executable source + end-to-end dispatcher, callback register round trip and relocated prologue; no game entry\"}\n",
  (unsigned long long)synthetic,(unsigned long long)srecord,(unsigned long long)strampoline,(unsigned long long)result,(unsigned long long)probe_hook_x0,(unsigned long long)probe_hook_x1);
}
#ifdef TOTK_MOD_SUBSDK3
/* UltraCam gate: exlaunch's DT_INIT runs first (it installs the hook set and fills the module table),
   then subsdk3's own DT_INIT, in the same order module_inits() uses during a real boot. subsdk3 carries
   236 init_array entries, so the first service the port has not implemented aborts by name; that turns
   the remaining work list into evidence instead of guesswork. */
int runtime_module_offset(uint64_t pc,const char **name,uint64_t *off);
static void probe_uc_init(void) {
 need(NM==MOD_COUNT,"mod build must load the expected module count");
 Module *sub=&modules[3],*uc=&modules[4];
 need(!strcmp(uc->name,"subsdk3"),"subsdk3 must be the fifth module");
 need(sub->init==0x4120,"subsdk1 DT_INIT offset");
 need(uc->init==0x1c918c,"subsdk3 DT_INIT offset");
 need(uc->init_size%8==0&&uc->init_size/8==236,"subsdk3 init_array entry count");
 need(probe_rd32((uintptr_t)sub->base+0xc004)==0xffffffffu,"subsdk1 module table must start unset");
 runtime_thread_init();
 ((void(*)(void))((uintptr_t)sub->base+sub->init))();
 need(probe_rd32((uintptr_t)sub->base+0xc004)==NM&&probe_rd32((uintptr_t)sub->base+0xc008)==3,"subsdk1 FindModules reports every module");
 fprintf(stderr,"[probe-uc-init] subsdk3 DT_INIT=%#llx init_array=%#llx entries=%llu weak=%u cross=%llu\n",
  (unsigned long long)uc->init,(unsigned long long)uc->init_array,(unsigned long long)(uc->init_size/8),uc->weak,(unsigned long long)uc->cross);
 ((void(*)(void))((uintptr_t)uc->base+uc->init))();
 fprintf(stderr,"[probe-uc-init] subsdk3 DT_INIT returned\n");
 /* What a hook of an SDK body actually looks like in memory: UltraCam's NvnBootstrapHook installs at
    nvnBootstrapLoader (sdk+0x4900b0), so the bytes there say how wide its patch is and where it branches. */
 { Module *sdk=&modules[5]; need(!strcmp(sdk->name,"sdk"),"the sixth module must be sdk");
  uintptr_t t=(uintptr_t)sdk->base+0x4900b0;
  fprintf(stderr,"[probe-uc-init] %s+0x4900b0:",sdk->name);
  for(int i=0;i<8;i++)fprintf(stderr," %08x",probe_rd32(t+i*4));
  fprintf(stderr,"\n");
  uint32_t w=probe_rd32(t);
  if((w>>26)==0x05) {   /* b <26-bit displacement>: the narrowest patch a mod can leave behind */
   int64_t disp=((w&0x3ffffffu)^0x2000000u)-(int64_t)0x2000000u;disp*=4;
   uintptr_t h=t+disp;const char *hn;uint64_t ho;
   fprintf(stderr,"[probe-uc-init] body branches to %p",  (void *)h);
   if(runtime_module_offset(h,&hn,&ho))fprintf(stderr," = %s+0x%llx",hn,(unsigned long long)ho);
   fprintf(stderr,"\n[probe-uc-init] there:");
   for(int i=0;i<6;i++)fprintf(stderr," %08x",probe_rd32(h+i*4));
   fprintf(stderr,"\n");
  } else fprintf(stderr,"[probe-uc-init] body word %#x is not a branch\n",w);
 }
 printf("{\"status\":\"pass\",\"phase\":\"uc-init\",\"subsdk1_base\":\"0x%llx\",\"subsdk3_base\":\"0x%llx\",\"modules\":%u,\"subsdk3_init\":\"0x%llx\",\"subsdk3_init_array\":\"0x%llx\",\"subsdk3_ctors\":%llu}\n",
  (unsigned long long)sub->base,(unsigned long long)uc->base,probe_rd32((uintptr_t)sub->base+0xc004),
  (unsigned long long)uc->init,(unsigned long long)uc->init_array,(unsigned long long)(uc->init_size/8));
}
#endif
int runtime_module_offset(uint64_t pc,const char **name,uint64_t *off);
/* An exlaunch module patches a guest function by replacing its first instruction with a branch into its own image;
   every record is within +-128 MiB of its target, so that single B is the only form to look for (see probe_mod_hooks).
   From the host a mod's hook set is otherwise invisible - this names the functions it chose, with the exported symbol
   each site falls in, once every DT_INIT has run (TOTK_PROBE_HOOKS=1).
   TOTK_MOD_UNHOOK additionally turns hooks off, which is how a mod's behaviour change is attributed to one of them:
   a record branches to its trampoline after calling the mod's callback, so a site that branches straight to the
   trampoline runs the displaced instruction and continues at target+4 - the function exactly as the game wrote it,
   with the mod's code skipped. Tokens: uc-all, uc-first-<n>, or <module>+0x<offset> lists. */
typedef struct { const char *mod; uint64_t off; } HookSite;
static HookSite unhook_wanted[128]; static int unhook_n, unhook_all; static long unhook_first;
static const char *unhook_only;   /* restrict by the module the site is in: uc-main / uc-sdk */
static int unhook_module(const char *mod) { return !unhook_only||!strcmp(unhook_only,mod); }
static int unhook_selected(const char *mod,uint64_t off,unsigned index) {
 if(!unhook_module(mod))return 0;
 for(int i=0;i<unhook_n;i++)if(!strcmp(unhook_wanted[i].mod,mod)&&unhook_wanted[i].off==off)return 1;
 if(unhook_all)return 1;
 return unhook_first>0&&(long)index<unhook_first;
}
static void unhook_parse(void) {
 const char *e=getenv("TOTK_MOD_UNHOOK");if(!e||!*e)return;
 for(const char *tok=e;tok&&*tok;) {
  const char *end=strchr(tok,',');size_t n=end?(size_t)(end-tok):strlen(tok);char spec[40];
  if(n<sizeof spec) {memcpy(spec,tok,n);spec[n]=0;
   const char *plus=strchr(spec,'+');
   if(!strcmp(spec,"uc-all"))unhook_all=1;
   else if(!strcmp(spec,"uc-main")){unhook_only="main";unhook_all=1;}
   else if(!strncmp(spec,"uc-main-",8)&&isdigit(spec[8])){unhook_only="main";unhook_first=atol(spec+8);}
   else if(!strcmp(spec,"uc-sdk")){unhook_only="sdk";unhook_all=1;}
   else if(plus) {
    char name[16];size_t ln=(size_t)(plus-spec);
    if(ln<sizeof name&&plus[1]=='0'&&plus[2]=='x') {
     memcpy(name,spec,ln);name[ln]=0;uint64_t off=strtoull(plus+1,NULL,16);int known=0;
     for(int i=0;i<unhook_n;i++)if(!strcmp(unhook_wanted[i].mod,name)&&unhook_wanted[i].off==off)known=1;
     if(!known&&unhook_n<(int)(sizeof unhook_wanted/sizeof*unhook_wanted))
      unhook_wanted[unhook_n++]=(HookSite){strdup(name),off};
    } else fprintf(stderr,"[unhook] 不认识的项：%s\n",spec);
   } else fprintf(stderr,"[unhook] 不认识的项：%s\n",spec);}
  tok=end?end+1:NULL;
 }
 fprintf(stderr,"[unhook] 配置 %s：点名 %d 处 全关=%d 前 %ld 个 只限 %s\n",e,unhook_n,unhook_all,unhook_first,unhook_only?unhook_only:"所有模块");
}
static void report_hook_targets(void) {
 if(!getenv("TOTK_PROBE_HOOKS")&&!getenv("TOTK_MOD_UNHOOK"))return;
 unhook_parse();
 unsigned n=0;
 for(unsigned i=0;i<NM;i++) {
  Module *m=&modules[i];
  if(!strcmp(m->name,"subsdk1")||!strcmp(m->name,"subsdk3"))continue;   /* a mod branches freely inside itself */
  uintptr_t end=(uintptr_t)m->base+page_up(m->text_end);
  for(uintptr_t site=(uintptr_t)m->base;site+16<end;site+=4) {
   uint32_t w=probe_rd32(site);uint64_t target;
   if((w&0xfc000000)==0x14000000)target=probe_branch_target(w,site);
   else if(w==0x58000051&&probe_rd32(site+4)==0xd61f0220)target=probe_rd64(site+8);
   else continue;
   const char *tn=NULL;uint64_t to=0;
   if(!runtime_module_offset(target,&tn,&to))continue;
   if(strcmp(tn,"subsdk1")&&strcmp(tn,"subsdk3"))continue;
   uint64_t here=site-(uintptr_t)m->base,best=0;const char *name=NULL;
   for(unsigned j=1;j<m->nsym;j++) {const Symbol *s=&m->symbols[j];
    if(s->defined&&s->value<m->key_off&&s->value<=here&&(!name||s->value>best)){best=s->value;name=s->name;} }
   if(name)fprintf(stderr,"[hooks] %s+0x%llx -> %s+0x%llx  最近导出 %s+0x%llx\n",m->name,(unsigned long long)here,
    tn,(unsigned long long)to,name,(unsigned long long)(here-best));
   else fprintf(stderr,"[hooks] %s+0x%llx -> %s+0x%llx\n",m->name,(unsigned long long)here,tn,(unsigned long long)to);
   n++;
   if(strcmp(tn,"subsdk3")||getenv("TOTK_MOD_UNHOOK")==NULL||!unhook_selected(m->name,here,n-1))continue;
   /* The mod overwrote exactly one word (the branch it installed), so the function's remaining body is still the
      game's. The rewritten image on disk holds that word untouched, and module offsets are file offsets in it, so
      writing it back un-hooks the site completely - including the plain hooks, which replace a function and leave
      no trampoline to jump around. */
   uint32_t original=0;char path[4096];int restored=0;
   if(image_dir) {
    snprintf(path,sizeof path,"%s/%s.patched.bin",image_dir,m->name);
    int fd=open(path,O_RDONLY);
    if(fd>=0) { ssize_t got=pread(fd,&original,4,(off_t)here);close(fd);restored=got==4&&original!=w; }
   }
   if(!restored){fprintf(stderr,"[unhook] %s+0x%llx：读不到原始指令（镜像 %s），保持挂钩\n",m->name,(unsigned long long)here,path);continue;}
   probe_write_code(site,&original,1);
   fprintf(stderr,"[unhook] %s+0x%llx 恢复原指令 %#08x（原先跳 %s+0x%llx，mod 回调不再执行）\n",
    m->name,(unsigned long long)here,original,tn,(unsigned long long)to);
  }
 }
 fprintf(stderr,"[hooks] %u patched sites branch into a mod image\n",n);
}
#endif
int runtime_module_offset(uint64_t pc,const char **name,uint64_t *off) {
 for(unsigned i=0;i<NM;i++)if(pc>=(uintptr_t)modules[i].base&&pc<(uintptr_t)modules[i].base+modules[i].size){*name=modules[i].name;*off=pc-(uintptr_t)modules[i].base;return 1;}
 return 0;
}
uintptr_t runtime_frame_controller_return_pc(void) {
#ifdef GAME_BOTW
 return 0; /* no survey on Breath of the Wild */
#elif defined(TOTK_GAME_V143)
 /* The older graphics diagnostic reads the pre-1.4 controller layout. The survey only needs the system object (caller's x19
    at x29 + 0x38, same frame as 1.2.1) for its frame-end fence, so 1.4.3 finds it only while TOTK_SURVEY is on. */
 const char *survey=getenv("TOTK_SURVEY");
 return survey&&!strcmp(survey,"1")?(uintptr_t)modules[MAIN_MODULE_INDEX].base+GAME_ADDR(0x8f6cbc):0;
#else
 return (uintptr_t)modules[MAIN_MODULE_INDEX].base + GAME_ADDR(0x8f6cbc);
#endif
}
uint64_t runtime_image_bytes(void) { uint64_t total=0;for(unsigned i=0;i<NM;i++)total+=modules[i].key_off;return page_up(total); }
static void loader_ready(void) { fprintf(stderr,"[totk] rtld callback: modules linked\n"); }
static void module_inits(void) {
 fprintf(stderr,"[totk] SDK startup returned; running module constructors\n");
 for(unsigned i=0;i<NM;i++){char detail[128];snprintf(detail,sizeof detail,TOTK_UI("运行 %s 游戏模块初始化代码（%u/%u）","Running the %s game module initializers (%u/%u)"),modules[i].name,i+1,(unsigned)NM);runtime_boot_status(TOTK_UI("初始化游戏模块","Initializing game modules"),detail);
  if(!modules[i].init){fprintf(stderr,"[totk] %s has no DT_INIT\n",modules[i].name);continue;}
  {const char *skip=getenv("TOTK_MOD_SKIP_INIT");
   int skipped=0;
   for(const char *tok=skip;tok&&*tok;){const char *end=strchr(tok,',');size_t n=end?(size_t)(end-tok):strlen(tok);
    if(n==strlen(modules[i].name)&&!strncmp(tok,modules[i].name,n)){skipped=1;break;}tok=end?end+1:NULL;}
   if(skipped){fprintf(stderr,"[totk] SKIP %s DT_INIT (TOTK_MOD_SKIP_INIT)\n",modules[i].name);continue;}}
  fprintf(stderr,"[totk] ENTER %s DT_INIT\n",modules[i].name);((void(*)(void))(modules[i].base+modules[i].init))();
  if(modules[i].ctor_flag){uint32_t state;memcpy(&state,modules[i].base+modules[i].ctor_flag,4);need(state==2,"DT_INIT deferred or skipped constructors");
   fprintf(stderr,"[totk] RETURN %s DT_INIT state=%u init_array_count=%llu\n",modules[i].name,state,(unsigned long long)(modules[i].init_size/8));}
  else fprintf(stderr,"[totk] RETURN %s DT_INIT init_array_count=%llu\n",modules[i].name,(unsigned long long)(modules[i].init_size/8));}
#ifdef TOTK_MOD_SUBSDK1
 report_hook_targets();
#endif
}
void runtime_startup_checkpoint(uintptr_t caller) {
 if(!getenv("TOTK_VERIFY_STARTUP"))return;
 need(caller==(uintptr_t)modules[MAIN_MODULE_INDEX].base+GAME_ADDR(0xe995c4),"checkpoint not reached from original nnMain");
 for(unsigned i=0;i<NM;i++){if(!modules[i].ctor_flag)continue;uint32_t state;memcpy(&state,modules[i].base+modules[i].ctor_flag,4);need(state==2,"constructor checkpoint state");}
 printf("{\"status\":\"pass\",\"phase\":4,\"original_nnMain_return_pc\":\"0x%x\",\"scope\":\"all DT_INIT constructor loops completed; original nnMain prefix executed; stops at focus setup\"}\n", GAME_ADDR(0xe995c4));fflush(stdout);_exit(0);
}
#ifndef GAME_BOTW160
static void module_finis(void) { runtime_fail("guest exited: module finalizers not yet implemented"); }
#endif
static void boot(void) {
 fprintf(stderr,"[totk] game version %s\n", TOTK_GAME_VERSION);
 runtime_boot_status(TOTK_UI("启动游戏运行环境","Starting the game runtime"),TOTK_UI("连接游戏代码与 macOS 系统服务","Connecting the game code to macOS system services"));
 runtime_thread_init();uint32_t main_handle=svc_thread_main_init();
#ifdef GAME_BOTW
 /* SDK 7.3.2 (Breath of the Wild 1.6.0): Start(handle, arg, rtld callback, module initializers). The order inside is the one of
    TOTK's SDK 15 (libc0, nnosInitialize, callback, libc1, InitializeSdkModule, nninitStartup, libc2, callback, nnMain), but
    after nnMain it calls nninitFinalizeSdkModule and quick-exits itself instead of a third callback. */
 /* Host functions called from the main thread run on a stack of their own (8 MiB, guard page), as on every other guest
    thread: the host-stack slot is then set while it runs guest code and cleared inside host code, which is how an
    asynchronous preemption signal tells the two apart (threads.c preempt_signal). Without it a better thread that only
    runs on core 0 waited for the main thread's next SVC (botw.md). */
 if(!getenv("TOTK_MAIN_PREEMPT")||strcmp(getenv("TOTK_MAIN_PREEMPT"),"0")){extern void runtime_hle_stack_set(uintptr_t top);size_t n=8u<<20;void *hs=mmap(NULL,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  need(hs!=MAP_FAILED&&mprotect(hs,0x4000,PROT_NONE)==0,"main thread host-service stack");runtime_hle_stack_set((uintptr_t)hs+n-64);}
#endif
#ifdef GAME_BOTW160
 fprintf(stderr,"[totk] ENTER original nn::init::Start (SDK 7)\n");
 ((void(*)(uint64_t,uint64_t,void(*)(void),void(*)(void)))required("_ZN2nn4init5StartEmmPFvvES2_"))(main_handle,0,loader_ready,module_inits);
#elif defined(GAME_BOTW)   /* 1.9.0 (SDK 20.5) takes the five-argument Start of TOTK's SDK */
 fprintf(stderr,"[totk] ENTER original nn::init::Start (SDK 20.5)\n");
 ((void(*)(uint64_t,uint64_t,void(*)(void),void(*)(void),void(*)(void)))required("_ZN2nn4init5StartEmmPFvvES2_S2_"))(main_handle,0,loader_ready,module_inits,module_finis);
#else
 fprintf(stderr,"[totk] ENTER original nn::init::Start sdk+0xfa060\n");
 ((void(*)(uint64_t,uint64_t,void(*)(void),void(*)(void),void(*)(void)))required("_ZN2nn4init5StartEmmPFvvES2_S2_"))(main_handle,0,loader_ready,module_inits,module_finis);
#endif
 runtime_fail("SDK Start unexpectedly returned");
}
/* Host aborts (e.g. Metal validation assertions) print the host call stack before the process ends. */
#include <execinfo.h>
static void abort_report(int num) {
 (void)num;void *frames[64];int n=backtrace(frames,64);write(2,"[totk] host abort, call stack:\n",31);backtrace_symbols_fd(frames,n,2);
 signal(SIGABRT,SIG_DFL);raise(SIGABRT);
}
int main(int argc,char **argv) {
 need(argc==3,"usage: totk-native rewritten-dir probe|probe-mod|boot");
 /* One game or GPU probe at a time (memory, GPU time): wait for the slot before anything is loaded. */
 if(!strcmp(argv[2],"boot")||!strncmp(argv[2],"probe-gpu",9))runtime_game_slot_acquire(argv[2]);
 if(strcmp(argv[2],"boot"))setenv("TOTK_PROBE_GPU","1",1);   /* standalone probes submit GPU work; the game does not unless TOTK_GPU_ALLOW_SUBMIT=1 */
 else unsetenv("TOTK_PROBE_GPU");need(sysconf(_SC_PAGESIZE)==0x4000,"expected 16KB Apple pages");
 struct sigaction a={0};a.sa_sigaction=crash;a.sa_flags=SA_SIGINFO|SA_ONSTACK;sigemptyset(&a.sa_mask);
 sigaction(SIGSEGV,&a,NULL);sigaction(SIGBUS,&a,NULL);sigaction(SIGILL,&a,NULL);sigaction(SIGTRAP,&a,NULL);
 {struct sigaction ab={0};ab.sa_handler=abort_report;ab.sa_flags=SA_ONSTACK;sigemptyset(&ab.sa_mask);sigaction(SIGABRT,&ab,NULL);}
 for(unsigned i=0;i<8;i++)need(pthread_key_create(&runtime_keys[i],NULL)==0&&runtime_keys[i]!=0,"allocate Darwin key");
 runtime_hle_stack_init((uint64_t)runtime_keys[4]*8);
 need(pthread_key_create(&environment_key,environment_destroy)==0,"thread environment key");
 load_tables();
 for(unsigned i=0;i<NM;i++)map_module(&modules[i],argv[1]);
 for(unsigned i=0;i<NM;i++)relocate(&modules[i]);
 for(unsigned i=0;i<NM;i++)if(!strcmp(modules[i].name,"main"))runtime_game_patches(&modules[i]);
#if !TARGET_OS_IPHONE
 if(!strcmp(argv[2],"export-ios")){const char *out=getenv("TOTK_EXPORT_IOS");need(out!=NULL,"export-ios needs TOTK_EXPORT_IOS=<dir>");export_ios_text(argv[1],out);return 0;}
#endif
 verify_identity(!strcmp(argv[2],"probe-identity-negative"));
#ifdef TOTK_MOD_SUBSDK3
 redirect_sdk_bodies();   /* while the text pages are still writable */
 route_redirected_imports();   /* likewise: a mod's trampoline in one of those bodies has to be in the call path */
#endif
 for(unsigned i=0;i<NM;i++){seal(&modules[i]);check_permissions(&modules[i]);}
 if(!strcmp(argv[2],"probe-gpu-writeback")||!strcmp(argv[2],"probe-gpu-sampler-border")||!strcmp(argv[2],"probe-gpu-pool-retire")||!strcmp(argv[2],"probe-gpu-tex-slots")||!strcmp(argv[2],"probe-gpu-arg-epoch")||!strcmp(argv[2],"probe-gpu-anomaly")||!strcmp(argv[2],"probe-gpu-vertex-streams")||!strcmp(argv[2],"probe-gpu-vin")||!strcmp(argv[2],"probe-gpu-fout")||!strcmp(argv[2],"probe-gpu-pipeline-archive")||!strcmp(argv[2],"probe-gpu-layer-merge")||!strcmp(argv[2],"probe-gpu-cube-merge")||!strcmp(argv[2],"probe-gpu-texture-retire")||!strcmp(argv[2],"probe-gpu-texels-region")||!strcmp(argv[2],"probe-gpu-linear-rt")||!strcmp(argv[2],"probe-gpu-storage-view")||!strcmp(argv[2],"probe-gpu-compressed-alias")||!strcmp(argv[2],"probe-gpu-upload-batch")||!strcmp(argv[2],"probe-gpu-ds-clear")||!strcmp(argv[2],"probe-gpu-ub-rename")||!strcmp(argv[2],"probe-gpu-ubo-snapshot")||!strcmp(argv[2],"probe-gpu-drv-c0")||!strcmp(argv[2],"probe-gpu-dispatch-chain")||!strcmp(argv[2],"probe-gpu-copy-alias")||!strcmp(argv[2],"probe-gpu-srgb-view")||!strcmp(argv[2],"probe-gpu-depth-output"))runtime_gpu_path_probe(argv[2]);else if(!strcmp(argv[2],"probe-memory"))runtime_memory_probe();else if(!strcmp(argv[2],"probe-gfx"))runtime_gfx_probe(0);else if(!strcmp(argv[2],"probe-vpool"))runtime_vpool_probe();else if(!strcmp(argv[2],"probe-gpu-widen")||!strcmp(argv[2],"probe-gpu-blockrt")||!strcmp(argv[2],"probe-gpu-midclear")||!strcmp(argv[2],"probe-gpu-winding")||!strcmp(argv[2],"probe-gpu-tile"))runtime_gpu_path_probe(argv[2]);else if(!strcmp(argv[2],"probe-audio"))runtime_audio_probe();else if(!strcmp(argv[2],"probe-gfx-negative"))runtime_gfx_probe(1);else if(!strcmp(argv[2],"probe"))probe();
#ifdef TOTK_MOD_SUBSDK1
 else if(!strcmp(argv[2],"probe-mod"))probe_mod();
 else if(!strcmp(argv[2],"probe-mod-init"))probe_mod_init();
 else if(!strcmp(argv[2],"probe-mod-hooks"))probe_mod_hooks();
 #ifdef TOTK_MOD_SUBSDK3
 else if(!strcmp(argv[2],"probe-uc-init"))probe_uc_init();
 #endif
#endif
else if(!strcmp(argv[2],"probe-fs"))runtime_fs_probe();else if(!strcmp(argv[2],"probe-swkbd"))runtime_swkbd_probe();else if(!strcmp(argv[2],"probe-save"))runtime_save_probe();else if(!strcmp(argv[2],"boot")){if(getenv("TOTK_VERIFY_STARTUP")||getenv("TOTK_HEADLESS"))boot();else runtime_front_run(boot);}else runtime_fail("unknown mode");return 0;
}
