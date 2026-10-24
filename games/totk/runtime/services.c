/* Horizon services reached by the current TOTK startup. Unknown operations fail. */
#include "runtime.h"
#include "game_version.h"
#include <TargetConditionals.h>
#include "ipc.h"
#include <mach/mach.h>
#include "mach_vm_compat.h"
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>

#include <time.h>
#include <unistd.h>
#include <mach/mach_time.h>
/* Guest address layout. The SDK encodes IPC buffer addresses with 39 bits (HIPC descriptor bits 36..38),
   so all guest memory must lie below 2^39. Darwin arm64 keeps 0x10_0000_0000..0x70_0000_0000 reserved,
   leaving exactly 64 GiB at 0x70_0000_0000 for the alias region (the real 39-bit Horizon size, which the
   game's allocators depend on); the stack and heap regions are reserved separately below it. */
#define GUEST_ADDRESS_LIMIT (1ULL<<39)
#define ALIAS_SPACE_AT 0x7000000000ULL
#define ALIAS_SIZE_MAX (64ULL<<30)
/* TOTK_ALIAS_GIB: alias region size reported to the game (default 64, the real 39-bit Horizon size). An iOS app signed
   without extended virtual addressing (unavailable to personal teams) gets a much smaller map: the old 6 + 16 GiB
   reservation failed on an iPhone, while 4.75 + 16 GiB fit on an iPad (A16, iPadOS 26.7). So the largest size from 16
   down to 4 GiB that fits is chosen at startup; the game maps about 3.3 GiB of it. */
#if TARGET_OS_IPHONE
#define ALIAS_DEFAULT_GIB 16
#define ALIAS_MIN_GIB 4ULL
#else
#define ALIAS_DEFAULT_GIB 64
#endif
static uint64_t alias_len;
static uint64_t alias_requested(void){const char *e=getenv("TOTK_ALIAS_GIB");uint64_t g=e?strtoull(e,NULL,0):ALIAS_DEFAULT_GIB;if(g<1||g>64)runtime_fail("TOTK_ALIAS_GIB must be 1..64");return g<<30;}
static uint64_t alias_size(void){if(!alias_len)alias_len=alias_requested();return alias_len;}
#define ALIAS_SIZE alias_size()
#define LOW_SEARCH_FROM 0x300000000ULL
#define ARENA_SIZE (0x40000000ULL)
#ifdef TOTK_MOD_SUBSDK1
#define ARENA_TAIL ARENA_SIZE   /* the module arena keeps the last GiB of the reservation */
#else
#define ARENA_TAIL 0
#endif
#if TARGET_OS_IPHONE
#define LOW_SIZE_MIN (HEAP_OFF+HEAP_CAP_DEFAULT+ARENA_TAIL)   /* iOS: no slack after the heap cap; address space is scarce */
#else
#define LOW_SIZE_MIN (6ULL<<30)
#endif
#define STACK_OFF 0x10000000ULL
#define STACK_SIZE 0x10000000ULL
#define HEAP_OFF (STACK_OFF+STACK_SIZE+0x10000000ULL)
#ifdef TOTK_MOD_SUBSDK1
/* The module arena is the tail of the reservation, so a reservation grown for a bigger pool leaves it room. */
#define ARENA_OFF (low_size()-ARENA_SIZE)
static uint64_t arena_used;
#endif
static uint8_t *alias_space,*low_space,*heap;
static size_t heap_size;
static unsigned char alias_pages[ALIAS_SIZE_MAX/4096];
/* 4 KiB guest pages that are unmapped but whose host 16 KiB page is still committed with old contents: only these are
   zeroed when mapped again. Every other free page is untouched anonymous memory (zero on first touch), so mapping does
   not make it resident; a fully free 16 KiB host page is handed back to the system (fresh anonymous mapping). On the
   iPhone, where the app may use about 4 GB in total, memory the game maps but never touches must stay unbacked. */
static unsigned char alias_stale[ALIAS_SIZE_MAX/4096];
static uint64_t alias_bytes;
static uint8_t user_exception_context[0x1000] __attribute__((aligned(0x1000)));
#define SYSTEM_RESOURCE_BUDGET (32ULL<<20)
#ifdef GAME_BOTW
#define GAME_PROGRAM_ID 0x01007ef00011e000ULL   /* GetInfo 18 (ProgramId): Breath of the Wild */
#else
#define GAME_PROGRAM_ID 0x0100f2c0115b6000ULL
#endif
#define HEAP_CAP_DEFAULT (4ULL<<30)   /* 1.4.3 sets a 2.2 GiB heap during nninitStartup */
#define HEAP_CAP_MAX (16ULL<<30)   /* largest heap a raised pool can ask for */
#ifdef TOTK_MOD_SUBSDK1
_Static_assert(HEAP_OFF+HEAP_CAP_DEFAULT+ARENA_SIZE<=LOW_SIZE_MIN,"module arena must fit the smallest low reservation");
#endif
#define APP_POOL app_pool()
static uint64_t app_pool(void){static uint64_t v;if(!v){const char *e=getenv("TOTK_APP_POOL");uint64_t extra=(runtime_output_res_extra_bytes()+0x1fffff)&~0x1fffffULL;
 v=e?strtoull(e,NULL,0):0xcd500000ULL+extra;if(!e&&extra)fprintf(stderr,"[totk] application pool %#llx: +%llu MiB for the bigger texture heaps (TOTK_OUTPUT_RES, TOTK_RENDER_RES)\n",(unsigned long long)v,(unsigned long long)(extra>>20));}return v;}
/* TOTK: application memory pool reported to the game (default: retail 3.2 GiB; TOTK_OUTPUT_RES adds what its HeapDef overlay gives the texture heaps) */
#define ALIAS_START ((uintptr_t)alias_space)
#define STACK_START ((uintptr_t)low_space+STACK_OFF)
#define ASLR_START ((uintptr_t)low_space)
#if TARGET_OS_IPHONE
#define ASLR_SIZE (ALIAS_START+ALIAS_SIZE-(uintptr_t)low_space)   /* iOS: everything the process can map ends far below 2^39 */
#else
#define ASLR_SIZE (GUEST_ADDRESS_LIMIT-(uintptr_t)low_space)
#endif
static uint8_t *reserve_fixed(uint64_t at,uint64_t size){
 mach_vm_address_t a=at;   /* FIXED without OVERWRITE: fails instead of replacing an existing mapping */
 return mach_vm_map(mach_task_self(),&a,size,0,VM_FLAGS_FIXED,MEMORY_OBJECT_NULL,0,FALSE,VM_PROT_NONE,VM_PROT_ALL,VM_INHERIT_DEFAULT)==KERN_SUCCESS?(uint8_t *)(uintptr_t)a:NULL;
}
#define GUEST_ALIGN (2ULL<<20)
/* The heap ceiling follows the pool the game is told it owns, so raising TOTK_APP_POOL raises the game's main heap
   instead of running into a fixed 4 GiB wall that svcSetHeapSize would refuse with an error the game cannot recover
   from. Only the pool (a startup constant) sizes the reservation, so the reservation never moves after memory_init
   has placed it; the heap bound additionally leaves room for the mapped images. Both keep the retail figures when the
   pool is the default one. */
static uint64_t low_size(void){
 static uint64_t v;
 if(!v){uint64_t cap=APP_POOL>HEAP_CAP_MAX?HEAP_CAP_MAX:APP_POOL;uint64_t need=HEAP_OFF+cap+ARENA_TAIL;v=need>LOW_SIZE_MIN?need:LOW_SIZE_MIN;}
 return v;
}
static uint64_t heap_cap(void){
 uint64_t by_pool=APP_POOL>runtime_image_bytes()?APP_POOL-runtime_image_bytes():0;
 uint64_t cap=by_pool>HEAP_CAP_DEFAULT?by_pool:HEAP_CAP_DEFAULT;
 if(cap>HEAP_CAP_MAX)cap=HEAP_CAP_MAX;
 uint64_t room=low_size()-HEAP_OFF-ARENA_TAIL;
 if(cap>room)cap=room;
 return cap&~(GUEST_ALIGN-1);
}
/* Reserve size bytes in a free gap (2 MiB aligned). The end of the map is
   not reported, so the last gap is only tried; FIXED fails there with KERN_NO_SPACE when it reaches past the end. */
static uint8_t *reserve_in_gap_from(uint64_t size,int log,uint64_t prev){
 for(;;){
  mach_vm_address_t r=prev;mach_vm_size_t rsize=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t n=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=MACH_PORT_NULL;
  int more=mach_vm_region(mach_task_self(),&r,&rsize,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&n,&obj)==KERN_SUCCESS;
  if(obj!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),obj);
  uint64_t start=(prev+GUEST_ALIGN-1)&~(GUEST_ALIGN-1),end=more&&r<GUEST_ADDRESS_LIMIT?r:GUEST_ADDRESS_LIMIT;
  if(end>start&&end-start>=(256ULL<<20)&&log)fprintf(stderr,"[totk-mem] free %#llx..%s%#llx\n",(unsigned long long)start,more?"":"(end of map, at most) ",(unsigned long long)end);
  if(end>start&&end-start>=size){uint8_t *p=reserve_fixed(start,size);if(p)return p;}
  if(!more||r>=GUEST_ADDRESS_LIMIT||!rsize||r+rsize<=prev)return NULL;
  prev=r+rsize;
 }
}
static uint8_t *reserve_in_gap(uint64_t size,int log){
#if TARGET_OS_IPHONE
 return reserve_in_gap_from(size,log,1ULL<<32);
#else
 return reserve_in_gap_from(size,log,LOW_SEARCH_FROM);
#endif
}
static void memory_init(void) {
 if(alias_space)return;
#if TARGET_OS_IPHONE
 /* iOS: stack+heap and the alias region go side by side in one reservation (ASLR_SIZE spans both), placed in the lowest
    free gap that holds them. The free space depends on the device, so the alias region shrinks from the requested size
    to ALIAS_MIN_GIB before giving up (logging the free gaps); TOTK_ALIAS_GIB pins one size. */
 uint64_t want=alias_requested(),least=getenv("TOTK_ALIAS_GIB")?want:(ALIAS_MIN_GIB<<30);
 for(uint64_t a=want;a>=least&&!low_space;a-=1ULL<<30)if((low_space=reserve_in_gap(low_size()+a,0)))alias_len=a;
 if(!low_space){reserve_in_gap(UINT64_MAX,1);runtime_fail("reserve guest stack, heap and alias regions");}
 alias_space=low_space+low_size();
#else
 alias_space=reserve_fixed(ALIAS_SPACE_AT,ALIAS_SIZE);
 if(alias_space)for(uint64_t at=LOW_SEARCH_FROM;at+low_size()<=ALIAS_SPACE_AT&&!low_space;at+=1ULL<<30)low_space=reserve_fixed(at,low_size());
 if(!low_space){
  /* macOS 27: the shared cache fills 0x1_8000_0000..0xF_C000_0000 and the system reserves ~24 GiB at a random place in
     0x70_0000_0000..2^39, so neither fixed region fits. As on iOS, put stack+heap and the alias region side by side in one
     free hole, shrinking the alias region (the game uses < 3 GiB of it) until it fits. TOTK_ALIAS_GIB pins one size. */
  if(alias_space)mach_vm_deallocate(mach_task_self(),(mach_vm_address_t)(uintptr_t)alias_space,ALIAS_SIZE);
  alias_space=NULL;
  uint64_t want=alias_requested(),least=getenv("TOTK_ALIAS_GIB")?want:(8ULL<<30);
  for(uint64_t g=want;!low_space;g-=4ULL<<30){
   for(uint64_t at=LOW_SEARCH_FROM;at+low_size()+g<=GUEST_ADDRESS_LIMIT&&!low_space;at+=1ULL<<30)
    if((low_space=reserve_fixed(at,low_size()+g)))alias_len=g;
   if(g<least+(4ULL<<30))break;
  }
  if(!low_space){
   /* ASLR can leave only ~13 GiB holes, or a 14 GiB hole missed by the old
      1 GiB stride. Preserve successful layouts; only a previously failing
      startup queries exact gaps, then tries separate stack/heap and alias
      reservations (already supported by the original fixed layout). */
   for(uint64_t g=want;!low_space;g-=4ULL<<30){
    if((low_space=reserve_in_gap(low_size()+g,0))){alias_space=low_space+low_size();alias_len=g;break;}
    /* Keep low below alias: GetInfo's ASLR span and QueryMemory use that order,
       including an explicit TOTK_ALIAS_GIB smaller than the stack+heap reservation. */
    uint8_t *separate_low=reserve_in_gap(low_size(),0);
    if(separate_low){
     if((alias_space=reserve_in_gap_from(g,0,(uintptr_t)separate_low+low_size()))){low_space=separate_low;alias_len=g;break;}
     mach_vm_deallocate(mach_task_self(),(mach_vm_address_t)(uintptr_t)separate_low,low_size());
    }
    if(g<least+(4ULL<<30))break;
   }
  }
  if(!low_space)runtime_fail(getenv("TOTK_ALIAS_GIB")?"reserve guest stack, heap and the TOTK_ALIAS_GIB alias region below 2^39":"reserve guest stack, heap and alias regions below 2^39");
  if(!alias_space)alias_space=low_space+low_size();
 }
#endif
 heap=low_space+HEAP_OFF;
 fprintf(stderr,"[totk] guest layout: alias %#llx+%#llx stack %#llx+%#llx heap %#llx (cap %#llx)\n",(unsigned long long)ALIAS_START,ALIAS_SIZE,(unsigned long long)STACK_START,STACK_SIZE,(unsigned long long)(uintptr_t)heap,heap_cap());
}
void runtime_memory_init(void){memory_init();}
#ifdef TOTK_MOD_SUBSDK1
uint8_t *runtime_arena_alloc(size_t size){
 memory_init();
 size=(size+0x3fff)&~(size_t)0x3fff;
 if(arena_used+size>ARENA_SIZE)runtime_fail("module arena full");
 uintptr_t at=(uintptr_t)low_space+ARENA_OFF+arena_used;
 mach_vm_address_t a=at;
 /* The slot lies inside the low reservation's PROT_NONE mapping, so it must be overwritten, not merely placed. */
 kern_return_t kr=mach_vm_map(mach_task_self(),&a,size,0,VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,MEMORY_OBJECT_NULL,0,FALSE,VM_PROT_READ|VM_PROT_WRITE,VM_PROT_ALL,VM_INHERIT_DEFAULT);
 if(kr!=KERN_SUCCESS||a!=at)runtime_fail("reserve module arena slot");
 arena_used+=size;
 return (uint8_t *)at;
}
uint8_t *runtime_module_arena_base(void){return low_space?(uint8_t *)((uintptr_t)low_space+ARENA_OFF):NULL;}
uint8_t *runtime_module_arena_end(void){return low_space?(uint8_t *)((uintptr_t)low_space+ARENA_OFF+arena_used):NULL;}
uint64_t runtime_guest_low_base(void){memory_init();return (uint64_t)(uintptr_t)low_space;}
uint64_t runtime_guest_low_size(void){return low_size();}
#endif
/* Scoped stack moves: independent host backing, copy back on unmap.
 * Logical accounting is 4 KiB; Darwin protections are rounded to 16 KiB.
 * The leading/trailing partial source pages cannot be isolated on this host.
 */
static pthread_mutex_t memory_lock=PTHREAD_MUTEX_INITIALIZER;
typedef struct{uint64_t dst,src,size;} StackMap;static StackMap stack_maps[4096];static unsigned nstack_maps;
static int overlaps(uint64_t a,uint64_t n,uint64_t b,uint64_t m){return a<b+m&&b<a+n;}
static uint64_t stack_move(int unmap,uint64_t dst,uint64_t src,uint64_t size){
 if(!size||((dst|src|size)&4095))return 0xcc01;
 if(dst<STACK_START||size>STACK_SIZE||dst-STACK_START>STACK_SIZE-size)return 0xdc01;
 int inHeap=src>=(uintptr_t)heap&&size<=heap_size&&src-(uintptr_t)heap<=heap_size-size;
 uint64_t aliasStart=ALIAS_START;
 int inAlias=src>=aliasStart&&size<=ALIAS_SIZE&&src-aliasStart<=ALIAS_SIZE-size;
 /* A loaded module's memory is process-local like the heap. UltraCam's subsdk3 starts a worker thread
    whose stack is a static buffer in its own data segment, and the console kernel moves those pages the
    same way it moves a heap stack: copy them to the stack region and take the source away. */
 int inModule=!inHeap&&!inAlias&&runtime_module_contains(src,size);
 if(!inHeap&&!inAlias&&!inModule)return 0xdc01;
 pthread_mutex_lock(&memory_lock);
 if(inAlias){unsigned first=(unsigned)((src-aliasStart)/4096);for(uint64_t i=0;i<size/4096;i++)if(!alias_pages[first+i]){pthread_mutex_unlock(&memory_lock);return 0xdc01;}}

 unsigned found=nstack_maps;for(unsigned i=0;i<nstack_maps;i++)if(stack_maps[i].dst==dst&&stack_maps[i].src==src&&stack_maps[i].size==size)found=i;
 uint64_t lo=dst&~0x3fffULL,hi=(dst+size+0x3fff)&~0x3fffULL;
 uint64_t slo=(src+0x3fff)&~0x3fffULL,shi=(src+size)&~0x3fffULL;
 if(unmap){
  if(found==nstack_maps){pthread_mutex_unlock(&memory_lock);return 0xd401;}
  if(shi>slo&&mprotect((void *)slo,shi-slo,PROT_READ|PROT_WRITE))runtime_fail("restore moved stack source");
  memcpy((void *)src,(const void *)dst,size);stack_maps[found]=stack_maps[--nstack_maps];
  for(uint64_t page=lo;page<hi;page+=0x4000){int used=0;for(unsigned i=0;i<nstack_maps;i++)if(overlaps(page,0x4000,stack_maps[i].dst,stack_maps[i].size))used=1;
   if(!used&&mprotect((void *)page,0x4000,PROT_NONE))runtime_fail("decommit moved stack");}
 }else{
  if(nstack_maps==4096){pthread_mutex_unlock(&memory_lock);return 0xd401;}
  for(unsigned i=0;i<nstack_maps;i++)if(overlaps(dst,size,stack_maps[i].dst,stack_maps[i].size)||overlaps(src,size,stack_maps[i].src,stack_maps[i].size)){pthread_mutex_unlock(&memory_lock);return 0xdc01;}
  if(mprotect((void *)lo,hi-lo,PROT_READ|PROT_WRITE))runtime_fail("commit moved stack");memcpy((void *)dst,(const void *)src,size);
  if(shi>slo&&mprotect((void *)slo,shi-slo,PROT_NONE))runtime_fail("protect moved stack source");
  stack_maps[nstack_maps++]=(StackMap){dst,src,size};
 }
 pthread_mutex_unlock(&memory_lock);return 0;
}
static uint64_t alias_map(int unmap,uint64_t addr,uint64_t size){
 uint64_t start=ALIAS_START;
 if(!size||((addr|size)&4095))return 0xcc01;
 if(addr<start||size>ALIAS_SIZE||addr-start>ALIAS_SIZE-size)return 0xdc01;
 pthread_mutex_lock(&memory_lock);unsigned first=(unsigned)((addr-start)/4096),count=(unsigned)(size/4096);
 /* Horizon MapPhysicalMemory maps only the pages of the range that are still unmapped and leaves mapped pages (and their
    contents) untouched; TOTK's physical-memory heaps grow by re-mapping ranges that overlap what they already own. */
 uint64_t fresh=0;if(!unmap)for(unsigned i=0;i<count;i++)if(!alias_pages[first+i])fresh+=4096;
 /* Physical-memory resource reservation failure is LimitReached (132), not
    InvalidCurrentMemory (106). The original SDK maps LimitReached to its
    recoverable out-of-memory result; 0xd401 makes AllocateMemoryPages abort. */
 if(!unmap&&fresh+alias_bytes+heap_size+runtime_image_bytes()>APP_POOL){
  pthread_mutex_unlock(&memory_lock);
  const char *negative=getenv("TOTK_PROBE_NEGATIVE");
  return negative&&atoi(negative)==14?0xd401:0x10801;
 }
 if(unmap){
  for(unsigned i=0;i<nstack_maps;i++)if(overlaps(addr,size,stack_maps[i].src,stack_maps[i].size)){pthread_mutex_unlock(&memory_lock);return 0xdc01;}
  uint64_t released=0;for(unsigned i=0;i<count;i++)if(alias_pages[first+i]){alias_pages[first+i]=0;alias_stale[first+i]=1;released+=4096;}alias_bytes-=released;
  uint64_t low=addr&~0x3fffULL,high=(addr+size+0x3fff)&~0x3fffULL;
  for(uint64_t page=low;page<high;page+=0x4000){unsigned p=(unsigned)((page-start)/4096);if(!alias_pages[p]&&!alias_pages[p+1]&&!alias_pages[p+2]&&!alias_pages[p+3]){
   if(mmap((void *)page,0x4000,PROT_NONE,MAP_FIXED|MAP_PRIVATE|MAP_ANON,-1,0)!=(void *)page)runtime_fail("decommit physical alias page");
   memset(alias_stale+p,0,4);}}
 }else if(fresh){
  uint64_t low=addr&~0x3fffULL,high=(addr+size+0x3fff)&~0x3fffULL;
  if(mprotect((void *)low,high-low,PROT_READ|PROT_WRITE))runtime_fail("commit physical alias pages");
  for(unsigned i=0;i<count;i++)if(!alias_pages[first+i]){   /* new pages only: zero-filled like fresh pool pages */
   if(alias_stale[first+i]){memset((void *)(addr+(uint64_t)i*4096),0,4096);alias_stale[first+i]=0;}
   alias_pages[first+i]=1;}
  alias_bytes+=fresh;
 }
 pthread_mutex_unlock(&memory_lock);return 0;
}
uint64_t runtime_heap_base(void){return (uintptr_t)heap;}
/* Guest memory the game has committed (heap size + mapped alias pages), for memory reports (iOS app monitor). */
void runtime_guest_committed(uint64_t *heap_bytes,uint64_t *alias_mapped){*heap_bytes=heap_size;*alias_mapped=alias_bytes;}
/* Physical memory behind the guest regions (stack+heap and alias): resident pages, of which dirty, and pages the system
   compressed. Committed sizes overstate what the game uses; these are what count against the iOS memory limit. */
static void region_pages(uint64_t a,uint64_t end,uint64_t *resident,uint64_t *dirty,uint64_t *compressed){
 while(a<end){vm_address_t va=(vm_address_t)a;vm_size_t vs=0;natural_t depth=0;vm_region_submap_info_data_64_t info;mach_msg_type_number_t cnt=VM_REGION_SUBMAP_INFO_COUNT_64;
  if(vm_region_recurse_64(mach_task_self(),&va,&vs,&depth,(vm_region_recurse_info_t)&info,&cnt)!=KERN_SUCCESS||va>=end)break;
  *resident+=(uint64_t)info.pages_resident*vm_page_size;*dirty+=(uint64_t)info.pages_dirtied*vm_page_size;*compressed+=(uint64_t)info.pages_swapped_out*vm_page_size;
  a=(uint64_t)va+vs;}
}
void runtime_guest_resident(uint64_t *resident,uint64_t *dirty,uint64_t *compressed){
 *resident=*dirty=*compressed=0;if(!low_space)return;
 region_pages((uintptr_t)low_space,(uintptr_t)low_space+low_size(),resident,dirty,compressed);
 region_pages(ALIAS_START,ALIAS_START+ALIAS_SIZE,resident,dirty,compressed);
}
static void host_diag_init(void) { fprintf(stderr,"[totk] native diagnostics initialized\n"); }
static void host_oe_init(void) { fprintf(stderr,"[totk] application environment: local macOS process\n"); }
/* nn::oe::Initialize is a no-op here, so the SDK's oe singleton stays null; mods still read the
   display version at init (exlaunch matches it against a per-version hook table). The version
   string is the first field; exlaunch reserves exactly 0x10 bytes for it (its 0x4f18 caller
   frame ends 0x10 bytes below the entry stack pointer), so writing more overwrites the caller's
   saved frame and DT_INIT's return address. */
static void host_display_version(void *out) {
 memset(out,0,0x10);
 size_t n=sizeof(TOTK_GAME_VERSION)-1;if(n>0xf)n=0xf;
 memcpy(out,TOTK_GAME_VERSION,n);
}
#ifdef GAME_BOTW
void runtime_aoc_announce(void); int runtime_aoc_count(void); int runtime_aoc_list(int *out,int offset,int count);   /* aoc_romfs.c */
static void host_aoc_init(void) { runtime_aoc_announce(); }   /* aoc_romfs.c: the DLC volumes (botw.md) */
static int host_aoc_count(void) { return runtime_aoc_count(); }
static int host_aoc_list(int *out,int offset,int count) {
 if(offset<0||count<0)runtime_fail("invalid add-on content list range");return runtime_aoc_list(out,offset,count);
}
#else
static void host_aoc_init(void) { fprintf(stderr,"[totk] add-on content: no DLC\n"); }
static int host_aoc_count(void) { return 0; }
static int host_aoc_list(int *out,int offset,int count) {
 (void)out;if(offset<0||count<0)runtime_fail("invalid add-on content list range");return 0;
}
#endif
static void host_error_init(void) { fprintf(stderr,"[totk] error contexts: local diagnostics\n"); }
static void host_fs_init(void) { runtime_fs_init(); }
static void host_pctl_init(void) { fprintf(stderr,"[totk] local application parental controls initialized\n"); }
static void host_abort_init(void) { fprintf(stderr,"[totk] native crash observer initialized\n"); }
static void observed_os_init(uint64_t h,uint64_t args) {
 fprintf(stderr,"[totk] ENTER nnosInitialize\n");((void(*)(uint64_t,uint64_t))runtime_symbol("nnosInitialize"))(h,args);fprintf(stderr,"[totk] RETURN nnosInitialize\n");
}
static void observed_sdk_init(void) { fprintf(stderr,"[totk] ENTER nninitInitializeSdkModule\n");((void(*)(void))runtime_symbol("nninitInitializeSdkModule"))();fprintf(stderr,"[totk] RETURN nninitInitializeSdkModule\n"); }
static void observed_startup(void) { fprintf(stderr,"[totk] ENTER nninitStartup\n");((void(*)(void))runtime_symbol("nninitStartup"))();fprintf(stderr,"[totk] RETURN nninitStartup\n"); }
static void observed_main(void) { fprintf(stderr,"[totk] ENTER nnMain\n");((void(*)(void))runtime_symbol("nnMain"))();fprintf(stderr,"[totk] RETURN nnMain\n"); }
static void cpu_boost(int mode) { if(mode<0||mode>2)runtime_fail("unknown CPU boost mode");fprintf(stderr,"[totk] CPU boost request %d: macOS manages CPU frequency\n",mode); }
/* TOTK_OPERATION_MODE=handheld reports the Switch handheld mode (oe OperationMode 0, PerformanceMode Normal 0) instead of
   docked (1, Boost 1): the game then uses its own handheld settings (1280x720 output, lower internal resolution), which
   Nintendo made for half the docked GPU clock. Read once; any other value stops the start. */
static int handheld_mode(void) {static int v=-1;if(v<0){const char *e=getenv("TOTK_OPERATION_MODE");int h;if(!e||!strcmp(e,"docked"))h=0;else if(!strcmp(e,"handheld"))h=1;else runtime_fail("TOTK_OPERATION_MODE must be docked or handheld");
 fprintf(stderr,"[totk] operation mode reported to the game: %s\n",h?"handheld (performance normal)":"docked (performance boost)");v=h;}return v;}
int runtime_handheld_mode(void){return handheld_mode();}   /* runtime/input.c: the pad is the handheld controller then */
static int operation_mode(void) {return handheld_mode()?0:1;}
static int performance_mode(void) {return handheld_mode()?0:1;}
static int focus_policy;
static void focus_mode(int mode) {if(mode<0||mode>3)runtime_fail("unknown focus handling mode");focus_policy=mode;runtime_startup_checkpoint((uintptr_t)__builtin_return_address(0));fprintf(stderr,"[totk] focus policy stored: %d (window lifecycle pending)\n",focus_policy);}
static int focus_state(void) {return runtime_front_focus();}
static unsigned resume_notification,operation_notification,performance_notification;
static void resume_enabled(unsigned value) {resume_notification=value&255;}
static void operation_enabled(unsigned value) {operation_notification=value&255;}
static void performance_enabled(unsigned value) {performance_notification=value&255;}
static uint32_t performance_configuration[2];
static void performance_config(int mode,int cfg) {if(mode<0||mode>1)runtime_fail("invalid performance mode");performance_configuration[mode]=(uint32_t)cfg;fprintf(stderr,"[totk] performance request mode=%d cfg=%x: native macOS scheduling\n",mode,(uint32_t)cfg);}
/* The game's language: TOTK_LANG as given (a Switch language code), otherwise from a locale: TOTK_LOCALE, which the
   launcher sets to the app's first preferred language (BCP 47, e.g. "pt-BR"; it follows a per-app language), or else
   the Mac's current locale. Brazil maps to "pt-BR" only in the 1.4.3 build and in Breath of the Wild 1.9.0, whose RomFS have the official USpt text.
   Chinese is zh-Hant for the Hant script or, without a script, for Taiwan, Hong Kong and Macau; zh-Hans otherwise. */
static uint64_t desired_language(void) {
 const char *explicit=getenv("TOTK_LANG");char code[8]={0};
 if(explicit){if(strlen(explicit)>7)runtime_fail("language code too long");memcpy(code,explicit,strlen(explicit));}
 else {
  char language[16]={0},script[8]={0},region[4]={0};const char *tag=getenv("TOTK_LOCALE");
  if(tag&&*tag){
   size_t n=strcspn(tag,"-_");if(n<sizeof(language))memcpy(language,tag,n);
   for(const char *p=tag+n;*p;){p+=strspn(p,"-_");size_t k=strcspn(p,"-_");
    if(k==2&&isalpha((unsigned char)p[0])&&isalpha((unsigned char)p[1])){region[0]=(char)toupper((unsigned char)p[0]);region[1]=(char)toupper((unsigned char)p[1]);}
    if(k==4&&!script[0]&&isalpha((unsigned char)p[0])&&isalpha((unsigned char)p[3])){for(size_t i=0;i<4;i++)script[i]=(char)(i?tolower((unsigned char)p[i]):toupper((unsigned char)p[i]));}
    p+=k;}
  } else {
   CFLocaleRef locale=CFLocaleCopyCurrent();
   CFStringRef value=CFLocaleGetValue(locale,kCFLocaleLanguageCode);
   if(value)CFStringGetCString(value,language,sizeof(language),kCFStringEncodingUTF8);
   value=CFLocaleGetValue(locale,kCFLocaleScriptCode);
   if(value)CFStringGetCString(value,script,sizeof(script),kCFStringEncodingUTF8);
   value=CFLocaleGetValue(locale,kCFLocaleCountryCode);
   if(value)CFStringGetCString(value,region,sizeof(region),kCFStringEncodingUTF8);CFRelease(locale);
  }
#if defined(TOTK_GAME_V143) || defined(GAME_BOTW190)
  const char *portuguese=!strcmp(region,"BR")?"pt-BR":"pt";
#else
  const char *portuguese="pt";
#endif
  const char *chinese=!strcmp(script,"Hant")||(!script[0]&&(!strcmp(region,"TW")||!strcmp(region,"HK")||!strcmp(region,"MO")))?"zh-Hant":"zh-Hans";
  const char *selected=!strcmp(language,"ja")?"ja":!strcmp(language,"de")?"de":!strcmp(language,"fr")?"fr":!strcmp(language,"es")?"es":!strcmp(language,"it")?"it":!strcmp(language,"nl")?"nl":!strcmp(language,"ru")?"ru":!strcmp(language,"ko")?"ko":!strcmp(language,"zh")?chinese:!strcmp(language,"pt")?portuguese:"en-US";
  memcpy(code,selected,strlen(selected));
 }
 uint64_t result;memcpy(&result,code,8);
 fprintf(stderr,"[totk] language: %s (TOTK_LANG=%s TOTK_LOCALE=%s)\n",code,explicit?explicit:"-",getenv("TOTK_LOCALE")?getenv("TOTK_LOCALE"):"-");
 return result;
}
/* One line per game allocation came in bursts of 1000-3000 while the world streams (each a write to the log),
   so only failures are logged unless TOTK_TRACE_ALLOC=1. */
static int trace_alloc(void){static int v=-1;if(v<0){const char *e=getenv("TOTK_TRACE_ALLOC");v=e&&*e&&strcmp(e,"0");}return v;}
static uint32_t observed_region(uint64_t *out,uint64_t size){
 uint8_t *fn=runtime_symbol("_ZN2nn2os21AllocateAddressRegionEPmm");uint32_t r=((uint32_t(*)(uint64_t *,uint64_t))fn)(out,size);
 if(r||trace_alloc())fprintf(stderr,"[totk] AllocateAddressRegion size=%llx result=%x address=%llx\n",(unsigned long long)size,r,(unsigned long long)(r?0:*out));
 if(r&&getenv("TOTK_TRACE_VAMM")){
  uint8_t *sdk=fn-0x12ca60;uint64_t root;memcpy(&root,sdk+0xd16bb8,8);uint64_t *v=(void *)(uintptr_t)(root+0x418);
  for(unsigned i=0;i<10;i++)fprintf(stderr,"[totk] VAMM +%x=%llx\n",i*8,(unsigned long long)v[i]);
  if(v[8]){uint64_t *a=(void *)(uintptr_t)v[8];for(unsigned i=0;i<12;i++)fprintf(stderr,"[totk] allocator +%x=%llx\n",i*8,(unsigned long long)a[i]);if(a[2]){uint64_t *node=(void *)(uintptr_t)a[2];for(unsigned i=0;i<12;i++)fprintf(stderr,"[totk] node +%x=%llx\n",i*8,(unsigned long long)node[i]);}}
 }
 return r;
}
static uint32_t observed_pages(uint64_t addr,uint64_t size){uint32_t r=((uint32_t(*)(uint64_t,uint64_t))runtime_symbol("_ZN2nn2os19AllocateMemoryPagesEmm"))(addr,size);if(r||trace_alloc())fprintf(stderr,"[totk] AllocateMemoryPages address=%llx size=%llx result=%x\n",(unsigned long long)addr,(unsigned long long)size,r);return r;}
/* UltraCam installs its trampolines by name (exl::hook::TrampolineHook::InstallAtSymbol), which goes through
   nn::ro::LookupSymbol. That walks the ro service's registered module list; this port maps the NSOs itself, so
   the loader's own symbol tables answer the same query. 0xa16 is the Result the SDK returns when no loaded
   module exports the name. */
static uint32_t host_lookup_symbol(uint64_t *out,const char *name){
 /* A mod patches what it resolves, so the answer has to be a guest address it can map an alias of.
    The port's host implementations reach those addresses instead (loader.c redirects the SDK body). */
 void *found=runtime_symbol(name);
 if(!found){fprintf(stderr,"[totk] ro::LookupSymbol %s: no module exports it\n",name);return 0xa16;}
 if(out)*out=(uint64_t)(uintptr_t)found;
 fprintf(stderr,"[totk] ro::LookupSymbol %s -> %#llx\n",name,(unsigned long long)(uintptr_t)found);
 return 0;
}
/* UltraCam's subsdk3 brings up the network itself during startup (nn::nifm, then a nn::socket client of
   127.0.0.1:3080). This port runs no nifm service, and the mod's own state machine has a branch for
   "no network available", so answering offline is what a Switch without a saved network would do. The
   two results are module 43 (nifm) errors; subsdk3 discards them and only reads IsNetworkAvailable. */
static uint32_t host_nifm_initialize(void){fprintf(stderr,"[totk] nn::nifm::Initialize: this port has no network service\n");return 0x80002b01u;}
static uint32_t host_nifm_submit_network_request(void){return 0x80002b01u;}
static int host_nifm_is_available(void){return 0;}
void *runtime_observer(const char *name) {
 static const struct {const char *name;void *fn;} entries[]={
 {"_ZN2nn2os21AllocateAddressRegionEPmm",observed_region},{"_ZN2nn2os19AllocateMemoryPagesEmm",observed_pages},{"nnosInitialize",observed_os_init},{"nninitInitializeSdkModule",observed_sdk_init},{"nninitStartup",observed_startup},{"nnMain",observed_main}};
 for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++)if(!strcmp(name,entries[i].name))return entries[i].fn;return NULL;
}
void *runtime_override(const char *name) {
 static const struct {const char *name;void *fn;} entries[]={
  {"_ZN2nn2oe18GetDesiredLanguageEv",desired_language},
  {"_ZN2nn2oe27SetPerformanceConfigurationENS0_15PerformanceModeEi",performance_config},
  {"_ZN2nn2oe15SetCpuBoostModeENS0_12CpuBoostModeE",cpu_boost},{"_ZN2nn2oe16GetOperationModeEv",operation_mode},{"_ZN2nn2oe18GetPerformanceModeEv",performance_mode},
  {"_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE",focus_mode},{"_ZN2nn2oe20GetCurrentFocusStateEv",focus_state},
  {"_ZN2nn2oe28SetResumeNotificationEnabledEb",resume_enabled},{"_ZN2nn2oe42SetOperationModeChangedNotificationEnabledEb",operation_enabled},{"_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb",performance_enabled},
  {"nndiagStartup",host_diag_init},{"_ZN2nn2oe10InitializeEv",host_oe_init},{"_ZN2nn3aoc10InitializeEv",host_aoc_init},
  {"_ZN2nn2oe17GetDisplayVersionEPNS0_14DisplayVersionE",host_display_version},
  {"_ZN2nn3aoc17CountAddOnContentEv",host_aoc_count},{"_ZN2nn3aoc16ListAddOnContentEPiii",host_aoc_list},
  {"_ZN2nn3err26InitializeContextWriterApiEv",host_error_init},{"_ZN2nn2fs24InitializeForApplicationEv",host_fs_init},
  {"_ZN2nn4pctl10InitializeEv",host_pctl_init},{"_ZN2nn4diag34InitializeApplicationAbortObserverEv",host_abort_init},
  {"_ZN2nn2ro12LookupSymbolEPmPKc",host_lookup_symbol},
  {"_ZN2nn4nifm10InitializeEv",host_nifm_initialize},
  {"_ZN2nn4nifm20SubmitNetworkRequestEv",host_nifm_submit_network_request},
  {"_ZN2nn4nifm18IsNetworkAvailableEv",host_nifm_is_available}};
 for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++)if(!strcmp(name,entries[i].name))return entries[i].fn;
 void *input=runtime_input_override(name);if(input)return input;void *font=runtime_font_override(name);if(font)return font;void *codec=runtime_codec_override(name);if(codec)return codec;void *movie=runtime_movie_override(name);if(movie)return movie;void *clock=runtime_time_override(name);if(clock)return clock;void *applet=runtime_applet_override(name);if(applet)return applet;void *swkbd=runtime_swkbd_override(name);if(swkbd)return swkbd;void *account=runtime_account_override(name);if(account)return account;void *fs=runtime_fs_override(name);if(fs)return fs;void *front=runtime_front_override(name);return front?front:runtime_gfx_override(name);
}
/* QueryMemory as the retail kernel describes the official layout. The game's own allocators
   (thread stacks, heap) were validated against these semantics, so module builds keep them
   byte-for-byte and only add the module arena the mod loader maps inside the low reservation. */
static uint64_t default_query_memory(uint64_t *r) {
 uint64_t addr=r[2],base=addr&~0xfffULL,size=0x1000;unsigned state=0,perm=0,attr=0;
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t stack=pthread_get_stacksize_np(pthread_self());
 if(addr>=top-stack&&addr<top){base=top-stack;size=stack;state=0xb;perm=3;}
 else if(addr>=(uintptr_t)heap&&addr<(uintptr_t)heap+heap_size){base=(uintptr_t)heap;size=heap_size;state=5;perm=3;}
#ifdef TOTK_MOD_SUBSDK1
 else if(runtime_module_arena_base()&&addr>=(uintptr_t)runtime_module_arena_base()&&addr<(uintptr_t)runtime_module_arena_end()){
  if(!runtime_arena_query(addr,&base,&size,&state,&perm,&attr))runtime_fail("module arena query");}
#endif
 else if(addr>=(uintptr_t)low_space&&addr<(uintptr_t)low_space+low_size()){base=(uintptr_t)low_space;size=low_size();if(addr<(uintptr_t)heap){size=(uintptr_t)heap-base;}else{base=(uintptr_t)heap+heap_size;size=(uintptr_t)low_space+low_size()-base;}}
 else if(addr>=(uintptr_t)low_space+low_size()&&addr<ALIAS_START){base=(uintptr_t)low_space+low_size();size=ALIAS_START-base;state=0x10;perm=0;}   /* host-owned: Inaccessible */
 else if(!addr){base=0;size=ASLR_START;state=0;perm=0;}
 else if(runtime_module_query(addr,&base,&size,&state,&perm,&attr)){}
 else {state=3;perm=5;}
 pthread_mutex_lock(&memory_lock);
 if(addr>=ALIAS_START&&addr<ALIAS_START+ALIAS_SIZE){
  unsigned p=(unsigned)((addr-ALIAS_START)/4096),low=p,high=p+1;unsigned allocated=alias_pages[p];
  while(low>0&&alias_pages[low-1]==allocated)low--;while(high<sizeof(alias_pages)&&alias_pages[high]==allocated)high++;
  base=ALIAS_START+(uint64_t)low*4096;size=(uint64_t)(high-low)*4096;state=allocated?5:0;perm=allocated?3:0;
 }
 for(unsigned i=0;i<nstack_maps;i++){
  StackMap *m=&stack_maps[i];uint64_t end=m->dst+m->size,send=m->src+m->size;
  if(addr>=m->dst&&addr<end){base=m->dst;size=m->size;state=0xb;perm=3;break;}
  if(addr>=m->src&&addr<send){base=m->src;size=m->size;state=5;perm=0;attr=4;break;}
  if(state==0){uint64_t oldEnd=base+size;if(end<=addr&&end>base)base=end;if(m->dst>addr&&m->dst<oldEnd)oldEnd=m->dst;size=oldEnd-base;}
  else if(state==5){uint64_t oldEnd=base+size;if(send<=addr&&send>base)base=send;if(m->src>addr&&m->src<oldEnd)oldEnd=m->src;size=oldEnd-base;}
 }pthread_mutex_unlock(&memory_lock);
 struct {uint64_t base,size;uint32_t state,attr,perm,ipc,device,pad;} info={base,size,state,attr,perm,0,0,0};
 if(r[0])memcpy((void *)(uintptr_t)r[0],&info,sizeof(info));r[0]=0;r[1]=0;return 0;
}
void runtime_core_checkpoint(void);
#ifdef TOTK_MOD_SUBSDK1
static int mod_negative(void){static int value=-1;if(value<0){const char *e=getenv("TOTK_PROBE_NEGATIVE");value=e?atoi(e):0;}return value;}
/* MapProcessMemory windows (SVC 0x74/0x75): exlaunch's RwPages maps module pages at an alias address so it can write code.
   The guest is this process, so a window is a second mapping of the same pages. Host pages are 16 KiB: a window whose
   source and destination are congruent modulo 16 KiB is shared, so writes through the window reach the module at once;
   any other window is a private copy written back before the unmap. */
#define MAX_MAP_WINDOWS 512
typedef struct {uint64_t dst,src,size,host,host_size;int shared;} MapWindow;
static MapWindow map_windows[MAX_MAP_WINDOWS];static unsigned nmap_windows;
static int mod_window_query(uint64_t addr,uint64_t *base,uint64_t *size,unsigned *state,unsigned *permission) {
 for(unsigned i=0;i<nmap_windows;i++){const MapWindow *w=&map_windows[i];
  if(addr>=w->host&&addr-w->host<w->host_size){*base=w->host;*size=w->host_size;*state=5;*permission=3;return 1;}}
 return 0;
}
/* Full, monotonic memory map for exlaunch's module scan. Every address below 2^39
   belongs to exactly one region and regions never overlap, so the scan advances by
   region size; querying 2^39 wraps to region 0, whose base is below the previous
   region and ends the scan (the real kernel masks the address the same way). */
static uint64_t mod_query_memory(uint64_t *r,int exlaunch) {
 if(!exlaunch)return default_query_memory(r);
 uint64_t out=r[0],addr=r[2]&(GUEST_ADDRESS_LIMIT-1);
 uint64_t base=addr&~0xfffULL,size=0x1000;unsigned state=0,attribute=0,permission=0;
 uint64_t lo=(uintptr_t)low_space,hi=lo+low_size();
 uint64_t as=ALIAS_START,ae=ALIAS_START+ALIAS_SIZE;
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t stack=pthread_get_stacksize_np(pthread_self());
 if(addr>=(uint64_t)(top-stack)&&addr<(uint64_t)top){base=top-stack;size=stack;state=0xb;permission=3;}
 else if(heap_size&&addr>=(uintptr_t)heap&&addr<(uintptr_t)heap+heap_size){base=(uintptr_t)heap;size=heap_size;state=5;permission=3;}
 else if(addr>=lo&&addr<hi) {
  uint64_t stack0=(uintptr_t)low_space+STACK_OFF,stack1=stack0+STACK_SIZE;
  uint64_t heap0=(uintptr_t)heap,heap1=heap0+heap_size;
  uint64_t ar0=(uintptr_t)runtime_module_arena_base(),ar1=(uintptr_t)runtime_module_arena_end();
  uint64_t ares1=lo+ARENA_OFF+ARENA_SIZE;
  int hide=mod_negative()==30;   /* negative control: the arena reads back as free memory */
  if(addr>=stack0&&addr<stack1){base=stack0;size=STACK_SIZE;state=0xb;permission=3;}
  else if(heap_size&&addr>=heap0&&addr<heap1){base=heap0;size=heap_size;state=5;permission=3;}
  else if(ar0&&addr>=ar0&&addr<ar1){if(hide){base=ar0;size=ares1-ar0;state=0;permission=0;}else if(!runtime_arena_query(addr,&base,&size,&state,&permission,&attribute))runtime_fail("module arena query");}
  else if(ar0&&addr>=ar1&&addr<ares1){base=ar1;size=ares1-ar1;state=0x10;permission=0;}
  else {
   /* Free runs: before the stack, between stack and heap start, after the heap
      reservation. MapProcessMemory windows occupy free runs, so they show up as
      mapped and split the runs the module scan steps through. */
   uint64_t limit=ar0?ar0:hi,low,high;
   pthread_mutex_lock(&memory_lock);
   if(mod_window_query(addr,&base,&size,&state,&permission)) {}
   else if(exlaunch&&addr>=heap1&&addr<heap0+heap_cap()){base=heap1;size=heap0+heap_cap()-heap1;state=0x10;permission=0;}
   else {
    if(addr<stack0){low=lo;high=stack0;}
    else if(addr>=stack1&&addr<heap0){low=stack1;high=heap0;}
    else {low=exlaunch?heap0+heap_cap():heap1;high=limit;
     if(addr<low||addr>=high){pthread_mutex_unlock(&memory_lock);runtime_fail("low-space region gap");}}
    for(unsigned i=0;i<nmap_windows;i++){const MapWindow *w=&map_windows[i];
     if(w->host+w->host_size<=addr&&w->host+w->host_size>low)low=w->host+w->host_size;
     if(w->host>addr&&w->host<high)high=w->host;}
    if(low>addr||high<=addr){pthread_mutex_unlock(&memory_lock);runtime_fail("module window split");}
    /* exlaunch allocates 4 KiB units from the ASLR pool; one host 16 KiB page cannot
       hold two unrelated windows, so unaligned candidates read as reserved and its
       retry loop picks another address. */
    if(exlaunch&&(addr&0x3fff)){base=addr&~0xfffULL;size=0x1000;state=0x10;permission=0;}
    else {base=low;size=high-low;state=0;permission=0;}
   }
   pthread_mutex_unlock(&memory_lock);
  }
 }
 else if(addr>=as&&addr<ae) {
  unsigned limit=(unsigned)(ALIAS_SIZE/4096),p=(unsigned)((addr-as)/4096),l=p,h=p+1;
  pthread_mutex_lock(&memory_lock);unsigned allocated=alias_pages[p];
  while(l>0&&alias_pages[l-1]==allocated)l--;while(h<limit&&alias_pages[h]==allocated)h++;
  pthread_mutex_unlock(&memory_lock);
  base=as+(uint64_t)l*4096;size=(uint64_t)(h-l)*4096;state=allocated?5:0;permission=allocated?3:0;
 }
 else if(addr>=hi&&addr<as){base=hi;size=as-hi;state=0x10;permission=0;}   /* host-owned: Inaccessible */
 else if(addr>=hi&&addr<GUEST_ADDRESS_LIMIT){base=hi>ae?hi:ae;size=GUEST_ADDRESS_LIMIT-base;state=0x10;permission=0;}
 else if(!addr){base=0;size=lo;state=0;permission=0;}
 else if(!runtime_module_query(addr,&base,&size,&state,&permission,&attribute)){base=addr&~0xfffULL;size=0x1000;state=3;permission=5;}
 /* TOTK_QM_TRACE=1: every answer the exlaunch view gives, in query order (an exlaunch MemQuery that
    stops early shows exactly which region shape it could not accept). */
 {static int qm=-1;if(qm<0)qm=getenv("TOTK_QM_TRACE")!=NULL;
  if(qm)fprintf(stderr,"[totk-qm] %#llx -> base=%#llx size=%#llx state=%x perm=%x\n",(unsigned long long)addr,
   (unsigned long long)base,(unsigned long long)size,state,permission);}
 struct {uint64_t base,size;uint32_t state,attr,perm,ipc,device,pad;} info={base,size,state,attribute,permission,0,0,0};
 if(out)memcpy((void *)(uintptr_t)out,&info,sizeof(info));
 r[0]=0;r[1]=0;return 0;
}
static int mod_source_range(uint64_t src,uint64_t size) {
 if(runtime_module_contains(src,size))return 1;
 return heap_size&&src>=(uintptr_t)heap&&src-(uintptr_t)heap<=heap_size&&size<=heap_size-(src-(uintptr_t)heap);
}
static uint64_t map_process_memory(uint64_t dst,uint64_t handle,uint64_t src,uint64_t size) {
 if((uint32_t)handle!=0xffff8001u)return 0xdc01;   /* GetInfo 0xFDE9: the current process */
 if(!size||((dst|src|size)&0xfff)||!mod_source_range(src,size))return 0xcc01;
 uint64_t lo=(uintptr_t)low_space,dd=dst&~0x3fffULL,sd=src&~0x3fffULL;
 uint64_t span_shared=(((src&0x3fff)+size+0x3fff)&~0x3fffULL);
 int shared=!((dst^src)&0x3fff)&&mod_source_range(sd,span_shared);
 uint64_t span=shared?span_shared:(((dst&0x3fff)+size+0x3fff)&~0x3fffULL);
 if(dst<lo||dst-lo>low_size()-size||dd<lo||dd-lo>low_size()-span)return 0xdc01;
 pthread_mutex_lock(&memory_lock);
 for(unsigned i=0;i<nmap_windows;i++)if(overlaps(dd,span,map_windows[i].host,map_windows[i].host_size)){pthread_mutex_unlock(&memory_lock);return 0xdc01;}
 if(nmap_windows==MAX_MAP_WINDOWS){pthread_mutex_unlock(&memory_lock);return 0xd401;}
 int ok;
 if(shared) {
  mach_vm_address_t at=dd;vm_prot_t cur=0,max=0;
  kern_return_t kr=mach_vm_remap(mach_task_self(),&at,span,0,VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,mach_task_self(),(mach_vm_address_t)sd,FALSE,&cur,&max,VM_INHERIT_DEFAULT);
  ok=kr==KERN_SUCCESS&&at==dd&&mach_vm_protect(mach_task_self(),dd,span,FALSE,VM_PROT_READ|VM_PROT_WRITE)==KERN_SUCCESS;
 } else {
  mach_vm_address_t at=dd;
  kern_return_t kr=mach_vm_map(mach_task_self(),&at,span,0,VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,MEMORY_OBJECT_NULL,0,FALSE,VM_PROT_READ|VM_PROT_WRITE,VM_PROT_ALL,VM_INHERIT_DEFAULT);
  ok=kr==KERN_SUCCESS&&at==dd;
  if(ok)memcpy((void *)(uintptr_t)dst,(const void *)(uintptr_t)src,size);
 }
 if(ok)map_windows[nmap_windows++]=(MapWindow){dst,src,size,dd,span,shared};
 pthread_mutex_unlock(&memory_lock);
 if(!ok){fprintf(stderr,"[totk] MapProcessMemory %#llx <- %#llx size=%#llx failed\n",(unsigned long long)dst,(unsigned long long)src,(unsigned long long)size);return 0xdc01;}
 fprintf(stderr,"[totk] %s window %#llx <- %#llx size=%#llx\n",shared?"shared":"copied",(unsigned long long)dst,(unsigned long long)src,(unsigned long long)size);
 return 0;
}
/* A copied window's source is module code or rodata, which the host keeps read-only: Apple Silicon
   refuses any mapping that is both writable and executable. Write the alias bytes back through a
   second mapping of the same host page that is read-write instead of taking EXECUTE away from the
   guest's page: both entries share the frame, so the copy is visible while the source stays r-x and
   a thread running module code never takes a transient instruction abort. Both callers hold
   memory_lock, so one alias page serves every publish. */
static uint8_t *write_alias;
static int window_write_back(uint64_t dst,uint64_t src,uint64_t size) {
 if(!write_alias) {
  mach_vm_address_t at=0;
  if(mach_vm_map(mach_task_self(),&at,0x4000,0,VM_FLAGS_ANYWHERE,MEMORY_OBJECT_NULL,0,FALSE,
   VM_PROT_READ|VM_PROT_WRITE,VM_PROT_READ|VM_PROT_WRITE,VM_INHERIT_NONE)!=KERN_SUCCESS)return 0;
  write_alias=(uint8_t *)(uintptr_t)at;
 }
 uint64_t first=src&~0x3fffULL,last=(src+size-1)&~0x3fffULL;
 for(uint64_t page=first;;page+=0x4000) {
  mach_vm_address_t at=page;mach_vm_size_t len=0;vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
  kern_return_t kr=mach_vm_region(mach_task_self(),&at,&len,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&obj);
  if(obj)mach_port_deallocate(mach_task_self(),obj);
  if(kr!=KERN_SUCCESS||page<at||page>=at+len)return 0;
  mach_vm_address_t alias=(mach_vm_address_t)write_alias;vm_prot_t cur=0,max=0;
  kr=mach_vm_remap(mach_task_self(),&alias,0x4000,0,VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,mach_task_self(),page,FALSE,&cur,&max,VM_INHERIT_NONE);
  if(kr!=KERN_SUCCESS||alias!=(mach_vm_address_t)write_alias)return 0;
  if(mach_vm_protect(mach_task_self(),alias,0x4000,FALSE,VM_PROT_READ|VM_PROT_WRITE)!=KERN_SUCCESS)return 0;
  uint64_t start=page>src?page:src,end=page+0x4000<src+size?page+0x4000:src+size;
  memcpy(write_alias+(start-page),(const void *)(uintptr_t)(dst+(start-src)),(size_t)(end-start));
  if(page>=last)break;
 }
 sys_icache_invalidate((void *)(uintptr_t)src,size);
 return 1;
}
/* Persistent RwPages windows are never unmapped, so a copied window must publish its alias writes
   to the source while the guest is still running. Exlaunch's RwPages::Sync (0x4db0) starts by
   reading CTR_EL0 (0x5c98/0x5cd4), which Darwin traps and the runtime emulates; that is the
   publication point. Shared windows already see each other and need nothing. */
void mod_window_publish(void) {
 pthread_mutex_lock(&memory_lock);
 for(unsigned i=0;i<nmap_windows;i++){const MapWindow *w=&map_windows[i];
  if(!w->shared&&!window_write_back(w->dst,w->src,w->size))runtime_fail("window publish write-back");}
 pthread_mutex_unlock(&memory_lock);
}
static uint64_t unmap_process_memory(uint64_t dst,uint64_t handle,uint64_t src,uint64_t size) {
 if((uint32_t)handle!=0xffff8001u)return 0xdc01;
 if(!size||((dst|src|size)&0xfff))return 0xcc01;
 pthread_mutex_lock(&memory_lock);
 unsigned i;for(i=0;i<nmap_windows;i++)if(map_windows[i].dst==dst&&map_windows[i].src==src&&map_windows[i].size==size)break;
 if(i==nmap_windows){pthread_mutex_unlock(&memory_lock);return 0xd401;}
 MapWindow w=map_windows[i];map_windows[i]=map_windows[--nmap_windows];
 if(w.shared)sys_icache_invalidate((void *)(uintptr_t)src,size);
 else if(!window_write_back(dst,src,size))runtime_fail("copied window write-back");
 void *p=mmap((void *)(uintptr_t)w.host,(size_t)w.host_size,PROT_NONE,MAP_FIXED|MAP_PRIVATE|MAP_ANON,-1,0);
 pthread_mutex_unlock(&memory_lock);
 if(p!=(void *)(uintptr_t)w.host)runtime_fail("decommit module window");
 fprintf(stderr,"[totk] %s window %#llx <- %#llx size=%#llx\n",w.shared?"unmapped":"copied back",(unsigned long long)dst,(unsigned long long)src,(unsigned long long)size);
 return 0;
}
#endif
#ifdef GAME_BOTW
/* Breath of the Wild (botw.md): the preemption point is also after every SVC. A thread the SVC woke competes for a core at
   once (threads.c wake_queue); when it beats this one on this core, Horizon runs it before the SVC returns. */
uint64_t runtime_svc_inner(unsigned num,uint64_t *r,const char *module,uint64_t offset);
uint64_t runtime_svc(unsigned num,uint64_t *r,const char *module,uint64_t offset){uint64_t v=runtime_svc_inner(num,r,module,offset);runtime_core_checkpoint();return v;}
#define runtime_svc runtime_svc_inner
#endif
uint64_t runtime_svc(unsigned num,uint64_t *r,const char *module,uint64_t offset) {
 runtime_core_checkpoint();
 // Successful SVCs occur several times per frame. Keep the detailed trace available
 // for diagnostics without formatting and writing every call during normal play.
 static _Atomic int trace=-1;int enabled=atomic_load_explicit(&trace,memory_order_relaxed);
 if(enabled<0){enabled=getenv("TOTK_TRACE_SVC")!=NULL;atomic_store_explicit(&trace,enabled,memory_order_relaxed);}
 if(enabled)fprintf(stderr,"[totk] SVC 0x%x at %s+0x%llx x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx\n",num,module,(unsigned long long)offset,(unsigned long long)r[0],(unsigned long long)r[1],(unsigned long long)r[2],(unsigned long long)r[3]);
 if(svc_thread((int)num,r))return r[0];
 if(runtime_ipc_svc(num,r))return r[0];
 memory_init();
 switch(num) {
 case 0x02:r[0]=runtime_module_permission(r[0],r[1],(unsigned)r[2]);return r[0];
 case 0x03:r[0]=runtime_module_lock_permission(r[0],r[1],(unsigned)r[2],(unsigned)r[3]);return r[0];
 case 0x29: {
  uint64_t value=0;unsigned id=(unsigned)r[1];int exlaunch_module=!strcmp(module,"subsdk1")||!strcmp(module,"subsdk3");
  switch(id) {
  case 0:value=7;break;case 1:value=0x0ffffffff0000000ULL;break;
  case 2:value=ALIAS_START;break;case 3:value=ALIAS_SIZE;break;
  case 4:value=(uintptr_t)heap;break;case 5:value=heap_cap();break;
  case 6:case 21:value=APP_POOL;break;case 7:case 22:value=runtime_image_bytes()+heap_size+alias_bytes;
   { static unsigned polls; if(getenv("TOTK_MEM_LOG")&&(polls++%600)==0) fprintf(stderr,"[totk-mem] GetInfo(%u) total=%#llx used=%#llx image=%#llx heap=%#llx alias=%#llx\n",id,(unsigned long long)APP_POOL,(unsigned long long)value,(unsigned long long)runtime_image_bytes(),(unsigned long long)heap_size,(unsigned long long)alias_bytes); }
   break;
  case 8:value=0;break;case 10:value=0;break;
  case 11:arc4random_buf(&value,8);break;
  /* exlaunch allocates its RwPages alias addresses from the ASLR region; keep its
     choices inside the low reservation the module build actually maps. subsdk3 carries the
     same exlaunch code, so it gets the same region. */
  case 12:value=exlaunch_module?(uintptr_t)low_space:ASLR_START;break;case 13:value=exlaunch_module?low_size():ASLR_SIZE;break;
  case 14:value=STACK_START;break;case 15:value=STACK_SIZE;break;
  case 16:value=SYSTEM_RESOURCE_BUDGET;break;case 17:value=sizeof(stack_maps)+sizeof(alias_pages);break;case 18:value=GAME_PROGRAM_ID;break;
  case 20:value=(uintptr_t)user_exception_context;break;   /* UserExceptionContextAddress: SDK stores e.g. the dying-message region at +0x1c0 */case 23:value=1;break;
  case 0xfde9:value=0xffff8001ULL;break;   /* pseudo-handle of the current process (MapProcessMemory) */
  /* AliasRegionExtraSize (18.0.0+): our alias reservation contains no
   * kernel-owned extension outside the range reported by ids 2 and 3. */
  case 28:value=0;break;
  default:fprintf(stderr,"unknown GetInfo id %u\n",id);runtime_fail("GetInfo id not implemented");
  }
  r[0]=0;r[1]=value;return 0;
 }
 case 0x2c:case 0x2d:{uint64_t a=r[0],n=r[1];r[0]=alias_map(num==0x2d,a,n);
  if(getenv("TOTK_MEM_LOG"))fprintf(stderr,"[totk-mem] %sMapPhysicalMemory %#llx+%#llx -> %#llx alias=%#llx remaining=%#llx\n",num==0x2d?"Un":"",(unsigned long long)a,(unsigned long long)n,(unsigned long long)r[0],(unsigned long long)alias_bytes,(unsigned long long)(APP_POOL-runtime_image_bytes()-heap_size-alias_bytes));
  if(r[0])fprintf(stderr,"[totk] %sMapPhysicalMemory %#llx+%#llx failed %#llx (alias %#llx used, heap %#llx)\n",num==0x2d?"Un":"",(unsigned long long)a,(unsigned long long)n,(unsigned long long)r[0],(unsigned long long)alias_bytes,(unsigned long long)heap_size);return r[0];}
 case 0x04:case 0x05:r[0]=stack_move(num==5,r[0],r[1],r[2]);return r[0];
 case 0x06:
#ifdef TOTK_MOD_SUBSDK1
  /* The exlaunch-loaded modules (subsdk1, and UltraCam's subsdk3) scan the address space themselves, so
     they need the complete monotonic map; the game keeps the retail view it was validated against. */
#ifdef TOTK_MOD_SUBSDK3
  return mod_query_memory(r,!strcmp(module,"subsdk1")||!strcmp(module,"subsdk3"));
#else
  return mod_query_memory(r,!strcmp(module,"subsdk1"));
#endif
#else
  return default_query_memory(r);
#endif
#ifdef TOTK_MOD_SUBSDK1
 case 0x74:r[0]=map_process_memory(r[0],r[1],r[2],r[3]);
  /* A mod that resolves a function by name and then patches it can be handed a host implementation instead of
     guest code (the NVN entry points are the port's own). Those windows are refused above without a word, so
     name the caller: this is the only way to see a hook that silently never installed. */
  if(r[0])fprintf(stderr,"[totk] MapProcessMemory from %s+0x%llx: src %#llx size %#llx rejected %#llx\n",
   module,(unsigned long long)offset,(unsigned long long)r[2],(unsigned long long)r[3],(unsigned long long)r[0]);
  return r[0];
 case 0x75:r[0]=unmap_process_memory(r[0],r[1],r[2],r[3]);return r[0];
#endif
 case 0x01:{size_t size=r[1];if(getenv("TOTK_MEM_LOG"))fprintf(stderr,"[totk-mem] SetHeapSize %#zx (image=%#llx alias=%#llx pool=%#llx)\n",size,(unsigned long long)runtime_image_bytes(),(unsigned long long)alias_bytes,(unsigned long long)APP_POOL);
  if(size>heap_cap()||size%0x200000||size+runtime_image_bytes()>APP_POOL){fprintf(stderr,"[totk] SetHeapSize %#zx refused: heap limit %#llx (pool %#llx, images %#llx), requests must be 2 MiB aligned and fit the pool\n",size,(unsigned long long)heap_cap(),(unsigned long long)APP_POOL,(unsigned long long)runtime_image_bytes());r[0]=0xd401;return r[0];}
  if(size>heap_size&&mprotect(heap+heap_size,size-heap_size,PROT_READ|PROT_WRITE))runtime_fail("commit heap");
  if(size<heap_size&&mprotect(heap+size,heap_size-size,PROT_NONE))runtime_fail("decommit heap");heap_size=size;r[0]=0;r[1]=(uintptr_t)heap;return 0;}
 case 0x1e: r[0]=runtime_now_ns()*12/625;return r[0];   /* GetSystemTick: 19.2 MHz */
 case 0x0c: r[0]=0;r[1]=44;return 0;
 case 0x0e: r[0]=0;r[1]=0;r[2]=15;return 0;
 case 0x25: {uint64_t id;pthread_threadid_np(NULL,&id);r[0]=0;r[1]=id;return 0;}
 case 0x10:r[0]=0;return 0;
 /* SynchronizePreemptionState: the SDK calls it after clearing ThreadLocalRegion disable_count (+0x100) when interrupt_flag
    (+0x102) was set by a preemption that had to wait (threads.c totk_preempt_signal). The switch itself happened at this
    SVC's entry (runtime_core_checkpoint); here the flag is cleared, as Horizon does. */
 case 0x36:{volatile uint16_t *tlr=pthread_getspecific(runtime_keys[2]);if(tlr)tlr[0x102/2]=0;r[0]=0;return 0;}
 case 0x26: {uint32_t result=0;if(r[1]&&r[2]>=4)memcpy(&result,(void *)(uintptr_t)r[1],4);fprintf(stderr,"[totk] guest Break reason=%llx result=%x\n",(unsigned long long)r[0],result);
  if(!(r[0]&0x80000000ULL)){fprintf(stderr,"[totk] break regs:");for(int i=0;i<31;i++)fprintf(stderr," x%d=%llx",i,(unsigned long long)r[i]);uint64_t sp=(uint64_t)((uint64_t *)r)[100];fprintf(stderr," sp=%llx\n",(unsigned long long)sp);
   const uint64_t *st=(const uint64_t *)(uintptr_t)sp;for(int i=0;i<32;i++)fprintf(stderr,"[totk] sp+%03x=%llx\n",i*8,(unsigned long long)st[i]);
   if(getenv("TOTK_DUMP_BREAK"))runtime_dump_break_state(r[29],r[30]);}
  runtime_trace_guest(r[29],r[30]);if(r[0]&0x80000000ULL)return 0;runtime_fail("original SDK Break");}
 case 0x27: {size_t n=r[1];if(n>65536)runtime_fail("debug string too long");fwrite((void *)(uintptr_t)r[0],1,n,stderr);r[0]=0;return 0;}
 case 0x0b:{int64_t ns=(int64_t)r[0];if(ns>0){struct timespec t={ns/1000000000,ns%1000000000};nanosleep(&t,NULL);}r[0]=0;return 0;}
 default:fprintf(stderr,"[totk] unimplemented SVC 0x%x at %s+%#llx\n",num,module,(unsigned long long)offset);if(num==0x1f)fprintf(stderr,"[totk] named port %.12s\n",(const char *)(uintptr_t)r[1]);runtime_trace_guest(r[29],r[30]);runtime_fail("system service not implemented");return 0;
 }
}
#ifdef GAME_BOTW
#undef runtime_svc
#endif
