#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <link.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>  
#include <errno.h>
#include <memory>

/**
 * ref: 
 *    https://stackoverflow.com/questions/19451791/get-loaded-address-of-a-elf-binary-dlopen-is-not-working-as-expected
 *    https://linux.die.net/man/3/dl_iterate_phdr
 * 
**/

typedef struct CbData_t {
    char in_so_name[1024]; //input
    void *so_addr; //output
    void *exe_base_addr; //output
    size_t so_size; //output
}CbData;

// extern "C" int __libc_csu_init(); //near 0x400920
// extern "C" int __libc_start_main(); //__libc_start_main@GLIBC_2.2.5
// extern "C" int _start(); //near 0x400610


// iterator all shared objects, or iterator unitl this callback return none 0
static int dl_iter_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    bool print_debug = 0;
    CbData *cbdata = (CbData *)data;
    if(print_debug) printf("======dl_iter_callback: %s @ %#lx\n", info->dlpi_name, (unsigned long)info->dlpi_addr);
    if(cbdata->in_so_name && strstr(info->dlpi_name, cbdata->in_so_name)) {
        cbdata->so_addr = (char *)info->dlpi_addr;
    }

    const char *main_addr = (const char *)dlsym(RTLD_DEFAULT, "main");
    if(!main_addr) {
        printf("dlsym mian filed !!!\n");
    }
    
    const char *base = (const char *)info->dlpi_addr;
    const ElfW(Phdr) *first_load = NULL;

    int j;
    for (j = 0; j < info->dlpi_phnum; j++) {
      const ElfW(Phdr) *phdr = &info->dlpi_phdr[j];

      if (phdr->p_type == PT_LOAD) {
        const char *begin = base + phdr->p_vaddr;
        const char *end = begin + phdr->p_memsz;

        if(print_debug) printf("    in [%s] load %p->%p size=%ld\n", info->dlpi_name, begin, end, end-begin);

        if (first_load == NULL) first_load = phdr;
        if (begin <= main_addr && main_addr < end) {
          // Found PT_LOAD that "covers" callback().
            if(print_debug) printf("    --main ELF header is at %p, image linked at 0x%zx, relocation: 0x%zx\n",
                base + first_load->p_vaddr, first_load->p_vaddr, info->dlpi_addr); 
            cbdata->exe_base_addr = (void*)(base + first_load->p_vaddr);
                //elf_header=0x400000, image_link=0x400000, relocation: 0x0
        }
      }
    }

    return 0;
}


// get so load addr. so_name should be smaller than 1024
void *get_so_addr_complicated(const char *so_name) {
    if(!so_name) return NULL;
    CbData cbdata;
    bzero(&cbdata, sizeof(CbData));
    strncpy(cbdata.in_so_name, so_name, sizeof(cbdata.so_addr));
    dl_iterate_phdr(&dl_iter_callback, &cbdata);
    if(cbdata.so_addr) {
        return cbdata.so_addr;
    }
    return nullptr;
}


void *get_so_addr(const char *so_name) {
    // actually dlopen return the so's linkmap.
    link_map *lk = (link_map*)dlopen(so_name, RTLD_NOW|RTLD_GLOBAL);
    return (void*)lk->l_addr;
}

// get exe_base addr. usually it would be to be 0x400000
// but if specified in build or set fPIC, it will change. 
__attribute__((visibility("default")))
void *get_exe_load_addr() {
    CbData cbdata;
    bzero(&cbdata, sizeof(CbData));
    dl_iterate_phdr(&dl_iter_callback, &cbdata);
    if(cbdata.exe_base_addr) {
        return cbdata.exe_base_addr;
    }
    return nullptr;
}



#define VERMAP_SIZE 8192


typedef struct tag_sec_table
{
	uint64_t addr;
	uint64_t start;
	uint64_t end;
} sec_table_t;


typedef struct {
    uint64_t base_addr;
    uint64_t initEntryAddr;
    uint64_t initArrayAddr;
    uint64_t initArraySize;
    uint64_t entryAddr; 
    uint64_t jmpRelAddr; 
    uint64_t pltRelType; 
    uint64_t pltRelSize; 
    uint64_t symTabAddr; 
    uint64_t strTabAddr; 
    uint64_t strTabSize; 
    uint64_t RelAddr; 
    uint64_t RelSize; 

    uint64_t soaddr[16];
    uint32_t soindex;

    sec_table_t sectable[16];
    uint32_t secidx;
    ElfW(Addr) gotplt_addr;

//   Elf64_Word vermap[VERMAP_SIZE]; //std::tr1::unordered_map<ElfW(Half), ElfW(Word)> vermap;
} ElfSecInfo;


#define HPC_ROUND_UP(value, align)  (((value) + ((align)-1u)) & ~((align)-1u))
#define HPC_ROUND_DOWN(value, align)  ((value) & ~((align)-1u))
#define HPC_IS_POWER2(value)		((value) > 0 && (((value) & (~(value) + 1u)) == (value)))

uint8_t *elf_mmap(uint8_t *addr, int len)
{
	if (addr) {
		int pagesize = sysconf(_SC_PAGE_SIZE);
		uint64_t start = (uint64_t)addr;
		uint64_t end = (uint64_t)addr + len;
		start = HPC_ROUND_DOWN(start, pagesize);
		end = HPC_ROUND_UP(end, pagesize);
		int size = end - start;
        uint8_t *mem = (uint8_t *)mmap((void *)start, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
		printf("mmap addr: %p->0x%p\n", mem, mem+size);
		memset(mem,0,size);
		//mprotect(mem, size, PROT_READ|PROT_WRITE|PROT_EXEC);
		return MAP_FAILED == mem ? NULL : addr;
	} else {
		uint8_t *mem = (uint8_t *)mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
		//printf("mmap addr2: %p-0x%x\n", mem, len);
		memset(mem,0,len);
		//mprotect(mem, size, PROT_READ|PROT_WRITE|PROT_EXEC);
		return MAP_FAILED == mem ? NULL : mem;
	}
}

uint64_t get_addr(ElfSecInfo *secinfo, uint64_t addr)
{
	for (uint32_t k = 0; k < secinfo->secidx; k++) {
		if (addr >= secinfo->sectable[k].start && addr <= secinfo->sectable[k].end) {
			return (secinfo->sectable[k].addr+addr-secinfo->sectable[k].start);
		}
	}
	return addr;
}

int LoadAndSecInfo(char *buf, Elf64_Ehdr *ehdr, ElfSecInfo *secinfo)
{
  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf64_Phdr *ephdr = (Elf64_Phdr *)(buf+ehdr->e_phoff);
    switch (ephdr[i].p_type) {
	    case PT_LOAD: {
            break;
	    }
        case PT_DYNAMIC: {
            Elf64_Dyn *dynSection = (Elf64_Dyn*)(buf+ephdr[i].p_offset);

            // printf("dynSection=%p\n", dynSection);
            for (; dynSection->d_tag != DT_NULL; dynSection++) {
                uint64_t dynSectionAddr = get_addr(secinfo, dynSection->d_un.d_val);

                switch (dynSection->d_tag) {
                    // case DT_VERSYM: {
                    // 	break;
                    // }
                    case DT_PLTGOT: {
                        secinfo->gotplt_addr = dynSection->d_un.d_ptr;
                    }
                    case DT_NEEDED: {
                        if (secinfo->soindex < 16) {
                            secinfo->soaddr[secinfo->soindex++] = dynSection->d_un.d_val;
                        } else {
                            printf("[LoadAndSecInfo]: soindex > 16\n");
                        }
                        break;
                    }
                    case DT_INIT: {
                        secinfo->initEntryAddr = dynSectionAddr;
                        break;
                    }
                    case DT_INIT_ARRAY: {
                        secinfo->initArrayAddr = dynSectionAddr;
                        break;
                    }
                    case DT_INIT_ARRAYSZ: {
                        secinfo->initArraySize = dynSection->d_un.d_val;
                        break;
                    }
                    case DT_PLTRELSZ: {
                        secinfo->pltRelSize = dynSection->d_un.d_val;
                        break;
                    }
                    case DT_STRTAB: {
                        secinfo->strTabAddr = dynSectionAddr;
                        break;
                    }
                    case DT_STRSZ: {
                        secinfo->strTabSize = dynSection->d_un.d_val;
                        break;
                    }
                    case DT_JMPREL: {
                        secinfo->jmpRelAddr = dynSectionAddr;
                        break;
                    }
                    case DT_SYMTAB: {
                        secinfo->symTabAddr = dynSectionAddr;
                        break;
                    }
                    case DT_REL:
                    case DT_RELA: {
                        secinfo->RelAddr = dynSectionAddr;
                        break;
                    }
                    case DT_RELSZ:
                    case DT_RELASZ: {
                        secinfo->RelSize = dynSection->d_un.d_val;
                        break;
                    }
                    case DT_RELENT: {
                        int relent = dynSection->d_un.d_val;
                        break;
                    }
                    case DT_PLTREL: {
                        int pltRelType = dynSection->d_un.d_val;
                        break;
                    }
                    default: {
                        // printf("[LoadAndSecInfo]: unknown DYN %d %d\n", dynSection->d_tag, dynSection->d_un.d_val);
                        break;
                    }
                }
            }
            
            if (!secinfo->symTabAddr || !secinfo->strTabAddr) {
                printf("[LoadAndSecInfo]: no dsym or strTabAddr\n");
                return -1;
            }
            
            break;
        }
	    
        default:
	        // printf("[LoadAndSecInfo]: unknown PT %d\n", phdr[i].p_type);
		    break;
      }
  }

    secinfo->entryAddr = get_addr(secinfo, ehdr->e_entry);
    return 0;
}


void *find_relocate_sub(const char* reloc_type, ElfSecInfo *secinfo, const char *tar_symbol_name) 
{
  int i, k;
  int relsz = 0;
  Elf64_Rela* rel = NULL;
  char* dstr = (char*)secinfo->strTabAddr;
  Elf64_Sym* dsym = (Elf64_Sym*)secinfo->symTabAddr;

  if (strcmp(reloc_type, "rel") == 0) {
	  rel = (Elf64_Rela*)secinfo->RelAddr;
	  relsz = secinfo->RelSize;
  } else {
	  rel = (Elf64_Rela*)secinfo->jmpRelAddr;
	  relsz = secinfo->pltRelSize;
  }

    for (i = 0; i < relsz / sizeof(Elf64_Rela); rel++, i++) {
        long* addr = (long*)((char*)rel->r_offset + secinfo->base_addr);
        int type = ELF64_R_TYPE(rel->r_info);
        Elf64_Sym* sym = dsym + ELF64_R_SYM(rel->r_info);
        char* sname = dstr + sym->st_name;

        // printf("sname=%s, addr=%p\n", sname, addr);
        if (strcmp(sname, tar_symbol_name)==0) {
            // val = (void *)(0x00db4dc0);
            return (void *)addr;
        }
    }
    return nullptr;
}

void *find_relocate(const char *tar_symbol_name, ElfSecInfo *secinfo) {
    void *ret = find_relocate_sub("rel", secinfo, tar_symbol_name);
    if(!ret) {
        ret = find_relocate_sub("pltrel", secinfo, tar_symbol_name);
    }
    return ret;
}


// find the symbol in exe's plt addr.
void * find_symbol_got_in_exe(const char *tar_symbol_name) {

    char exe_name_buffer[PATH_MAX];
    // Get the absolute path of current executable file.
    if(readlink("/proc/self/exe", exe_name_buffer, PATH_MAX) < 0) {
        perror("readlink /proc/self/exe fail");
        return nullptr;
    }
    FILE *fp = fopen(exe_name_buffer, "rb");
    if(fp == NULL) {
        perror("can not open self_exe_filename");
    }
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    char *buf = (char *)malloc(size);
    // std::make_shared<char *>(malloc(size))
    fseek(fp, 0, SEEK_SET);
    fread(buf, size, 1, fp);
    fclose(fp);
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
    if(memcmp(ehdr->e_ident, ELFMAG, SELFMAG)){
        printf("check exe_base magic fail\n");
        free(buf);
        return nullptr;
    }
    if(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        printf("check exe_base e_type fail, ehdr->e_type=%d\n", ehdr->e_type);
        free(buf);
        return nullptr;
    }

    ElfSecInfo secinfo{0};
    if(LoadAndSecInfo((char *)buf, ehdr, &secinfo)<0) {
        free(buf);
        return nullptr;
    }
    void *ret = find_relocate(tar_symbol_name, &secinfo);
    printf("find %s's plt: %p\n", tar_symbol_name, ret);
    free(buf);
    return ret;
}

// if failed return -1. success return 0.
// usage: replace_plt_function("memset", memset_new);
// aware that main shoud start by 0. if specified fPIC for main, should add the base.
int replace_plt_function(const char *func_name, void *new_func) {
    void *tar_plt = find_symbol_got_in_exe(func_name);
    if(tar_plt) {
        memcpy(tar_plt, &new_func, sizeof(void *));
        return 0;
    }
    return -1;
}



//通过修改jump指令来替换函数，jump到*got，修改*got的值。
//intel指令集有效，其他未知。
//参考: https://zhuanlan.zhihu.com/p/372151448
void replace_function_by_jump(void *origin_func, void *new_func) {
    //origin_func实际上就是plt jump，是一条相对跳转指令，跳转到got处存放的地址，即(*got)
    //intel下jump相对跳转指令为2字节的 0xff 25 加4字节的offset, 总长度为6个字节
    // jump会跳转到 *(ip+offset),  ip是指令指针寄存器, (ip+offset)是got的地址。
    struct jump_instruction_t {
        uint16_t instruction;
        uint32_t offset;
    }__attribute__((packed));
    static_assert(sizeof(jump_instruction_t) == 6);

    jump_instruction_t *origin = (jump_instruction_t *)origin_func;
    char *rip = (char*)origin + sizeof(jump_instruction_t);  //计算执行(jump指令)时ip寄存器的值
    size_t *got = (size_t*)(rip + origin->offset); //计算(ip+offset), 即got的地址
    
    //jump指令跳转到(*got)，因此修改(*got)为新地址。
    *got = (size_t)new_func;
}

link_map * locate_linkmap() {
    return (struct link_map*) dlopen(0, RTLD_NOW);
}

link_map * locate_linkmap_complicated() {
    
    void *load_addr = get_exe_load_addr();
    ElfW(Addr) phdr_addr, dyn_addr, map_addr, gotplt_addr, text_addr;

    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)load_addr;
    ElfW(Phdr) *phdr = (ElfW(Phdr)*)((char*)load_addr + ehdr->e_phoff);
    
    while (phdr->p_type != PT_DYNAMIC) {
        phdr++;
    }
    ElfW(Dyn) *dyn = (ElfW(Dyn)*)(phdr->p_vaddr);

    while(dyn->d_tag != DT_PLTGOT) {
        dyn++;
    }
    gotplt_addr = dyn->d_un.d_ptr;
    gotplt_addr += sizeof(ElfW(Addr));

    map_addr = *(size_t *)(gotplt_addr);
    // printf("get linkmap:%p\n", map_addr);
    return (link_map*)map_addr;
}


