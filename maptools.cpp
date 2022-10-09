#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>
#include <new>
#include <tuple>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "elf_utils.h"
using namespace std;

char * mmap_alloc(size_t size) {
    char *ret = (char *)mmap(nullptr, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(ret == MAP_FAILED) {
        printf("mmap_alloc failed, lasterror = %s\n", strerror(errno));
        return nullptr;
    }
    else return ret;
}


void map_huge_exebase_inso() {
    struct AddrRange
    {
        char *init_begin;
        char *init_end;
        char *back_begin;
        size_t size;
    };

    constexpr size_t hugepage_size_2m = 1024*1024*2ULL; //2M
    constexpr size_t hugepage_size_1g = 1024*1024*1024ULL; //1G

    // print /proc/self/maps
    char selfexe[PATH_MAX] = {0};
    auto count = readlink("/proc/self/exe", selfexe, PATH_MAX);
    string exename(selfexe);
    if(count <= 0) {
        cout << "maphuge failed: cannot read /proc/self/exe\n";
        return;
    } else {
        cout << "exename is: " << exename << endl;
    }

    std::ifstream fmaps("/proc/self/maps");
    if(!fmaps) {
        cout << "maphuge failed: cannot read /proc/self/maps\n";
        return;
    }

    vector<AddrRange> seg_ranges;
    string map_line;
    char *main_least_end = nullptr;
    while(getline(fmaps, map_line)) {
        cout << map_line << std::endl;
        string permission, dev, pathname;
        char dash;
        uint64_t offset, inode;
        uintptr_t start, end;

        istringstream iss(map_line);
        iss >> std::hex >> start;
        iss >> dash;
        iss >> std::hex >> end;
        iss >> permission;
        iss >> offset >> dev >> inode;
        if(inode != 0) {
            iss >> pathname;
            if(pathname == exename) {
                main_least_end = (char*)end;
                printf("get main segment, start(%lx) -> end(%lx)  \n", start, end);
            }
        }

        AddrRange rg;
        rg.init_begin = (char*)start;
        rg.init_end = (char*)end;
        rg.back_begin = nullptr;
        rg.size = rg.init_end - rg.init_begin;
        seg_ranges.emplace_back(rg);
    }
    if(seg_ranges.size() == 0) {
        printf("maphuge failed: get 0 seg_ranges\n");
        return;
    }

    // copy exebase
    char *exe_begin = seg_ranges[0].init_begin;
    char *exe_end = seg_ranges[0].init_end;
    int total_count = 0;
    mmap_alloc(hugepage_size_1g); //make mapping gap

    for(auto &rg : seg_ranges) {
        if(rg.init_begin > main_least_end && rg.init_begin -exe_end > hugepage_size_2m) {
            //segment gap more than 2m
            break;
        }

        mprotect(rg.init_begin, rg.size, PROT_READ|PROT_WRITE|PROT_EXEC);
        rg.back_begin = (char*)mmap_alloc(hugepage_size_1g+rg.size) + hugepage_size_1g;
        if(rg.back_begin == nullptr) return;

        memcpy(rg.back_begin, rg.init_begin, rg.size);
        exe_end = rg.init_end;
        total_count++;
        printf("add exebase range %d: %p -> %p, size=%lx, back_begin=%p\n",
            total_count, rg.init_begin, rg.init_end, rg.size, rg.back_begin);
    }

    char *map_begin = (char*)HPC_ROUND_DOWN((size_t)exe_begin, hugepage_size_2m);
    char *map_end = (char*)HPC_ROUND_UP((size_t)exe_end, hugepage_size_2m);
    size_t map_size = map_end - map_begin;

    printf("map exebase, exe_begin=%p, exe_end=%p, maphuge_begin=%p, maphuge_end=%p, maphuge_size=%p, hugepage_cout=%lu\n", 
        exe_begin, exe_end, map_begin, map_begin+map_size, map_size, map_size/hugepage_size_2m);

    for(int _ir=0; _ir<total_count; ++_ir) {
        AddrRange &range = seg_ranges[_ir];
        printf("    --restore init_addr(%p) from backup_addr(%p) size(%ld)\n", range.init_begin, range.back_begin, range.size);
    }
    fflush(stdout);
    // usleep(100);

    void *mapped_addr = mmap((void*)map_begin, map_size, PROT_READ|PROT_WRITE|PROT_EXEC, 
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_HUGETLB, -1, 0);
    if(mapped_addr == MAP_FAILED) {
        printf("map_exebase failed, lasterror = %s\n", strerror(errno));
        return;
    }

    for(int _ir=0; _ir<total_count; ++_ir) {
        AddrRange &range = seg_ranges[_ir];
        // printf("    --restore init_addr(%p) from backup_addr(%p) size(%ld)\n", range.init_begin, range.back_begin, range.size);
        memcpy(range.init_begin, range.back_begin, range.size);
    }
    printf("map restore succeed. cur proc maps is:\n");
    // print /proc/self/maps
    std::ifstream fmaps_after("/proc/self/maps");
    std::cout << fmaps_after.rdbuf() << std::endl;
}
