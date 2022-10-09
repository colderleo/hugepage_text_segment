#include <stdio.h>
#include <unistd.h>
#include <string>

#include "elf_utils.h"

void map_huge_exebase_inso();



int main() {
    printf("main start\n");
    map_huge_exebase_inso();
    printf("use this cmd to check the program's memory map:\ncat /proc/`pgrep huge_demo`/maps\n");
    getchar();
}

