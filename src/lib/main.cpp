#include "dsm_node.hpp"
#include <alloca.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <malloc.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>
#include "debug.hpp"

using namespace dsm;

extern char __etext;

int dsm_main(char * mem_region, size_t length, int argc, char * argv[]);

int main(int argc, char * argv[]) {
    char * mem_region;
    bool is_master = atoi(argv[1]) == 0;
    int pages = atoi(argv[2]);
    if (is_master) {
        printf("create master\n");
        NodeAddr addr;
        addr.ip = string(argv[3]);
        addr.port = stoi(argv[4]);
        mem_region = dsm_init_master(addr, PAGE_SIZE * pages);
        is_master = true;
    } else {
        NodeAddr addr;
        addr.ip = string(argv[3]);
        addr.port = stoi(argv[4]);
        NodeAddr dst_addr;
        dst_addr.ip = string(argv[5]);
        dst_addr.port = stoi(argv[6]);
        mem_region = dsm_init_node(addr, dst_addr, PAGE_SIZE * pages);
    }

    printf("start running with %d pages...\n", pages);
    int res = dsm_main(mem_region, PAGE_SIZE * pages, argc, argv);
    while(1);
    return 0;
}









