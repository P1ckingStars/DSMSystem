#include "dsm_node.hpp"
#include <alloca.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <malloc.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace dsm;

void test() {
    int x = 0;
    printf("addr of x: 0x%lx\n", ((intptr_t)&x) >> 12);
}

int main(int argc, char * argv[]) {
    dsm_init();
    int a = 0;
    int swap_fd = memfd_create(".swap", 0);
    ftruncate(swap_fd, PAGE_SIZE * 10);
    char * mem_region = (char *)mmap(0, PAGE_SIZE * 10, PROT_READ | PROT_WRITE, MAP_SHARED, swap_fd, 0);
    printf("addr of a: 0x%lx\n", ((intptr_t)&a));
    printf("addr of mem_region: 0x%lx\n", ((intptr_t)mem_region));
    dsm_node * node;
    bool is_master = false;
    printf("argc: %d\n", argc);
    if (argc == 3) {
        printf("create master\n");
        is_master = true;
        node_addr addr;
        addr.ip = string(argv[1]);
        addr.port = stoi(argv[2]);
        printf("make new node\n");
        node = new dsm_node(addr, mem_region, PAGE_SIZE * 10, is_master, swap_fd);
        printf("finish make new node\n");
    } else if (argc == 5) {
        printf("create process\n");
        node_addr addr;
        addr.ip = string(argv[1]);
        addr.port = stoi(argv[2]);
        printf("make new node\n");
        node = new dsm_node(addr, mem_region, PAGE_SIZE * 10, is_master, swap_fd);
        printf("finish make new node\n");
        node_addr dst_addr;
        dst_addr.ip = string(argv[3]);
        dst_addr.port = stoi(argv[4]);
        printf("try connect\n");
        node->connect(dst_addr);
    } else {
        printf("parsing ERROR\n");
    }
    printf("start testing...\n");
    if (is_master) {
        mem_region[0] = 1;
        while (mem_region[1] == 0) {
            mem_region[0] = 1;
        }
    } else {
        mem_region[1] = 1;
        while (mem_region[0] == 0) {
            mem_region[1] = 1;
        }
    }
    printf("complete!!!\n");
    while(1);
    return 0;
}









